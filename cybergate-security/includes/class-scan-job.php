<?php
/**
 * Batched, resumable site scan (one job at a time).
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * A scan runs across many short ticks (AJAX or cron), so a 30k file site never
 * needs a long running request. All state lives in option 'wpcybersec_job'
 * (not autoloaded); the file list is a flat file in <jobs_dir>/<id>.list read
 * back from a stored byte offset.
 *
 * Phases:
 *   enumerating  Iterative DFS, building <id>.list. Symlinked dirs are not
 *                followed; Paths::is_excluded folders are skipped.
 *   processing   Batches of ~50 lines: stat, look up the manifest, decide,
 *                hash and malware-scan only when needed, upsert the manifest.
 *                The state is saved after every batch and the deadline is
 *                checked after every file.
 *   finishing    The database scan when the run includes it (Db_Scanner, in
 *                chunks over as many ticks as it needs), then for whole-site
 *                runs the missing core file count and the administrator
 *                check (User_Watch), then deleted-file detection (manifest
 *                rows this run never touched and nobody wrote since it
 *                started), list cleanup, save last_result, log, notify.
 *
 * Concurrency: AJAX, WP-Cron and bin/cron.php can all drive the same job. Only
 * one of them works at a time: tick(), start() and cancel() take the row lock
 * 'wpcybersec_job_lock' (INSERT IGNORE into the options table, value
 * "<expires>:<token>", taken over atomically once expired). A tick that cannot
 * get the lock returns status() at once. cancel() leaves a request in
 * 'wpcybersec_job_cancel' that the running tick honours at its next batch.
 *
 * List file: one relative path per line; "%", "\r" and "\n" in names are
 * percent-encoded, so a file named with a line break is still one entry. DFS
 * stack entries are rawurlencoded because the state is an option and must be
 * valid UTF-8 even for folder names that are not.
 *
 * Baseline: option 'wpcybersec_baseline_at' (unix time) is set when a
 * whole-site baseline finishes, with 'wpcybersec_manifest_root' (the scan root
 * it was built for). A whole-site incremental or full scan without one, or for
 * another scan root, runs as a baseline instead. Folders too large to
 * re-baseline inline after an update are queued in
 * 'wpcybersec_rebaseline_queue' (relative prefix => microtime when queued):
 * their new and changed files are judged like a baseline until a scan that
 * started after the entry was queued, and covers the folder, finishes.
 */
class Scan_Job {

	const OPTION          = 'wpcybersec_job';
	const LAST_OPTION     = 'wpcybersec_last_scan';
	const BASELINE_OPTION = 'wpcybersec_baseline_at';
	const ROOT_OPTION     = 'wpcybersec_manifest_root';
	const QUEUE_OPTION    = 'wpcybersec_rebaseline_queue';
	const LOCK_OPTION     = 'wpcybersec_job_lock';
	const CANCEL_OPTION   = 'wpcybersec_job_cancel';

	const BATCH          = 50;
	const ENUM_CHECK     = 200;
	const STALE_SECONDS  = HOUR_IN_SECONDS;
	const DEFAULT_BUDGET = 15.0;

	/** List and stack encoding version stored in the state ('enc'). */
	const ENCODING = 1;

	/** Files larger than this (or max_file_mb when higher) get a partial fingerprint. */
	const HASH_CAP = 268435456;

	/** @var array|null Working copy of the job state for this request. */
	private $state = null;

	/** @var string Lock value held by this request ('' when none). */
	private $lock = '';

	/** @var float Seconds the tick lock is held for (refreshed after each batch). */
	private $lock_hold = 60.0;

	/** @var bool The lock expired and another runner took it over during this tick. */
	private $lost_lock = false;

	/** @var bool The last tick() could not get the lock. */
	private $locked_out = false;

	/** @var bool finish() left queued rebaselines to start after the lock is released. */
	private $chain = false;

	/** @var array|null Rebaseline queue loaded for this tick. */
	private $queue = null;

	/** @var float Last time the cancel request was read from the database. */
	private $cancel_checked = 0.0;

	/** @var int Byte offset after the last line read_lines() consumed. */
	private $read_end = 0;

	/** @var array|null Last checksum verdict: [ rel, sha256, verify_details() result ]. */
	private $verified = null;

	/**
	 * Light hooks only; the heavy work is driven by Ajax and File_Monitor.
	 */
	public function register() {}

	/* ------------------------------------------------------------------ */
	/* Lifecycle                                                           */
	/* ------------------------------------------------------------------ */

	/**
	 * Starts a job. Returns the job id, or a running job's id when one is
	 * active and $opts['force'] is not set.
	 *
	 * @param array $opts mode, malware, paths, trigger, force, wait (seconds to wait for the lock, default 10),
	 *                    database (bool; default: on for full and baseline scans of the whole site,
	 *                    on for scheduled scans when the database was last scanned a day or more
	 *                    ago, off otherwise; never for scans limited to folders).
	 * @return string|\WP_Error
	 */
	public function start( array $opts = array() ) {
		$state = $this->load( true );
		if ( $this->is_active( $state ) && empty( $opts['force'] ) && ! $this->is_stale( $state ) ) {
			return $state['id'];
		}

		$wait = isset( $opts['wait'] ) ? max( 0.0, (float) $opts['wait'] ) : 10.0;
		$lock = $this->acquire_lock( 120, $wait );
		if ( '' === $lock ) {
			$state = $this->load( true );
			if ( $this->is_active( $state ) ) {
				return $state['id'];
			}
			return new \WP_Error( 'wpcybersec_job_busy', __( 'The scanner is busy. Try again in a moment.', 'cybergate-security' ) );
		}
		try {
			return $this->start_locked( $opts );
		} finally {
			$this->release_lock( $lock );
		}
	}

	/**
	 * start() body, run while holding the lock.
	 *
	 * @param array $opts Options.
	 * @return string|\WP_Error
	 */
	private function start_locked( array $opts ) {
		$state = $this->load( true );
		if ( $this->is_active( $state ) ) {
			if ( empty( $opts['force'] ) && ! $this->is_stale( $state ) ) {
				return $state['id'];
			}
			$this->cleanup_files( $state );
		}

		$mode = isset( $opts['mode'] ) ? (string) $opts['mode'] : 'incremental';
		if ( ! in_array( $mode, array( 'incremental', 'full', 'baseline' ), true ) ) {
			$mode = 'incremental';
		}

		$ensured = wpcybersec()->storage->ensure();
		if ( is_wp_error( $ensured ) ) {
			return $ensured;
		}

		$root  = Paths::scan_root();
		$paths = $this->normalize_paths( isset( $opts['paths'] ) ? (array) $opts['paths'] : array() );
		if ( ! empty( $opts['paths'] ) && ! $paths['abs'] ) {
			// Never fall back to the whole site when the requested folders are gone.
			return new \WP_Error( 'wpcybersec_job_paths', __( 'None of the folders to scan exist inside the scan folder.', 'cybergate-security' ) );
		}

		// Without a baseline every existing file would be reported as new (and in
		// strict mode moved to quarantine). A whole-site scan therefore builds the
		// baseline first: when none has finished yet, or when the manifest was
		// built for another scan root.
		if ( 'baseline' !== $mode && ! $paths['abs'] && ! $this->has_baseline( $root ) ) {
			$built_for = get_option( self::ROOT_OPTION, '' );
			if ( is_string( $built_for ) && '' !== $built_for && $built_for !== $root ) {
				wpcybersec()->logger->log(
					'scan_root_changed',
					__( 'The scan folder changed since the last baseline, so this scan rebuilds the baseline.', 'cybergate-security' ),
					array(
						'old' => $built_for,
						'new' => $root,
					)
				);
			}
			$mode = 'baseline';
		}

		$id   = gmdate( 'YmdHis' ) . substr( md5( uniqid( 'wpcs', true ) ), 0, 8 );
		$list = wpcybersec()->storage->jobs_dir() . '/' . $id . '.list';

		$trigger  = isset( $opts['trigger'] ) ? sanitize_key( $opts['trigger'] ) : 'manual';
		$database = false;
		if ( ! $paths['abs'] && wpcybersec()->db_scanner ) {
			if ( isset( $opts['database'] ) && null !== $opts['database'] ) {
				$database = (bool) $opts['database'];
			} elseif ( in_array( $mode, array( 'full', 'baseline' ), true ) ) {
				$database = true;
			} elseif ( 'cron' === $trigger ) {
				$database = $this->db_scan_due();
			}
		}

		$this->state = array(
			'id'           => $id,
			'state'        => 'enumerating',
			'mode'         => $mode,
			'malware'      => isset( $opts['malware'] ) ? (bool) $opts['malware'] : (bool) wpcybersec()->settings->get( 'scan_malware', true ),
			'trigger'      => $trigger,
			// Database scan at the end of this run (Db_Scanner); its cursor while it runs.
			'database'     => $database,
			'db'           => null,
			'db_done'      => false,
			'db_findings'  => 0,
			// Whole-site runs: core files missing (-1 = not known) and new administrators found.
			'missing_core' => -1,
			'new_admins'   => 0,
			'paths'        => $paths['abs'],
			'prefixes'     => $paths['rel'],
			'root'         => $root,
			'enc'          => self::ENCODING,
			// Queued folder rebaselines this run will list from scratch (see settle_rebaseline_queue()).
			'queue_seen'   => $this->rebaseline_queue( true ),
			// Also copy unchanged trusted files that have no stored copy yet (Snapshots).
			'backfill'     => wpcybersec()->snapshots ? wpcybersec()->snapshots->needs_backfill() : false,
			// Backfill generation at the start: a reset during the run (copies
			// deleted, limit raised) keeps the backfill pending for the next scan.
			'backfill_gen' => wpcybersec()->snapshots ? wpcybersec()->snapshots->backfill_generation() : 0,
			'list_file'    => $list,
			'list_offset'  => 0,
			'stack'        => array_map( 'rawurlencode', $paths['stack'] ),
			'enum_count'   => 0,
			'files_total'  => 0,
			'files_done'   => 0,
			'new'          => 0,
			'modified'     => 0,
			'deleted'      => 0,
			'threats'      => 0,
			'quarantined'  => 0,
			'skipped'      => 0,
			'current'      => '',
			'message'      => '',
			'started_at'   => time(),
			'ticked_at'    => time(),
			'finished_at'  => 0,
		);

		// Start the list file empty. No 0640 chmod: a CLI runner and the web
		// server user must both be able to continue a job when they share a group.
		if ( false === @file_put_contents( $list, '' ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions
			$this->state = null;
			return new \WP_Error( 'wpcybersec_job_list', __( 'Could not create the scan file list. Check the data folder permissions.', 'cybergate-security' ) );
		}
		Fs::chmod( $list, 0660 );

		$this->clear_cancel();
		$this->save();

		wpcybersec()->logger->log(
			'scan_started',
			sprintf(
				/* translators: 1: scan mode, 2: trigger */
				__( 'Started a %1$s scan (%2$s).', 'cybergate-security' ),
				$mode,
				$this->state['trigger']
			),
			array(
				'id'      => $id,
				'malware' => $this->state['malware'],
				'paths'   => $this->state['paths'],
			)
		);
		return $id;
	}

	/**
	 * Whether a whole-site baseline exists for the scan root.
	 *
	 * @param string|null $root Scan root (default: the current one).
	 * @return bool
	 */
	public function has_baseline( $root = null ) {
		$root      = null === $root ? Paths::scan_root() : (string) $root;
		$at        = (int) get_option( self::BASELINE_OPTION, 0 );
		$built_for = get_option( self::ROOT_OPTION, false );

		if ( ! $at && false === $built_for ) {
			// Installs from before baseline tracking: a finished whole-site
			// baseline was the last scan (path baselines carry trigger "update").
			$last = $this->last_result();
			if ( isset( $last['mode'], $last['state'], $last['trigger'] ) && 'baseline' === $last['mode'] && 'done' === $last['state'] && 'update' !== $last['trigger'] ) {
				$at = ! empty( $last['finished_at'] ) ? (int) $last['finished_at'] : time();
				update_option( self::BASELINE_OPTION, $at, false );
				update_option( self::ROOT_OPTION, $root, false );
				return true;
			}
			return false;
		}
		if ( ! $at ) {
			return false;
		}
		return ! ( is_string( $built_for ) && '' !== $built_for && $built_for !== $root );
	}

	/**
	 * Does up to $budget_seconds of work and returns the status.
	 *
	 * @param float $budget_seconds Time budget.
	 * @return array status()
	 */
	public function tick( $budget_seconds = self::DEFAULT_BUDGET ) {
		$this->locked_out = false;
		$this->lost_lock  = false;
		$this->chain      = false;

		$budget          = max( 1.0, (float) $budget_seconds );
		$this->lock_hold = 2 * $budget + 30;
		$this->lock      = $this->acquire_lock( $this->lock_hold, 0 );
		if ( '' === $this->lock ) {
			// Another runner is working on the job right now; report its progress.
			$this->locked_out = true;
			$this->state      = $this->load( true );
			return $this->status();
		}

		try {
			$status = $this->tick_locked( $budget );
		} finally {
			$this->release_lock( $this->lock );
			$this->lock = '';
		}

		if ( $this->chain ) {
			$this->chain = false;
			$this->start_queued_rebaselines( 2.0 );
		}
		return $status;
	}

	/**
	 * tick() body, run while holding the lock.
	 *
	 * @param float $budget Seconds.
	 * @return array status()
	 */
	private function tick_locked( $budget ) {
		$state = $this->load( true );
		if ( ! $this->is_active( $state ) ) {
			$this->state = $state;
			return $this->status();
		}

		$deadline                 = microtime( true ) + $budget;
		$this->state              = $state;
		$this->state['ticked_at'] = time();
		$this->queue              = null;

		try {
			if ( $this->cancel_requested( true ) ) {
				$this->cancel_now();
				return $this->status();
			}
			if ( ! empty( $this->state['root'] ) && $this->state['root'] !== Paths::scan_root() ) {
				$this->fail( __( 'The scan folder setting changed while this scan was running. Start a new scan.', 'cybergate-security' ) );
			} else {
				if ( 'enumerating' === $this->state['state'] ) {
					$this->enumerate( $deadline );
				}
				if ( 'processing' === $this->state['state'] && microtime( true ) < $deadline ) {
					$this->process( $deadline );
				}
				if ( 'finishing' === $this->state['state'] && ! $this->lost_lock ) {
					$this->finish( $deadline );
				}
			}
		} catch ( \Throwable $e ) {
			$this->fail( $e->getMessage() );
		}

		if ( $this->lost_lock ) {
			// Another runner owns the job now; do not overwrite its state.
			$this->state = null;
			return $this->status();
		}
		if ( $this->state ) {
			$this->save();
		}
		return $this->status();
	}

	/**
	 * Runs ticks until the job is no longer active (CLI and bin/cron.php).
	 * Waits while another runner holds the lock. Stops when the job it started
	 * with is over, even when a queued rebaseline starts right after it.
	 *
	 * @param callable|null $progress Receives status() after each tick.
	 * @return array Final status.
	 */
	public function run_to_completion( $progress = null ) {
		$first  = $this->load( true );
		$id     = $this->is_active( $first ) ? (string) $first['id'] : '';
		$guard  = 100000;
		$status = $this->status();
		do {
			$status = $this->tick( 20.0 );
			if ( is_callable( $progress ) ) {
				call_user_func( $progress, $status );
			}
			if ( $this->locked_out ) {
				usleep( 1000000 );
			}
			$current = $this->load( true );
			$running = $this->is_active( $current ) && ( '' === $id || (string) $current['id'] === $id );
		} while ( $running && --$guard > 0 );

		if ( '' !== $id && ( $status['id'] !== $id || $this->is_active( $status ) ) ) {
			// Another runner finished the job while this one waited for the lock.
			wp_cache_delete( self::LAST_OPTION, 'options' );
			$last = $this->last_result();
			if ( isset( $last['id'] ) && $last['id'] === $id ) {
				return $last;
			}
		}
		return $status;
	}

	/**
	 * Cancels the running job. When a tick is working on it, the tick stops at
	 * its next batch.
	 */
	public function cancel() {
		$state = $this->load( true );
		if ( ! $this->is_active( $state ) ) {
			return;
		}
		$this->request_cancel( (string) $state['id'] );

		$lock = $this->acquire_lock( 60, 8.0 );
		if ( '' === $lock ) {
			return; // The running tick honours the request.
		}
		try {
			$state       = $this->load( true );
			$this->state = $state;
			if ( $this->is_active( $state ) ) {
				$this->cancel_now();
			} else {
				$this->clear_cancel();
			}
		} finally {
			$this->release_lock( $lock );
		}
	}

	/**
	 * Marks the loaded job cancelled (caller holds the lock).
	 */
	private function cancel_now() {
		$this->cleanup_files( $this->state );
		$this->state['state']       = 'cancelled';
		$this->state['current']     = '';
		$this->state['finished_at'] = time();
		$this->state['message']     = __( 'Scan cancelled.', 'cybergate-security' );
		$this->save();
		$this->save_last();
		$this->clear_cancel();
		wpcybersec()->logger->log( 'scan_cancelled', __( 'Scan cancelled.', 'cybergate-security' ), array( 'id' => $this->state['id'] ) );
	}

	/**
	 * True while a job is active but has not ticked for STALE_SECONDS (its
	 * driver died, for example a request killed by max_execution_time).
	 *
	 * @return bool
	 */
	public function is_stalled() {
		$state = $this->load( true );
		return $this->is_active( $state ) && $this->is_stale( $state );
	}

	/**
	 * Status of the last finished job.
	 *
	 * @return array
	 */
	public function last_result() {
		$last = get_option( self::LAST_OPTION, array() );
		return is_array( $last ) ? $last : array();
	}

	/**
	 * Current job status (safe shape even when idle).
	 *
	 * @return array
	 */
	public function status() {
		$state = null !== $this->state ? $this->state : $this->load();
		if ( ! $state || empty( $state['id'] ) ) {
			return $this->idle_status();
		}
		return array(
			'id'           => (string) $state['id'],
			'state'        => (string) $state['state'],
			'mode'         => (string) $state['mode'],
			'malware'      => (bool) $state['malware'],
			'trigger'      => (string) $state['trigger'],
			'files_total'  => (int) $state['files_total'],
			'files_done'   => (int) $state['files_done'],
			'new'          => (int) $state['new'],
			'modified'     => (int) $state['modified'],
			'deleted'      => (int) $state['deleted'],
			'threats'      => (int) $state['threats'],
			'quarantined'  => (int) $state['quarantined'],
			'skipped'      => (int) $state['skipped'],
			'started_at'   => (int) $state['started_at'],
			'finished_at'  => (int) $state['finished_at'],
			'current'      => (string) $state['current'],
			'message'      => (string) $state['message'],
			'percent'      => $this->percent( $state ),
			'database'     => ! empty( $state['database'] ),
			'db_findings'  => isset( $state['db_findings'] ) ? (int) $state['db_findings'] : 0,
			'missing_core' => isset( $state['missing_core'] ) ? (int) $state['missing_core'] : -1,
			'new_admins'   => isset( $state['new_admins'] ) ? (int) $state['new_admins'] : 0,
		);
	}

	/**
	 * Whether a scheduled scan should include the database (at most once a day).
	 *
	 * @return bool
	 */
	private function db_scan_due() {
		$last = wpcybersec()->db_scanner->last_run();
		$at   = isset( $last['finished_at'] ) ? (int) $last['finished_at'] : 0;
		return $at <= time() - DAY_IN_SECONDS + 10 * MINUTE_IN_SECONDS;
	}

	/* ------------------------------------------------------------------ */
	/* Rebaseline queue (folders too large to re-trust inline)             */
	/* ------------------------------------------------------------------ */

	/**
	 * Queues a folder for a background baseline. Until a scan that listed it
	 * after now finishes, its new and changed files are judged like a baseline
	 * (trusted unless malware) instead of being reported as new.
	 *
	 * @param string $abs_dir Absolute folder inside the scan root.
	 * @return bool
	 */
	public function queue_rebaseline( $abs_dir ) {
		$root = Paths::scan_root();
		$dir  = trailingslashit( wp_normalize_path( (string) $abs_dir ) );
		if ( 0 !== strpos( $dir, $root ) || $dir === $root ) {
			return false;
		}
		$prefix = substr( $dir, strlen( $root ) );
		if ( Store::db_text( $prefix ) !== $prefix ) {
			return false; // Not storable in an option; the next scan reports it instead.
		}
		$queue            = $this->rebaseline_queue( true );
		$queue[ $prefix ] = microtime( true );
		update_option( self::QUEUE_OPTION, $queue, false );
		$this->queue = null;
		return true;
	}

	/**
	 * Starts a path-limited baseline for the queued folders when no job runs.
	 *
	 * @param float $wait Seconds to wait for the lock.
	 * @return string|false Job id.
	 */
	public function start_queued_rebaselines( $wait = 0.0 ) {
		$queue = $this->rebaseline_queue( true );
		if ( ! $queue ) {
			return false;
		}
		$state = $this->load( true );
		if ( $this->is_active( $state ) && ! $this->is_stale( $state ) ) {
			return false; // That job's finish() starts them.
		}

		$root    = Paths::scan_root();
		$paths   = array();
		$removed = false;
		foreach ( array_keys( $queue ) as $prefix ) {
			if ( @is_dir( $root . $prefix ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				$paths[] = untrailingslashit( $root . $prefix );
			} else {
				unset( $queue[ $prefix ] ); // Folder removed since; its rows go with the next scan.
				$removed = true;
			}
		}
		if ( $removed ) {
			$this->write_queue( $queue );
		}
		if ( ! $paths ) {
			return false;
		}

		$id = $this->start(
			array(
				'mode'    => 'baseline',
				'paths'   => $paths,
				'trigger' => 'update',
				'wait'    => $wait,
			)
		);
		if ( ! is_string( $id ) ) {
			return false;
		}
		if ( function_exists( 'wp_next_scheduled' ) && ! wp_next_scheduled( File_Monitor::TICK_HOOK ) ) {
			wp_schedule_single_event( time() + 10, File_Monitor::TICK_HOOK );
		}
		return $id;
	}

	/**
	 * @param bool $fresh Bypass the object cache.
	 * @return array Relative prefix => queued at (microtime).
	 */
	private function rebaseline_queue( $fresh = false ) {
		if ( $fresh ) {
			wp_cache_delete( self::QUEUE_OPTION, 'options' );
		}
		$queue = get_option( self::QUEUE_OPTION, array() );
		return is_array( $queue ) ? $queue : array();
	}

	/**
	 * @param array $queue Queue.
	 */
	private function write_queue( array $queue ) {
		if ( $queue ) {
			update_option( self::QUEUE_OPTION, $queue, false );
		} else {
			delete_option( self::QUEUE_OPTION );
		}
		$this->queue = null;
	}

	/**
	 * Whether a relative path lies in a queued folder.
	 *
	 * @param string $rel Relative path.
	 * @return bool
	 */
	private function in_rebaseline_queue( $rel ) {
		if ( null === $this->queue ) {
			$this->queue = $this->rebaseline_queue( true );
		}
		foreach ( $this->queue as $prefix => $queued_at ) {
			if ( '' !== (string) $prefix && 0 === strpos( $rel, (string) $prefix ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * At the end of a run: drops queued folders this run fully covered (they
	 * were already queued, with the same time, when it started, so it listed
	 * them after the update; and it scanned the whole site or a parent folder),
	 * and asks tick() to start a baseline for the rest.
	 */
	private function settle_rebaseline_queue() {
		$queue = $this->rebaseline_queue( true );
		if ( ! $queue ) {
			return;
		}
		$seen    = isset( $this->state['queue_seen'] ) && is_array( $this->state['queue_seen'] ) ? $this->state['queue_seen'] : array();
		$covers  = empty( $this->state['paths'] ) ? array( '' ) : (array) $this->state['prefixes'];
		$changed = false;
		foreach ( $queue as $prefix => $queued_at ) {
			if ( ! isset( $seen[ $prefix ] ) || sprintf( '%.6F', (float) $seen[ $prefix ] ) !== sprintf( '%.6F', (float) $queued_at ) ) {
				continue; // Queued (again) after this run started listing files.
			}
			foreach ( $covers as $cover ) {
				if ( '' === (string) $cover || 0 === strpos( (string) $prefix, (string) $cover ) ) {
					unset( $queue[ $prefix ] );
					$changed = true;
					break;
				}
			}
		}
		if ( $changed ) {
			$this->write_queue( $queue );
		}
		if ( $queue ) {
			$this->chain = true;
		}
	}

	/* ------------------------------------------------------------------ */
	/* Phase: enumerating                                                  */
	/* ------------------------------------------------------------------ */

	/**
	 * Iterative DFS that appends relative file paths to the list file.
	 *
	 * @param float $deadline Microtime deadline.
	 */
	private function enumerate( $deadline ) {
		$root   = $this->root();
		$handle = @fopen( $this->state['list_file'], 'ab' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- appended in chunks while the folder tree is walked.
		if ( ! $handle ) {
			$this->fail( __( 'Could not open the scan file list for writing. Check the data folder permissions and that the same user runs every scan step.', 'cybergate-security' ) );
			return;
		}

		$checks = 0;
		$buffer = '';
		while ( ! empty( $this->state['stack'] ) ) {
			if ( $this->cancel_requested() ) {
				$this->flush_enum( $handle, $buffer );
				fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- stream of the scan file list, written in chunks.
				$this->cancel_now();
				return;
			}
			$rel_dir = $this->stack_pop();
			$abs_dir = '' === $rel_dir ? rtrim( $root, '/' ) : $root . $rel_dir;

			$dh = @opendir( $abs_dir ); // phpcs:ignore
			if ( ! $dh ) {
				++$this->state['skipped'];
				continue;
			}
			$entries = array();
			while ( false !== ( $entry = readdir( $dh ) ) ) {
				if ( '.' === $entry || '..' === $entry ) {
					continue;
				}
				$entries[] = $entry;
				if ( ++$checks % self::ENUM_CHECK === 0 && microtime( true ) >= $deadline ) {
					// Put this directory back and resume next tick.
					closedir( $dh );
					$this->stack_push( $rel_dir );
					$this->flush_enum( $handle, $buffer );
					fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- stream of the scan file list, written in chunks.
					$this->state['current'] = Store::db_text( $rel_dir );
					return;
				}
			}
			closedir( $dh );
			sort( $entries, SORT_STRING );

			foreach ( $entries as $entry ) {
				$rel = '' === $rel_dir ? $entry : $rel_dir . '/' . $entry;
				$abs = $root . $rel;

				if ( is_link( $abs ) ) {
					// Never follow symlinked directories; a symlinked file is listed
					// but scanned by its own path, which realpath checks will catch.
					if ( @is_dir( $abs ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
						continue;
					}
				}

				if ( @is_dir( $abs ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
					if ( Paths::is_excluded( $rel . '/' ) ) {
						continue;
					}
					$this->stack_push( $rel );
					continue;
				}

				if ( ! @is_file( $abs ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
					continue;
				}
				if ( Paths::is_excluded( $rel ) ) {
					continue;
				}

				$buffer .= $this->encode_line( $rel ) . "\n";
				++$this->state['files_total'];
				if ( strlen( $buffer ) >= 65536 ) {
					$this->flush_enum( $handle, $buffer );
				}
			}

			++$this->state['enum_count'];
			if ( microtime( true ) >= $deadline ) {
				$this->flush_enum( $handle, $buffer );
				fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- stream of the scan file list, written in chunks.
				$this->state['current'] = Store::db_text( $rel_dir );
				return;
			}
		}

		$this->flush_enum( $handle, $buffer );
		fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- stream of the scan file list, written in chunks.
		$this->state['state']   = 'processing';
		$this->state['current'] = '';
	}

	/**
	 * @param resource $handle Open list file.
	 * @param string   $buffer Buffered lines (cleared).
	 */
	private function flush_enum( $handle, &$buffer ) {
		if ( '' !== $buffer ) {
			@fwrite( $handle, $buffer ); // phpcs:ignore
			$buffer = '';
		}
	}

	/* ------------------------------------------------------------------ */
	/* Phase: processing                                                   */
	/* ------------------------------------------------------------------ */

	/**
	 * Processes batches of list lines until the deadline or the list ends.
	 * The deadline is checked after every file and the state is saved after
	 * every batch, so one slow file can never make a whole batch repeat.
	 *
	 * @param float $deadline Microtime deadline.
	 */
	private function process( $deadline ) {
		$root = $this->root();

		do {
			if ( $this->cancel_requested() ) {
				$this->cancel_now();
				return;
			}
			$lines = $this->read_lines( self::BATCH );
			if ( false === $lines ) {
				// Never treat an unreadable list as finished: that would delete the
				// manifest rows of every file not reached yet.
				$this->fail( __( 'Could not read the scan file list. Check the data folder permissions and that the same user runs every scan step.', 'cybergate-security' ) );
				return;
			}
			if ( ! $lines ) {
				$this->state['list_offset'] = $this->read_end;
				$this->state['state']       = 'finishing';
				return;
			}

			// Look up every path in the manifest in one query.
			$hashes = array();
			foreach ( $lines as $entry ) {
				$hashes[ $entry[0] ] = Paths::hash( $entry[0] );
			}
			$manifest = wpcybersec()->store->manifest_get_many( array_values( $hashes ) );

			$upserts  = array();
			$seen     = array();
			$complete = true;
			$count    = count( $lines );
			foreach ( $lines as $i => $entry ) {
				list( $rel, $end ) = $entry;
				$abs               = $root . $rel;
				$stat              = $this->stat( $abs );
				if ( null === $stat ) {
					// Vanished or unreadable between listing and processing.
					++$this->state['skipped'];
				} else {
					$row    = isset( $manifest[ $hashes[ $rel ] ] ) ? $manifest[ $hashes[ $rel ] ] : null;
					$result = $this->evaluate( $abs, $rel, $stat, $row );
					$this->capture( $abs, $rel, $stat, $row, $result );

					// A file that was flagged and now verifies (official checksum or
					// approved fingerprint) no longer needs a decision.
					if ( $row && Store::STATE_TRUSTED !== (string) $row['state'] && Store::STATE_TRUSTED === $result['state'] ) {
						wpcybersec()->store->items_resolve_open( $rel, 'now_trusted' );
					}

					$upserts[] = array(
						'path'   => $rel,
						'sha256' => $result['sha256'],
						'size'   => $stat['size'],
						'mtime'  => $stat['mtime'],
						'state'  => $result['state'],
						'run_id' => $this->state['id'],
					);
					$seen[]                 = $hashes[ $rel ];
					$this->state['current'] = Store::db_text( $rel );
				}
				++$this->state['files_done'];
				$this->state['list_offset'] = $end;

				if ( $i < $count - 1 && microtime( true ) >= $deadline ) {
					$complete = false;
					break;
				}
			}
			if ( $complete ) {
				$this->state['list_offset'] = $this->read_end;
			}

			if ( $upserts ) {
				wpcybersec()->store->manifest_upsert_many( $upserts );
			}
			if ( $seen ) {
				// Mark pre-existing rows (unchanged, skipped) as seen this run too.
				wpcybersec()->store->manifest_touch( $seen, $this->state['id'] );
			}

			if ( ! $this->refresh_lock() ) {
				$this->lost_lock = true;
				return;
			}
			$this->save();
		} while ( microtime( true ) < $deadline );
	}

	/**
	 * Decides what a single file is and records items as needed.
	 *
	 * Order in every mode: the allowlist, then official checksums (a verified
	 * core, plugin or own file is never signature scanned), then malware
	 * signatures, then the file policy.
	 *
	 * @param string     $abs  Absolute path.
	 * @param string     $rel  Relative path.
	 * @param array      $stat { size, mtime }.
	 * @param array|null $row  Manifest row or null.
	 * @return array { state, sha256 }
	 */
	private function evaluate( $abs, $rel, array $stat, $row ) {
		$scanner = wpcybersec()->scanner;
		$mode    = $this->state['mode'];
		$malware = $this->state['malware'];

		$known     = is_array( $row );
		$unchanged = $known && (int) $row['size'] === $stat['size'] && (int) $row['mtime'] === $stat['mtime'] && '' !== (string) $row['sha256'];

		// Where a file is can be wrong by itself (a file among the core files that
		// WordPress does not ship, a stray PHP file in the WordPress root). This
		// only looks at the path and the core file list, so it runs for unchanged
		// trusted files too: a baseline from before this check cannot hide them.
		$integrity = $scanner->integrity_issue( $rel );
		if ( '' !== $integrity && $unchanged && wpcybersec()->allowlist->is_allowed_hash( (string) $row['sha256'], Paths::is_executable( $abs ) ) ) {
			$integrity = ''; // Approved before ("Mark safe" or "Allow").
		}

		// Fast path: unchanged + already trusted. Incremental and baseline skip it;
		// full re-scans trusted files for malware using the stored hash.
		if ( $unchanged && Store::STATE_TRUSTED === (string) $row['state'] && 'full' !== $mode && '' === $integrity ) {
			++$this->state['skipped'];
			return array(
				'state'  => Store::STATE_TRUSTED,
				'sha256' => (string) $row['sha256'],
			);
		}

		$prev_sha = $known ? (string) $row['sha256'] : '';
		$sha      = $unchanged ? $prev_sha : $this->hash( $abs, $stat['size'] );
		if ( '' === $sha ) {
			// Could not read the file; keep going without changing its state.
			++$this->state['skipped'];
			return array(
				'state'  => $known ? (string) $row['state'] : Store::STATE_PENDING,
				'sha256' => $prev_sha,
			);
		}

		$is_new     = ! $known;
		$changed    = $known && ! $unchanged && '' !== $prev_sha && ! hash_equals( $prev_sha, $sha );
		$too_big    = $stat['size'] > $scanner->max_bytes();
		$executable = Paths::is_executable( $abs );
		$change     = $is_new ? 'new' : 'modified';
		// An approval covers the kind of name it was given for: bytes approved as
		// an image are not approved as a PHP file.
		$allowed = wpcybersec()->allowlist->is_allowed_hash( $sha, $executable );

		/* -------- Baseline (or a folder re-baselined after an update). -------- */
		if ( 'baseline' === $mode || ( ! $unchanged && $this->in_rebaseline_queue( $rel ) ) ) {
			return $this->evaluate_baseline( $abs, $rel, $sha, $stat, $row, $change, $executable, $allowed, $too_big, $integrity, $changed );
		}

		/* -------- Nothing to decide: known, unchanged, not trusted, no full re-scan.
		   This only happens for files already pending/threat that have not changed
		   (and trusted files with a path problem, which are judged below). */
		if ( $unchanged && 'full' !== $mode && ( '' === $integrity || Store::STATE_TRUSTED !== (string) $row['state'] ) ) {
			++$this->state['skipped'];
			return array(
				'state'  => (string) $row['state'],
				'sha256' => $sha,
			);
		}

		if ( $allowed ) {
			return array(
				'state'  => Store::STATE_TRUSTED,
				'sha256' => $sha,
			);
		}

		// Official checksums: a verified file is trusted without a malware scan.
		$verify = $this->verify( $rel, $sha );
		if ( 'match' === $verify['verdict'] ) {
			return array(
				'state'  => Store::STATE_TRUSTED,
				'sha256' => $sha,
			);
		}

		// An empty or comments-only PHP file (the classic "Silence is golden"
		// index.php that blocks folder listings) cannot run any code.
		if ( $executable && $scanner->is_inert_php( $abs, $stat['size'] ) ) {
			return array(
				'state'  => Store::STATE_TRUSTED,
				'sha256' => $sha,
			);
		}

		if ( '' !== $integrity ) {
			$hits = $malware && ! $too_big ? $scanner->scan_file( $abs, $rel ) : array();
			return $this->handle_integrity( $integrity, $abs, $rel, $sha, $stat, $row, $hits, $verify, $is_new, $changed, $executable, false );
		}

		// What a report is compared with: the last version that was approved,
		// never a version that is itself still waiting for a decision.
		$base = self::approved_base( $rel, $row, $executable );

		// Malware scan (skipped for unchanged files unless mode is full).
		$hits     = array();
		$scan_now = $malware && ! $too_big && ( $is_new || $changed || 'full' === $mode );
		if ( $scan_now ) {
			$hits = $scanner->scan_file( $abs, $rel );
		}
		$severity = $scanner->max_severity( $hits );

		if ( $severity >= Store::SEV_HIGH ) {
			if ( $is_new ) {
				++$this->state['new'];
			} elseif ( $changed ) {
				++$this->state['modified'];
			}
			$this->record_threat( $abs, $rel, $sha, $stat, $hits, $change, $base, $verify );
			return array(
				'state'  => Store::STATE_THREAT,
				'sha256' => $sha,
			);
		}

		// A checksum mismatch on a core, wordpress.org plugin or own file is
		// suspicious even with no signature hit: record a medium threat so the
		// admin can review it (scripts, server config and JavaScript; not
		// images, styles or translations).
		if ( 'mismatch' === $verify['reason'] && self::reports_mismatch( $abs, $executable ) ) {
			$this->record_threat( $abs, $rel, $sha, $stat, $hits, $change, $base, $verify, Store::SEV_MEDIUM );
			return array(
				'state'  => Store::STATE_THREAT,
				'sha256' => $sha,
			);
		}

		// Low severity signature hits (medium) on executable files -> pending file item.
		if ( $severity >= Store::SEV_MEDIUM && $executable ) {
			if ( $is_new ) {
				++$this->state['new'];
			} elseif ( $changed ) {
				++$this->state['modified'];
			}
			$this->record_file( $abs, $rel, $sha, $stat, $change, $base, $hits );
			return array(
				'state'  => Store::STATE_PENDING,
				'sha256' => $sha,
			);
		}

		// A full re-scan only adds findings: a file still waiting for a decision
		// is never promoted to trusted (that would also put it on the fapolicyd
		// trust export).
		if ( $unchanged && Store::STATE_TRUSTED !== (string) $row['state'] ) {
			return array(
				'state'  => (string) $row['state'],
				'sha256' => $sha,
			);
		}

		// New or modified executable files with no hit: apply the file policy.
		if ( $executable ) {
			if ( $is_new ) {
				return $this->handle_new_executable( $abs, $rel, $sha, $stat, $verify );
			}
			if ( $changed ) {
				return $this->handle_modified_executable( $abs, $rel, $sha, $stat, $base, $verify );
			}
		}

		// New or changed non-executable file: nothing to hold, just record the state.
		if ( $is_new ) {
			++$this->state['new'];
		} elseif ( $changed ) {
			++$this->state['modified'];
		}
		return array(
			'state'  => Store::STATE_TRUSTED,
			'sha256' => $sha,
		);
	}

	/**
	 * Baseline decision: trusted, except malware hits and tampered files of
	 * this plugin itself.
	 *
	 * @param string $abs        Path.
	 * @param string $rel        Relative path.
	 * @param string     $sha        Hash.
	 * @param array      $stat       Stat.
	 * @param array|null $row        Manifest row before this run.
	 * @param string     $change     new | modified.
	 * @param bool       $executable Executable name.
	 * @param bool       $allowed    Allowlisted for this kind of name.
	 * @param bool       $too_big    Larger than max_file_mb.
	 * @param string     $integrity  Scanner::integrity_issue() result.
	 * @param bool       $changed    Content differs from the manifest row.
	 * @return array { state, sha256 }
	 */
	private function evaluate_baseline( $abs, $rel, $sha, array $stat, $row, $change, $executable, $allowed, $too_big, $integrity = '', $changed = false ) {
		$trusted = array(
			'state'  => Store::STATE_TRUSTED,
			'sha256' => $sha,
		);
		if ( $allowed ) {
			return $trusted;
		}

		// Checksums first: a verified core, plugin or own file is never signature
		// scanned (this plugin's signature file holds the patterns as data).
		$scanner = wpcybersec()->scanner;
		$verify  = $this->verify( $rel, $sha );
		if ( 'match' === $verify['verdict'] ) {
			return $trusted;
		}
		if ( $executable && $scanner->is_inert_php( $abs, $stat['size'] ) ) {
			return $trusted;
		}

		$hits = array();
		if ( $this->state['malware'] && ! $too_big ) {
			$hits = $scanner->scan_file( $abs, $rel );
		}
		// A baseline trusts what is there, except files that are wrong by where
		// they are (unknown file in wp-admin or wp-includes, stray root PHP file).
		if ( '' !== $integrity ) {
			return $this->handle_integrity( $integrity, $abs, $rel, $sha, $stat, $row, $hits, $verify, ! is_array( $row ), $changed, $executable, true );
		}
		if ( $hits ) {
			if ( $scanner->max_severity( $hits ) >= Store::SEV_HIGH ) {
				$this->record_threat( $abs, $rel, $sha, $stat, $hits, $change, self::approved_base( $rel, $row, $executable ), $verify );
				return array(
					'state'  => Store::STATE_THREAT,
					'sha256' => $sha,
				);
			}
		}

		// A core, wordpress.org plugin or own file that differs from its official
		// checksum is never trusted silently, not even by a baseline: the
		// Changes view compares it with the official original (Originals).
		// Checksums unavailable (offline) means no verdict, so nothing is said.
		if ( 'mismatch' === $verify['reason'] && in_array( $verify['source'], array( 'core', 'plugin', 'self' ), true ) && self::reports_mismatch( $abs, $executable ) ) {
			$this->record_threat( $abs, $rel, $sha, $stat, $hits, $change, self::approved_base( $rel, $row, $executable ), $verify, Store::SEV_MEDIUM );
			return array(
				'state'  => Store::STATE_THREAT,
				'sha256' => $sha,
			);
		}
		return $trusted;
	}

	/**
	 * Which files a checksum mismatch is reported for: executable names
	 * (PHP, .htaccess, .user.ini...) and JavaScript, a common injection target.
	 * Images, styles, fonts and translations that differ are not reported.
	 *
	 * @param string $abs        Path.
	 * @param bool   $executable Executable name.
	 * @return bool
	 */
	public static function reports_mismatch( $abs, $executable ) {
		return (bool) $executable || in_array( Paths::ext( (string) $abs ), array( 'js', 'mjs' ), true );
	}

	/**
	 * Scanner::verify_details() with the last result remembered, so capture()
	 * does not verify the file evaluate() just verified again.
	 *
	 * @param string $rel Relative path.
	 * @param string $sha Hash.
	 * @return array
	 */
	private function verify( $rel, $sha ) {
		if ( null !== $this->verified && $this->verified[0] === $rel && $this->verified[1] === $sha ) {
			return $this->verified[2];
		}
		$result         = wpcybersec()->scanner->verify_details( $rel, $sha );
		$this->verified = array( $rel, $sha, $result );
		return $result;
	}

	/**
	 * Keeps a copy of a file this run trusts (Snapshots), so a later change can
	 * be shown line by line. Files that were already trusted with the same
	 * content got their copy back then; they are only copied again while the
	 * one-time backfill runs (copies were just switched on). Files that match an
	 * official WordPress.org checksum are not copied.
	 *
	 * @param string     $abs    Path.
	 * @param string     $rel    Relative path.
	 * @param array      $stat   Stat.
	 * @param array|null $row    Manifest row before this run.
	 * @param array      $result evaluate() result.
	 */
	private function capture( $abs, $rel, array $stat, $row, array $result ) {
		if ( Store::STATE_TRUSTED !== $result['state'] || '' === (string) $result['sha256'] ) {
			return;
		}
		$known = is_array( $row ) && Store::STATE_TRUSTED === (string) $row['state'] && hash_equals( (string) $row['sha256'], (string) $result['sha256'] );
		if ( $known && empty( $this->state['backfill'] ) ) {
			return;
		}
		$snapshots = wpcybersec()->snapshots;
		if ( ! $snapshots || ! $snapshots->wants( $abs, $stat['size'] ) ) {
			return;
		}
		// An existing copy is not read again, only kept from the next prune().
		$snapshots->store_trusted( $abs, $result['sha256'], $this->verify( $rel, (string) $result['sha256'] ) );
	}

	/**
	 * Keeps a copy of a reported file as it is now, before it may be moved to
	 * quarantine (the previous version is the copy taken when it was trusted).
	 *
	 * @param string $abs Path.
	 * @param string $sha Hash.
	 */
	private function snapshot_current( $abs, $sha ) {
		$snapshots = wpcybersec()->snapshots;
		if ( $snapshots && '' !== (string) $sha ) {
			$snapshots->store( $abs, $sha );
		}
	}

	/**
	 * True for a file that belongs to this plugin's own code (listed in
	 * checksums.json, or checksums.json is missing). Such files are never moved
	 * to quarantine: that would break the security plugin itself.
	 *
	 * @param array|null $verify verify_details() result.
	 * @return bool
	 */
	private function is_own_code( $verify ) {
		return is_array( $verify ) && 'self' === $verify['source'] && 'unknown_file' !== $verify['reason'];
	}

	/**
	 * New executable file with no malware hit.
	 *
	 * @param string     $abs    Path.
	 * @param string     $rel    Relative path.
	 * @param string     $sha    Hash.
	 * @param array      $stat   Stat.
	 * @param array|null $verify Checksum result.
	 * @return array
	 */
	private function handle_new_executable( $abs, $rel, $sha, array $stat, $verify = null ) {
		++$this->state['new'];
		$mode = (string) wpcybersec()->settings->get( 'file_mode', 'report' );
		if ( 'off' === $mode ) {
			return array(
				'state'  => Store::STATE_TRUSTED,
				'sha256' => $sha,
			);
		}
		if ( 'quarantine_exec' === $mode && ! $this->is_own_code( $verify ) ) {
			return $this->quarantine_file( $abs, $rel, $sha, $stat, 'new', self::no_base() );
		}
		$this->record_file( $abs, $rel, $sha, $stat, 'new', self::no_base(), array() );
		return array(
			'state'  => Store::STATE_PENDING,
			'sha256' => $sha,
		);
	}

	/**
	 * Modified executable file with no malware hit.
	 *
	 * @param string     $abs      Path.
	 * @param string     $rel      Relative path.
	 * @param string     $sha      Hash.
	 * @param array      $stat     Stat.
	 * @param array      $base     approved_base().
	 * @param array|null $verify   Checksum result.
	 * @return array
	 */
	private function handle_modified_executable( $abs, $rel, $sha, array $stat, array $base, $verify = null ) {
		++$this->state['modified'];
		$action = (string) wpcybersec()->settings->get( 'modified_action', 'report' );
		if ( 'quarantine' === $action && ! $this->is_own_code( $verify ) ) {
			return $this->quarantine_file( $abs, $rel, $sha, $stat, 'modified', $base );
		}
		$this->record_file( $abs, $rel, $sha, $stat, 'modified', $base, array() );
		return array(
			'state'  => Store::STATE_PENDING,
			'sha256' => $sha,
		);
	}

	/**
	 * Moves a file to quarantine and records a pending file item with the held
	 * copy (the admin approves, which restores it, or deletes it).
	 *
	 * @param string $abs      Path.
	 * @param string $rel      Relative path.
	 * @param string $sha      Hash.
	 * @param array  $stat     Stat.
	 * @param string $change   new | modified.
	 * @param array  $base     approved_base().
	 * @param array  $hits     Hits that explain the report.
	 * @return array
	 */
	private function quarantine_file( $abs, $rel, $sha, array $stat, $change, array $base, array $hits = array() ) {
		$this->snapshot_current( $abs, $sha );
		$held = wpcybersec()->quarantine->hold( $abs, true );
		if ( is_wp_error( $held ) ) {
			// Could not move it; fall back to reporting it in place.
			$this->record_file( $abs, $rel, $sha, $stat, $change, $base, $hits );
			return array(
				'state'  => Store::STATE_PENDING,
				'sha256' => $sha,
			);
		}
		++$this->state['quarantined'];
		// Status stays pending: the item still needs a decision and must show in
		// Pending approvals, counts, and the scan email.
		$this->record_file( $abs, $rel, $sha, $stat, $change, $base, $hits, $held['quarantine_path'], Store::STATUS_PENDING );
		wpcybersec()->logger->log(
			'file_quarantined',
			/* translators: %s: relative path */
			sprintf( __( 'Quarantined new executable file %s.', 'cybergate-security' ), $rel ),
			array( 'path' => $rel, 'sha256' => $sha )
		);
		return array(
			'state'  => Store::STATE_PENDING,
			'sha256' => $sha,
		);
	}

	/**
	 * A file that is wrong by where it is (Scanner::integrity_issue()), in
	 * every scan mode including baseline:
	 *   core_unknown_file  -> high threat (more when signatures say so);
	 *   root_php,
	 *   core_unknown_config -> medium pending file item, or a threat when a
	 *                          signature found high severity code. A new or
	 *                          changed file outside a baseline follows the
	 *                          quarantine policy for new and modified files.
	 * Deduplicated like every other item (open item for the same path + hash).
	 *
	 * @param string     $integrity  Issue code.
	 * @param string     $abs        Path.
	 * @param string     $rel        Relative path.
	 * @param string     $sha        Hash.
	 * @param array      $stat       Stat.
	 * @param array|null $row        Manifest row before this run.
	 * @param array      $hits       Signature hits.
	 * @param array      $verify     Checksum result.
	 * @param bool       $is_new     Not in the manifest before.
	 * @param bool       $changed    Content changed since the manifest row.
	 * @param bool       $executable Executable name.
	 * @param bool       $baseline   Judged as part of a baseline.
	 * @return array { state, sha256 }
	 */
	private function handle_integrity( $integrity, $abs, $rel, $sha, array $stat, $row, array $hits, $verify, $is_new, $changed, $executable, $baseline ) {
		$scanner  = wpcybersec()->scanner;
		$change   = $changed ? 'modified' : 'new';
		$base     = $changed ? self::approved_base( $rel, $row, $executable ) : self::no_base();
		$severity = $scanner->max_severity( $hits );
		$hits     = array_merge( array( self::integrity_hit( $integrity, $rel ) ), $hits );
		if ( ! $baseline && $is_new ) {
			++$this->state['new'];
		} elseif ( ! $baseline && $changed ) {
			++$this->state['modified'];
		}

		if ( 'core_unknown_file' === $integrity || $severity >= Store::SEV_HIGH ) {
			$this->record_threat( $abs, $rel, $sha, $stat, $hits, $change, $base, $verify, max( Store::SEV_HIGH, $severity ) );
			return array(
				'state'  => Store::STATE_THREAT,
				'sha256' => $sha,
			);
		}

		if ( ! $baseline && ( $is_new || $changed ) && ! $this->is_own_code( $verify ) ) {
			$quarantine = $is_new
				? 'quarantine_exec' === (string) wpcybersec()->settings->get( 'file_mode', 'report' )
				: 'quarantine' === (string) wpcybersec()->settings->get( 'modified_action', 'report' );
			if ( $quarantine ) {
				return $this->quarantine_file( $abs, $rel, $sha, $stat, $change, $base, $hits );
			}
		}
		$this->record_file( $abs, $rel, $sha, $stat, $change, $base, $hits );
		return array(
			'state'  => Store::STATE_PENDING,
			'sha256' => $sha,
		);
	}

	/**
	 * Hit that explains an integrity report (shown like a signature match).
	 *
	 * @param string $integrity Issue code.
	 * @param string $rel       Relative path.
	 * @return array
	 */
	private static function integrity_hit( $integrity, $rel ) {
		switch ( $integrity ) {
			case 'core_unknown_file':
				$title    = __( 'File in wp-admin or wp-includes that is not part of WordPress', 'cybergate-security' );
				$severity = Store::SEV_HIGH;
				break;
			case 'core_unknown_config':
				$title    = __( 'Server configuration file added to a WordPress core folder', 'cybergate-security' );
				$severity = Store::SEV_MEDIUM;
				break;
			default:
				$title    = __( 'PHP file in the WordPress root folder that is not part of WordPress', 'cybergate-security' );
				$severity = Store::SEV_MEDIUM;
		}
		return array(
			'sig'      => 'root_php' === $integrity ? 'root_unknown_php' : $integrity,
			'title'    => $title,
			'severity' => $severity,
			'line'     => 0,
			'snippet'  => Signatures::clean_snippet( $rel ),
		);
	}

	/* ------------------------------------------------------------------ */
	/* Item creation                                                       */
	/* ------------------------------------------------------------------ */

	/**
	 * Creates a pending file item (deduplicated by path + hash).
	 *
	 * @param string $abs             Path.
	 * @param string $rel             Relative path.
	 * @param string $sha             Hash.
	 * @param array  $stat            Stat.
	 * @param string $change          new | modified.
	 * @param array  $base            approved_base().
	 * @param array  $hits            Signature hits.
	 * @param string $quarantine_path Held copy ('' when the file stays).
	 * @param string $status          Item status.
	 */
	private function record_file( $abs, $rel, $sha, array $stat, $change, array $base, array $hits, $quarantine_path = '', $status = Store::STATUS_PENDING ) {
		$store = wpcybersec()->store;
		if ( '' === $quarantine_path ) {
			$this->snapshot_current( $abs, $sha );
		}
		if ( $store->item_find_open( Store::TYPE_FILE, $rel, $sha ) ) {
			return;
		}
		$severity = $hits ? wpcybersec()->scanner->max_severity( $hits ) : Store::SEV_MEDIUM;
		$details  = self::base_details(
			array(
				'change' => $change,
				'hits'   => array_values( $hits ),
			),
			$base,
			$sha
		);
		$id = $store->item_insert(
			array(
				'type'            => Store::TYPE_FILE,
				'status'          => $status,
				'severity'        => $severity,
				'path'            => $rel,
				'original_path'   => $abs,
				'quarantine_path' => $quarantine_path,
				'sha256'          => $sha,
				'size'            => $stat['size'],
				'mime'            => $this->mime( $abs ),
				'source'          => 'scan',
				'details'         => $details,
			)
		);
		if ( $id ) {
			wpcybersec()->logger->log(
				'new' === $change ? 'file_new' : 'file_modified',
				'new' === $change
					/* translators: %s: relative path */
					? sprintf( __( 'Found a new file awaiting review: %s', 'cybergate-security' ), $rel )
					/* translators: %s: relative path */
					: sprintf( __( 'A monitored file changed: %s', 'cybergate-security' ), $rel ),
				array( 'item_id' => $id, 'path' => $rel, 'sha256' => $sha )
			);
			$this->notify_item( $id );
		}
	}

	/**
	 * Creates a threat item and optionally auto-quarantines critical hits. The
	 * item stays pending (with the held copy when quarantined) until the admin
	 * decides.
	 *
	 * @param string     $abs      Path.
	 * @param string     $rel      Relative path.
	 * @param string     $sha      Hash.
	 * @param array      $stat     Stat.
	 * @param array      $hits     Hits.
	 * @param string     $change   new | modified.
	 * @param array      $base     approved_base().
	 * @param array|null $verify   Checksum result.
	 * @param int        $severity Force a severity (default: from hits).
	 */
	private function record_threat( $abs, $rel, $sha, array $stat, array $hits, $change, array $base, $verify = null, $severity = 0 ) {
		$store = wpcybersec()->store;
		++$this->state['threats'];
		$this->snapshot_current( $abs, $sha );

		$existing = $store->item_find_open( Store::TYPE_THREAT, $rel, $sha );
		if ( $existing ) {
			return;
		}

		$severity = $severity > 0 ? $severity : max( Store::SEV_HIGH, wpcybersec()->scanner->max_severity( $hits ) );
		$details  = self::base_details(
			array(
				'change' => $change,
				'hits'   => array_values( $hits ),
			),
			$base,
			$sha
		);
		if ( is_array( $verify ) && '' !== $verify['source'] ) {
			$details['verified'] = $verify['source'];
			if ( '' !== $verify['reason'] ) {
				$details['checksum'] = $verify['reason'];
			}
		}

		$quarantine_path = '';
		if ( Store::SEV_CRITICAL === $severity && wpcybersec()->settings->get( 'auto_quarantine', false ) && ! $this->is_own_code( $verify ) ) {
			$held = wpcybersec()->quarantine->hold( $abs, true );
			if ( ! is_wp_error( $held ) ) {
				$quarantine_path = $held['quarantine_path'];
				++$this->state['quarantined'];
				wpcybersec()->store->manifest_set_state( $rel, Store::STATE_THREAT );
			}
		}

		$id = $store->item_insert(
			array(
				'type'            => Store::TYPE_THREAT,
				'status'          => Store::STATUS_PENDING,
				'severity'        => $severity,
				'path'            => $rel,
				'original_path'   => $abs,
				'quarantine_path' => $quarantine_path,
				'sha256'          => $sha,
				'size'            => $stat['size'],
				'mime'            => $this->mime( $abs ),
				'source'          => 'scan',
				'details'         => $details,
			)
		);
		if ( $id ) {
			wpcybersec()->logger->log(
				'threat_found',
				sprintf(
					/* translators: 1: severity label, 2: relative path */
					__( '%1$s threat found: %2$s', 'cybergate-security' ),
					Store::severity_label( $severity ),
					$rel
				),
				array( 'item_id' => $id, 'path' => $rel, 'sha256' => $sha, 'severity' => $severity )
			);
			if ( '' !== $quarantine_path ) {
				wpcybersec()->logger->log(
					'file_quarantined',
					/* translators: %s: relative path */
					sprintf( __( 'Auto-quarantined critical threat %s.', 'cybergate-security' ), $rel ),
					array( 'item_id' => $id, 'path' => $rel )
				);
			}
			$this->notify_item( $id );
		}
	}

	/**
	 * The version a reported change of a file is compared with ("Last
	 * approved version" on the changes screen). The manifest row holds the
	 * version seen last, which may itself be waiting for a decision (pending)
	 * or be a threat: only a trusted or approved (allowlisted) version counts.
	 * Otherwise the last approved version an open report of the same file
	 * already carries is used, and when there is none, nothing.
	 *
	 * @param string     $rel        Relative path.
	 * @param array|null $row        Manifest row before this run.
	 * @param bool       $executable Executable name (allowlist entries are per kind of name).
	 * @return array { sha256: string ('' for none), state: string (state of the row when it was not approved) }
	 */
	public static function approved_base( $rel, $row, $executable ) {
		$none = self::no_base();
		if ( ! is_array( $row ) || ! isset( $row['sha256'] ) || '' === (string) $row['sha256'] ) {
			return $none;
		}
		$sha   = strtolower( (string) $row['sha256'] );
		$state = isset( $row['state'] ) ? (string) $row['state'] : Store::STATE_TRUSTED;
		$allow = wpcybersec()->allowlist;
		if ( Store::STATE_TRUSTED === $state || ( $allow && $allow->is_allowed_hash( $sha, (bool) $executable ) ) ) {
			return array(
				'sha256' => $sha,
				'state'  => '',
			);
		}
		$latest = null;
		foreach ( array( Store::TYPE_FILE, Store::TYPE_THREAT ) as $type ) {
			$open = wpcybersec()->store->item_find_open( $type, (string) $rel );
			if ( $open && ( null === $latest || (int) $open['id'] > (int) $latest['id'] ) ) {
				$latest = $open;
			}
		}
		$previous = $latest && ! empty( $latest['details']['previous_sha256'] ) ? strtolower( (string) $latest['details']['previous_sha256'] ) : '';
		if ( Snapshots::is_sha( $previous ) ) {
			return array(
				'sha256' => $previous,
				'state'  => '',
			);
		}
		return array(
			'sha256' => '',
			'state'  => $state,
		);
	}

	/**
	 * @return array approved_base() result for "no earlier version".
	 */
	private static function no_base() {
		return array(
			'sha256' => '',
			'state'  => '',
		);
	}

	/**
	 * Adds the comparison base to an item's details: previous_sha256 (the last
	 * approved version), or previous_state when the earlier version was never
	 * approved.
	 *
	 * @param array  $details Details.
	 * @param array  $base    approved_base().
	 * @param string $sha     Hash of the reported version.
	 * @return array
	 */
	public static function base_details( array $details, array $base, $sha ) {
		$previous = isset( $base['sha256'] ) ? (string) $base['sha256'] : '';
		if ( '' !== $previous && ! hash_equals( $previous, strtolower( (string) $sha ) ) ) {
			$details['previous_sha256'] = $previous;
		} elseif ( '' === $previous && ! empty( $base['state'] ) ) {
			$details['previous_state'] = (string) $base['state'];
		}
		return $details;
	}

	/**
	 * @param int $id Item id.
	 */
	private function notify_item( $id ) {
		$notifier = wpcybersec()->notifier;
		if ( $notifier && method_exists( $notifier, 'item_created' ) ) {
			$notifier->item_created( $id );
		}
	}

	/* ------------------------------------------------------------------ */
	/* Phase: finishing                                                    */
	/* ------------------------------------------------------------------ */

	/**
	 * Database scan step (when the run includes it), then for whole-site runs
	 * the missing core file count and the administrator check.
	 *
	 * @param float $deadline Microtime deadline of this tick.
	 * @return bool True when this part is complete; false to continue next tick.
	 */
	private function finish_extras( $deadline ) {
		if ( ! empty( $this->state['database'] ) && empty( $this->state['db_done'] ) ) {
			$db = wpcybersec()->db_scanner;
			if ( $db ) {
				$cursor = isset( $this->state['db'] ) && is_array( $this->state['db'] ) ? $this->state['db'] : $db->begin( (string) $this->state['id'] );
				$done   = true;
				try {
					$done = $db->step(
						$cursor,
						$deadline,
						function () {
							return $this->cancel_requested();
						}
					);
					if ( $done ) {
						$db->finish( $cursor );
					}
				} catch ( \Throwable $e ) {
					wpcybersec()->logger->log(
						'db_scan_failed',
						/* translators: %s: error message */
						sprintf( __( 'The database scan stopped: %s', 'cybergate-security' ), Signatures::clean_snippet( $e->getMessage() ) ),
						array( 'id' => $this->state['id'] )
					);
					$done = true;
				}
				$this->state['db_findings'] = isset( $cursor['findings'] ) ? (int) $cursor['findings'] : 0;
				if ( ! $done ) {
					$this->state['db']      = $cursor;
					$this->state['current'] = 'options' === $cursor['stage'] ? __( 'Database: options', 'cybergate-security' ) : __( 'Database: posts', 'cybergate-security' );
					return false;
				}
			}
			$this->state['db']      = null;
			$this->state['db_done'] = true;
		}

		if ( empty( $this->state['paths'] ) && empty( $this->state['extras_done'] ) ) {
			$this->state['extras_done']  = true;
			$this->state['missing_core'] = (int) wpcybersec()->scanner->missing_core_count();
			if ( $this->state['missing_core'] > 0 ) {
				wpcybersec()->logger->log(
					'core_files_missing',
					sprintf(
						/* translators: %s: number of files */
						_n( '%s WordPress core file is missing. Reinstall WordPress from Dashboard > Updates to restore it.', '%s WordPress core files are missing. Reinstall WordPress from Dashboard > Updates to restore them.', $this->state['missing_core'], 'cybergate-security' ),
						number_format_i18n( $this->state['missing_core'] )
					),
					array( 'id' => $this->state['id'], 'missing_core' => $this->state['missing_core'] )
				);
			}
			$watch = wpcybersec()->user_watch;
			if ( $watch ) {
				try {
					$this->state['new_admins'] = (int) $watch->check_all();
				} catch ( \Throwable $e ) {
					wpcybersec()->logger->log( 'admin_check_failed', Signatures::clean_snippet( $e->getMessage() ), array( 'id' => $this->state['id'] ) );
				}
			}
		}
		return true;
	}

	/**
	 * Deleted-file detection, cleanup and notifications.
	 *
	 * @param float $deadline Microtime deadline of this tick (the database scan
	 *                        may need several ticks).
	 */
	private function finish( $deadline = 0.0 ) {
		if ( ! $this->finish_extras( $deadline > 0 ? $deadline : microtime( true ) + self::DEFAULT_BUDGET ) ) {
			return; // The database scan continues next tick.
		}
		if ( $this->cancel_requested( true ) ) {
			$this->cancel_now();
			return;
		}
		$prefixes = ! empty( $this->state['prefixes'] ) ? (array) $this->state['prefixes'] : array( '' );
		// Rows written after this run started (trusted after a decision, an
		// update, an approved upload...) describe files that exist: keep them.
		$before = gmdate( 'Y-m-d H:i:s', (int) $this->state['started_at'] );

		foreach ( $prefixes as $prefix ) {
			do {
				$rows = wpcybersec()->store->manifest_unseen( $this->state['id'], 500, (string) $prefix, $before );
				if ( ! $rows ) {
					break;
				}
				$delete = array();
				foreach ( $rows as $row ) {
					$delete[] = $row['path_hash'];
					++$this->state['deleted'];
					if ( Store::STATE_TRUSTED !== (string) $row['state'] ) {
						wpcybersec()->store->items_resolve_open( (string) $row['path'], 'file_gone' );
					}
				}
				wpcybersec()->store->manifest_delete( $delete );
			} while ( count( $rows ) >= 500 );
		}

		$this->cleanup_files( $this->state );

		$this->state['state']       = 'done';
		$this->state['current']     = '';
		$this->state['finished_at'] = time();
		$this->state['message']     = $this->summary( $this->state );

		if ( 'baseline' === $this->state['mode'] && empty( $this->state['paths'] ) ) {
			update_option( self::BASELINE_OPTION, time(), false );
			update_option( self::ROOT_OPTION, $this->root(), false );
		}
		if ( ! empty( $this->state['backfill'] ) && empty( $this->state['paths'] ) && wpcybersec()->snapshots ) {
			// Every trusted file of the site has been looked at once: copies exist
			// now, unless the backfill was reset while this scan ran.
			wpcybersec()->snapshots->backfill_done( isset( $this->state['backfill_gen'] ) ? (int) $this->state['backfill_gen'] : null );
		}
		$this->settle_rebaseline_queue();

		$this->save_last();

		wpcybersec()->logger->log(
			'scan_finished',
			$this->state['message'],
			array(
				'id'           => $this->state['id'],
				'files'        => $this->state['files_done'],
				'new'          => $this->state['new'],
				'modified'     => $this->state['modified'],
				'deleted'      => $this->state['deleted'],
				'threats'      => $this->state['threats'],
				'quarantined'  => $this->state['quarantined'],
				'skipped'      => $this->state['skipped'],
				'database'     => ! empty( $this->state['database'] ),
				'db_findings'  => isset( $this->state['db_findings'] ) ? (int) $this->state['db_findings'] : 0,
				'missing_core' => isset( $this->state['missing_core'] ) ? (int) $this->state['missing_core'] : -1,
				'new_admins'   => isset( $this->state['new_admins'] ) ? (int) $this->state['new_admins'] : 0,
			)
		);

		$notifier = wpcybersec()->notifier;
		if ( $notifier && method_exists( $notifier, 'scan_finished' ) ) {
			$notifier->scan_finished( $this->status() );
		}

		/**
		 * Fires when a scan finishes.
		 *
		 * @param array $status Final status.
		 */
		do_action( 'wpcybersec_scan_finished', $this->status() );
	}

	/* ------------------------------------------------------------------ */
	/* Lock and cancel request                                             */
	/* ------------------------------------------------------------------ */

	/**
	 * Takes the job lock. INSERT IGNORE succeeds for exactly one caller; an
	 * expired lock is taken over with a compare-and-swap on its old value, so
	 * two callers can never both win.
	 *
	 * @param float $hold Seconds before the lock counts as abandoned.
	 * @param float $wait Seconds to keep trying.
	 * @return string Lock value ('' when not acquired).
	 */
	private function acquire_lock( $hold, $wait = 0.0 ) {
		global $wpdb;
		$table = $wpdb->options;
		$token = substr( md5( uniqid( 'wpcs-lock', true ) . wp_rand() . getmypid() ), 0, 16 );
		$until = microtime( true ) + max( 0.0, (float) $wait );
		$tries = 0;
		while ( true ) {
			$value = ( time() + (int) ceil( $hold ) ) . ':' . $token;
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$added = $wpdb->query( $wpdb->prepare( "INSERT IGNORE INTO {$table} (option_name, option_value, autoload) VALUES (%s, %s, 'no')", self::LOCK_OPTION, $value ) );
			if ( $added ) {
				return $value;
			}
			$current = self::db_option( self::LOCK_OPTION );
			if ( null !== $current && (int) $current < time() ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$taken = $wpdb->query( $wpdb->prepare( "UPDATE {$table} SET option_value = %s WHERE option_name = %s AND option_value = %s", $value, self::LOCK_OPTION, $current ) );
				if ( $taken ) {
					return $value;
				}
			}
			++$tries;
			if ( null === $current && $tries < 3 ) {
				continue; // Released between the two queries: try again at once.
			}
			if ( microtime( true ) >= $until ) {
				return '';
			}
			usleep( 250000 );
		}
	}

	/**
	 * Extends the lock held by this tick.
	 *
	 * @return bool False when the lock was lost (expired and taken over).
	 */
	private function refresh_lock() {
		global $wpdb;
		if ( '' === $this->lock ) {
			return true;
		}
		$token = (string) substr( $this->lock, (int) strpos( $this->lock, ':' ) + 1 );
		$value = ( time() + (int) ceil( $this->lock_hold ) ) . ':' . $token;
		if ( $value === $this->lock ) {
			return true;
		}
		$table = $wpdb->options;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$ok = $wpdb->query( $wpdb->prepare( "UPDATE {$table} SET option_value = %s WHERE option_name = %s AND option_value = %s", $value, self::LOCK_OPTION, $this->lock ) );
		if ( $ok ) {
			$this->lock = $value;
			return true;
		}
		return self::db_option( self::LOCK_OPTION ) === $this->lock;
	}

	/**
	 * Releases a lock this request holds (never someone else's).
	 *
	 * @param string $value Lock value.
	 */
	private function release_lock( $value ) {
		global $wpdb;
		if ( '' === (string) $value ) {
			return;
		}
		$table = $wpdb->options;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE option_name = %s AND option_value = %s", self::LOCK_OPTION, (string) $value ) );
	}

	/**
	 * @param string $id Job id to cancel.
	 */
	private function request_cancel( $id ) {
		global $wpdb;
		$table = $wpdb->options;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query( $wpdb->prepare( "INSERT INTO {$table} (option_name, option_value, autoload) VALUES (%s, %s, 'no') ON DUPLICATE KEY UPDATE option_value = VALUES(option_value)", self::CANCEL_OPTION, (string) $id ) );
		wp_cache_delete( self::CANCEL_OPTION, 'options' );
	}

	/**
	 * Drops a pending cancel request.
	 */
	private function clear_cancel() {
		global $wpdb;
		$table = $wpdb->options;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE option_name = %s", self::CANCEL_OPTION ) );
		wp_cache_delete( self::CANCEL_OPTION, 'options' );
	}

	/**
	 * Whether cancel() asked the running job to stop. Reads the database at
	 * most once a second unless $force.
	 *
	 * @param bool $force Read now.
	 * @return bool
	 */
	private function cancel_requested( $force = false ) {
		$now = microtime( true );
		if ( ! $force && $now - $this->cancel_checked < 1.0 ) {
			return false;
		}
		$this->cancel_checked = $now;
		$value                = self::db_option( self::CANCEL_OPTION );
		return null !== $value && ! empty( $this->state['id'] ) && $value === (string) $this->state['id'];
	}

	/**
	 * Raw option value straight from the database (no object cache), for the
	 * values several processes coordinate through.
	 *
	 * @param string $name Option name.
	 * @return string|null
	 */
	private static function db_option( $name ) {
		global $wpdb;
		$table = $wpdb->options;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$value = $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$table} WHERE option_name = %s LIMIT 1", $name ) );
		return null === $value ? null : (string) $value;
	}

	/* ------------------------------------------------------------------ */
	/* State helpers                                                       */
	/* ------------------------------------------------------------------ */

	/**
	 * @param bool $fresh Read the database, not this request's object cache
	 *                    (another runner may have saved the job meanwhile).
	 * @return array|null
	 */
	private function load( $fresh = false ) {
		if ( $fresh ) {
			wp_cache_delete( self::OPTION, 'options' );
			$notoptions = wp_cache_get( 'notoptions', 'options' );
			if ( is_array( $notoptions ) && isset( $notoptions[ self::OPTION ] ) ) {
				unset( $notoptions[ self::OPTION ] );
				wp_cache_set( 'notoptions', $notoptions, 'options' );
			}
		}
		$state = get_option( self::OPTION, null );
		return is_array( $state ) && ! empty( $state['id'] ) ? $state : null;
	}

	/**
	 * Persists the working state.
	 */
	private function save() {
		if ( null === $this->state ) {
			return;
		}
		update_option( self::OPTION, $this->state, false );
	}

	/**
	 * Copies the final status into the last-scan option.
	 */
	private function save_last() {
		update_option( self::LAST_OPTION, $this->status(), false );
	}

	/**
	 * Marks the job failed and cleans up. Never deletes manifest rows.
	 *
	 * @param string $message Error.
	 */
	private function fail( $message ) {
		if ( null === $this->state ) {
			$this->state = $this->load();
		}
		if ( ! $this->state ) {
			return;
		}
		$this->cleanup_files( $this->state );
		$this->state['state']       = 'failed';
		$this->state['current']     = '';
		$this->state['finished_at'] = time();
		$this->state['message']     = Signatures::clean_snippet( (string) $message );
		$this->save_last();
		wpcybersec()->logger->log(
			'scan_failed',
			/* translators: %s: error message */
			sprintf( __( 'Scan failed: %s', 'cybergate-security' ), $this->state['message'] ),
			array( 'id' => $this->state['id'] )
		);
	}

	/**
	 * Removes the list file for a job.
	 *
	 * @param array|null $state State.
	 */
	private function cleanup_files( $state ) {
		if ( ! is_array( $state ) || empty( $state['list_file'] ) ) {
			return;
		}
		$file = (string) $state['list_file'];
		if ( Storage::is_within( $file, wpcybersec()->storage->jobs_dir() ) && @is_file( $file ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			Fs::delete( $file );
		}
	}

	/**
	 * @param array|null $state State.
	 * @return bool
	 */
	private function is_active( $state ) {
		return is_array( $state ) && in_array( isset( $state['state'] ) ? $state['state'] : '', array( 'enumerating', 'processing', 'finishing' ), true );
	}

	/**
	 * A job that has not ticked in over an hour is considered stuck.
	 *
	 * @param array $state State.
	 * @return bool
	 */
	private function is_stale( array $state ) {
		$ticked = isset( $state['ticked_at'] ) ? (int) $state['ticked_at'] : (int) $state['started_at'];
		return ( time() - $ticked ) > self::STALE_SECONDS;
	}

	/**
	 * Scan root the job was started for.
	 *
	 * @return string
	 */
	private function root() {
		return ! empty( $this->state['root'] ) ? (string) $this->state['root'] : Paths::scan_root();
	}

	/**
	 * @return bool Whether list lines and stack entries are encoded.
	 */
	private function encoded() {
		return ! empty( $this->state['enc'] );
	}

	/**
	 * @param string $rel Relative path.
	 * @return string One list line (without the newline).
	 */
	private function encode_line( $rel ) {
		if ( ! $this->encoded() ) {
			return $rel;
		}
		return strtr(
			$rel,
			array(
				'%'  => '%25',
				"\r" => '%0D',
				"\n" => '%0A',
			)
		);
	}

	/**
	 * @param string $rel Relative folder.
	 */
	private function stack_push( $rel ) {
		$this->state['stack'][] = $this->encoded() ? rawurlencode( $rel ) : $rel;
	}

	/**
	 * @return string Relative folder.
	 */
	private function stack_pop() {
		$entry = (string) array_pop( $this->state['stack'] );
		return $this->encoded() ? rawurldecode( $entry ) : $entry;
	}

	/**
	 * Reads up to $count non-empty list lines from the stored offset. Does not
	 * move the offset: process() advances it per processed line.
	 *
	 * @param int $count Lines.
	 * @return array[]|false List of [ relative path, byte offset after the line ], false when the list cannot be read.
	 */
	private function read_lines( $count ) {
		$file = (string) $this->state['list_file'];
		$fh   = @fopen( $file, 'rb' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- read line by line from an offset.
		if ( ! $fh ) {
			return false;
		}
		$offset = (int) $this->state['list_offset'];
		if ( $offset > 0 ) {
			$info = fstat( $fh );
			if ( ! is_array( $info ) || $offset > (int) $info['size'] || 0 !== fseek( $fh, $offset ) ) {
				fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- the scan file list is read line by line from an offset.
				return false; // Truncated or replaced: not the list this job wrote.
			}
		}
		$lines = array();
		while ( count( $lines ) < $count && false !== ( $line = fgets( $fh ) ) ) {
			$end  = ftell( $fh );
			$line = rtrim( $line, "\r\n" );
			if ( '' !== $line ) {
				$lines[] = array( $this->encoded() ? rawurldecode( $line ) : $line, (int) $end );
			}
		}
		$this->read_end = (int) ftell( $fh );
		fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- the scan file list is read line by line from an offset.
		return $lines;
	}

	/**
	 * @param string $abs Path.
	 * @return array|null { size, mtime }
	 */
	private function stat( $abs ) {
		if ( ! @is_file( $abs ) || ! @is_readable( $abs ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return null;
		}
		$size  = @filesize( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		$mtime = @filemtime( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $size || false === $mtime ) {
			return null;
		}
		return array(
			'size'  => (int) $size,
			'mtime' => (int) $mtime,
		);
	}

	/**
	 * @param string $abs  Path.
	 * @param int    $size Size in bytes.
	 * @return string
	 */
	private function hash( $abs, $size ) {
		return self::fingerprint( $abs, $size );
	}

	/**
	 * Content fingerprint used in the manifest: the sha256 of the file, or for
	 * files larger than max(256 MB, max_file_mb) (backup archives), the sha256
	 * of their size, first MB and last MB. Hashing several GB in full would
	 * outlast max_execution_time and leave the job stuck on one batch.
	 *
	 * @param string $abs  Path.
	 * @param int    $size Size in bytes (-1 to read it).
	 * @return string '' when the file cannot be read.
	 */
	public static function fingerprint( $abs, $size = -1 ) {
		$abs  = (string) $abs;
		$size = (int) $size;
		if ( $size < 0 ) {
			$size = @filesize( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( false === $size ) {
				return '';
			}
			$size = (int) $size;
		}
		$cap    = self::HASH_CAP;
		$plugin = function_exists( 'wpcybersec' ) ? wpcybersec() : null;
		if ( $plugin && ! empty( $plugin->scanner ) ) {
			$cap = max( $cap, (int) $plugin->scanner->max_bytes() );
		}
		if ( $size <= $cap ) {
			$sha = @hash_file( 'sha256', $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return is_string( $sha ) ? $sha : '';
		}
		$chunk = 1048576;
		$head  = @file_get_contents( $abs, false, null, 0, $chunk ); // phpcs:ignore
		$tail  = @file_get_contents( $abs, false, null, max( 0, $size - $chunk ), $chunk ); // phpcs:ignore
		if ( false === $head || false === $tail ) {
			return '';
		}
		$ctx = hash_init( 'sha256' );
		hash_update( $ctx, 'large:' . $size . ':' );
		hash_update( $ctx, $head );
		hash_update( $ctx, $tail );
		return hash_final( $ctx );
	}

	/**
	 * @param string $abs Path.
	 * @return string
	 */
	private function mime( $abs ) {
		$type = wp_check_filetype( basename( $abs ) );
		return ! empty( $type['type'] ) ? (string) $type['type'] : '';
	}

	/**
	 * Normalizes requested scan folders to absolute paths inside the scan root
	 * plus the relative prefixes for deleted detection and the DFS stack.
	 *
	 * @param array $paths Absolute folders.
	 * @return array { abs: string[], rel: string[], stack: string[] }
	 */
	private function normalize_paths( array $paths ) {
		$root  = Paths::scan_root();
		$abs   = array();
		$rel   = array();
		$stack = array();
		foreach ( $paths as $path ) {
			$norm = wp_normalize_path( (string) $path );
			if ( '' === $norm ) {
				continue;
			}
			$real = realpath( $norm );
			if ( $real ) {
				$norm = wp_normalize_path( $real );
			}
			$norm = trailingslashit( $norm );
			if ( 0 !== strpos( $norm, $root ) || ! @is_dir( $norm ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				continue; // Refuse folders outside the scan root, and missing ones.
			}
			if ( Store::db_text( $norm ) !== $norm ) {
				continue; // Not storable in the job state; a whole-site scan covers it.
			}
			$prefix  = ltrim( substr( $norm, strlen( $root ) ), '/' );
			$abs[]   = rtrim( $norm, '/' );
			$rel[]   = $prefix;
			$stack[] = rtrim( $prefix, '/' );
		}
		if ( ! $stack ) {
			$stack = array( '' );
		}
		return array(
			'abs'   => array_values( array_unique( $abs ) ),
			'rel'   => array_values( array_unique( $rel ) ),
			'stack' => array_values( array_unique( $stack ) ),
		);
	}

	/**
	 * @param array $state State.
	 * @return float 0..100
	 */
	private function percent( array $state ) {
		switch ( isset( $state['state'] ) ? $state['state'] : 'idle' ) {
			case 'enumerating':
				return 0.0;
			case 'processing':
				$total = (int) $state['files_total'];
				return $total > 0 ? round( min( 99.0, $state['files_done'] / $total * 100 ), 1 ) : 0.0;
			case 'finishing':
				return 99.0;
			case 'done':
				return 100.0;
			default:
				return 0.0;
		}
	}

	/**
	 * @param array $state State.
	 * @return string
	 */
	private function summary( array $state ) {
		$text = sprintf(
			/* translators: 1: files checked, 2: new, 3: modified, 4: deleted, 5: threats */
			__( 'Checked %1$s files. New: %2$s, modified: %3$s, deleted: %4$s, threats: %5$s.', 'cybergate-security' ),
			number_format_i18n( $state['files_done'] ),
			number_format_i18n( $state['new'] ),
			number_format_i18n( $state['modified'] ),
			number_format_i18n( $state['deleted'] ),
			number_format_i18n( $state['threats'] )
		);
		if ( isset( $state['missing_core'] ) && (int) $state['missing_core'] >= 0 ) {
			/* translators: %s: number of files */
			$text .= ' ' . sprintf( __( 'Missing core files: %s.', 'cybergate-security' ), number_format_i18n( (int) $state['missing_core'] ) );
		}
		if ( ! empty( $state['database'] ) ) {
			/* translators: %s: number of findings */
			$text .= ' ' . sprintf( __( 'Database findings: %s.', 'cybergate-security' ), number_format_i18n( isset( $state['db_findings'] ) ? (int) $state['db_findings'] : 0 ) );
		}
		if ( ! empty( $state['new_admins'] ) ) {
			/* translators: %s: number of accounts */
			$text .= ' ' . sprintf( __( 'New administrators: %s.', 'cybergate-security' ), number_format_i18n( (int) $state['new_admins'] ) );
		}
		return $text;
	}

	/**
	 * @return array
	 */
	private function idle_status() {
		return array(
			'id'           => '',
			'state'        => 'idle',
			'mode'         => '',
			'malware'      => false,
			'trigger'      => '',
			'files_total'  => 0,
			'files_done'   => 0,
			'new'          => 0,
			'modified'     => 0,
			'deleted'      => 0,
			'threats'      => 0,
			'quarantined'  => 0,
			'skipped'      => 0,
			'started_at'   => 0,
			'finished_at'  => 0,
			'current'      => '',
			'message'      => '',
			'percent'      => 0.0,
			'database'     => false,
			'db_findings'  => 0,
			'missing_core' => -1,
			'new_admins'   => 0,
		);
	}
}

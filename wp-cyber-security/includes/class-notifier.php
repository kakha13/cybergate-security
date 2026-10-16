<?php
/**
 * Email and webhook notifications.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Modes (setting notify_mode):
 *   instant  an email as soon as something is held or found, at most one every
 *            10 minutes; anything in between is queued and sent with the next one
 *   digest   one daily summary of pending items and threats (cron wpcybersec_digest)
 *   off      nothing
 *
 * Scan results are collected while a scan runs and sent once, by scan_finished()
 * (instant mode; in digest mode the daily summary includes them).
 * When webhook_url is set, the same summary is posted as JSON {"text": "..."}
 * (Slack, Mattermost, Teams and Discord compatible). Webhook URLs that point to
 * this server's private network are refused.
 */
class Notifier {

	const QUEUE_OPTION = 'wpcybersec_notify_queue';
	const LAST_OPTION  = 'wpcybersec_notify_last';
	const SCAN_OPTION  = 'wpcybersec_notify_scan';
	const LOCK_OPTION  = 'wpcybersec_notify_lock';
	const FLUSH_HOOK   = 'wpcybersec_notify_flush';
	const DIGEST_HOOK  = 'wpcybersec_digest';

	/** Seconds between two instant emails. */
	const THROTTLE = 600;

	/** Items described in full in one email. */
	const MAX_DETAILED = 25;

	/** Queue cap, so a flood of uploads cannot grow the option without limit. */
	const MAX_QUEUE = 500;

	/**
	 * Nothing heavy here; see register().
	 */
	public function __construct() {}

	/**
	 * Hooks.
	 */
	public function register() {
		add_action( self::DIGEST_HOOK, array( $this, 'send_digest' ) );
		add_action( self::FLUSH_HOOK, array( $this, 'flush' ) );
		add_action( 'wpcybersec_settings_updated', array( $this, 'schedule' ), 10, 0 );
		add_action( 'admin_init', array( $this, 'schedule' ) );
	}

	/**
	 * Keeps the daily digest event in line with notify_mode.
	 */
	public function schedule() {
		$next = wp_next_scheduled( self::DIGEST_HOOK );
		if ( 'digest' === $this->mode() ) {
			if ( ! $next ) {
				wp_schedule_event( $this->next_digest_time(), 'daily', self::DIGEST_HOOK );
			}
		} elseif ( $next ) {
			wp_clear_scheduled_hook( self::DIGEST_HOOK );
		}
	}

	/* ------------------------------------------------------------------ */
	/* Events                                                              */
	/* ------------------------------------------------------------------ */

	/**
	 * A new pending item was created (held upload or install, new file, threat).
	 *
	 * @param int $id Item id.
	 */
	public function item_created( $id ) {
		if ( 'instant' !== $this->mode() ) {
			return; // Off, or the daily digest covers it.
		}
		$item = wpcybersec()->store->item_get( (int) $id );
		if ( ! $item ) {
			return;
		}

		// Items found by a scan are reported together when the scan finishes.
		if ( 'scan' === $item['source'] ) {
			$this->enqueue( (int) $item['id'] );
			$this->schedule_flush( time() + self::THROTTLE ); // Fallback if the scan never finishes.
			return;
		}
		$this->enqueue( (int) $item['id'] );
		$this->maybe_flush();
	}

	/**
	 * A scan finished. In instant mode, sends one email when it found threats or
	 * new pending items; in digest mode, keeps the summary for the daily email.
	 *
	 * @param array $status Scan_Job::status() shape.
	 */
	public function scan_finished( array $status ) {
		$mode = $this->mode();
		if ( 'off' === $mode ) {
			return;
		}
		$threats     = isset( $status['threats'] ) ? (int) $status['threats'] : 0;
		$quarantined = isset( $status['quarantined'] ) ? (int) $status['quarantined'] : 0;
		$queued      = count( $this->queue() );
		if ( ! $threats && ! $quarantined && ! $queued ) {
			return;
		}
		$summary = array();
		foreach ( array( 'mode', 'trigger', 'files_total', 'files_done', 'new', 'modified', 'deleted', 'threats', 'quarantined', 'skipped', 'started_at', 'finished_at' ) as $key ) {
			$summary[ $key ] = isset( $status[ $key ] ) ? $status[ $key ] : '';
		}
		update_option( self::SCAN_OPTION, $summary, false );
		if ( 'instant' !== $mode ) {
			return; // send_digest() includes it.
		}
		$this->maybe_flush();
	}

	/**
	 * Sends a test email to the configured recipients (and the webhook, if set).
	 *
	 * @return bool wp_mail() result.
	 */
	public function send_test() {
		$recipients = wpcybersec()->settings->recipients();
		$subject    = $this->subject( __( 'Test email', 'wp-cyber-security' ) );
		$lines      = array(
			/* translators: %s: site name */
			sprintf( __( 'This is a test email from WP Cyber Security on %s.', 'wp-cyber-security' ), $this->site_name() ),
			'',
			__( 'If you can read this, security notifications reach you. Nothing needs to be done.', 'wp-cyber-security' ),
			'',
			/* translators: %s: comma separated email addresses */
			sprintf( __( 'Recipients: %s', 'wp-cyber-security' ), implode( ', ', $recipients ) ),
			/* translators: %s: notification mode */
			sprintf( __( 'Notification mode: %s', 'wp-cyber-security' ), $this->mode_label( $this->mode() ) ),
		);
		$ok      = $this->mail( $recipients, $subject, $this->body( $lines ) );
		$webhook = $this->webhook(
			/* translators: %s: site name */
			sprintf( __( 'Test message from WP Cyber Security on %s. Notifications work.', 'wp-cyber-security' ), $this->site_name() )
		);
		if ( false === $webhook ) {
			$this->log( 'notify_failed', __( 'The webhook URL was not used: it must be an https:// address on the public internet, not this server or its private network.', 'wp-cyber-security' ) );
		}
		$this->log(
			$ok ? 'notify_test' : 'notify_failed',
			$ok
				/* translators: %s: email addresses */
				? sprintf( __( 'Test email sent to %s.', 'wp-cyber-security' ), implode( ', ', $recipients ) )
				/* translators: %s: email addresses */
				: sprintf( __( 'The test email to %s could not be sent. Check the site\'s mail setup (an SMTP plugin usually fixes this).', 'wp-cyber-security' ), implode( ', ', $recipients ) )
		);
		return $ok;
	}

	/**
	 * Daily summary of everything still waiting (digest mode).
	 *
	 * @return bool Whether an email was sent.
	 */
	public function send_digest() {
		if ( 'digest' !== $this->mode() ) {
			return false;
		}
		$store   = wpcybersec()->store;
		$pending = $store->items_query(
			array(
				'type'     => array( Store::TYPE_UPLOAD, Store::TYPE_INSTALL, Store::TYPE_FILE ),
				'status'   => Store::STATUS_PENDING,
				'per_page' => self::MAX_DETAILED,
			)
		);
		$threats = $store->items_query(
			array(
				'type'     => Store::TYPE_THREAT,
				'status'   => Store::STATUS_PENDING,
				'orderby'  => 'severity',
				'per_page' => self::MAX_DETAILED,
			)
		);
		$scan    = get_option( self::SCAN_OPTION, array() );
		delete_option( self::SCAN_OPTION );
		$this->clear_queue(); // Everything queued is part of this summary.

		if ( ! $pending['total'] && ! $threats['total'] ) {
			return false;
		}

		$lines   = array();
		$lines[] = sprintf(
			/* translators: 1: site name, 2: number of pending items, 3: number of threats */
			__( 'Daily security summary for %1$s: %2$d waiting for approval, %3$d possible threats.', 'wp-cyber-security' ),
			$this->site_name(),
			$pending['total'],
			$threats['total']
		);
		$lines[] = '';
		if ( is_array( $scan ) && $scan ) {
			$lines   = array_merge( $lines, $this->scan_lines( $scan ) );
			$lines[] = '';
		}
		if ( $threats['total'] ) {
			$lines[] = __( 'POSSIBLE THREATS', 'wp-cyber-security' );
			foreach ( $threats['rows'] as $item ) {
				$lines[] = '- ' . $this->one_line( $item );
			}
			if ( $threats['total'] > count( $threats['rows'] ) ) {
				/* translators: %d: number of items */
				$lines[] = sprintf( __( '- and %d more', 'wp-cyber-security' ), $threats['total'] - count( $threats['rows'] ) );
			}
			$lines[] = '  ' . $this->reports_url( 'threats' );
			$lines[] = '';
		}
		if ( $pending['total'] ) {
			$lines[] = __( 'WAITING FOR APPROVAL', 'wp-cyber-security' );
			foreach ( $pending['rows'] as $item ) {
				$lines[] = '- ' . $this->one_line( $item );
			}
			if ( $pending['total'] > count( $pending['rows'] ) ) {
				/* translators: %d: number of items */
				$lines[] = sprintf( __( '- and %d more', 'wp-cyber-security' ), $pending['total'] - count( $pending['rows'] ) );
			}
			$lines[] = '  ' . $this->reports_url( 'pending' );
		}

		$subject = $this->subject(
			sprintf(
				/* translators: 1: pending count, 2: threat count */
				__( 'Daily summary: %1$d waiting, %2$d threats', 'wp-cyber-security' ),
				$pending['total'],
				$threats['total']
			)
		);
		$ok = $this->mail( wpcybersec()->settings->recipients(), $subject, $this->body( $lines, true ) );
		$this->webhook(
			sprintf(
				/* translators: 1: site name, 2: pending count, 3: threat count, 4: url */
				__( 'WP Cyber Security on %1$s: %2$d waiting for approval, %3$d possible threats. Review: %4$s', 'wp-cyber-security' ),
				$this->site_name(),
				$pending['total'],
				$threats['total'],
				$this->reports_url( $threats['total'] ? 'threats' : 'pending' )
			)
		);
		$this->log(
			$ok ? 'digest_sent' : 'notify_failed',
			$ok ? __( 'Daily security summary sent.', 'wp-cyber-security' ) : __( 'The daily security summary could not be emailed.', 'wp-cyber-security' )
		);
		return $ok;
	}

	/**
	 * Sends everything queued (items and the last scan summary) in one email.
	 * Runs directly or from the single cron event FLUSH_HOOK.
	 *
	 * @return bool Whether an email was sent.
	 */
	public function flush() {
		$mode = $this->mode();
		if ( 'instant' !== $mode ) {
			if ( 'off' === $mode ) {
				$this->clear_queue();
				delete_option( self::SCAN_OPTION );
			}
			return false; // Digest mode: send_digest() reports everything once a day.
		}
		if ( ! $this->acquire_lock() ) {
			return false;
		}
		$ids  = $this->queue();
		$scan = get_option( self::SCAN_OPTION, array() );
		$this->clear_queue();
		delete_option( self::SCAN_OPTION );
		wp_clear_scheduled_hook( self::FLUSH_HOOK );

		$items = array();
		foreach ( $ids as $id ) {
			$item = wpcybersec()->store->item_get( (int) $id );
			// Skip what an administrator already handled in the meantime.
			if ( $item && Store::STATUS_PENDING === $item['status'] ) {
				$items[] = $item;
			}
		}
		$scan = is_array( $scan ) ? $scan : array();
		if ( ! $items && ( ! $scan || ( empty( $scan['threats'] ) && empty( $scan['quarantined'] ) ) ) ) {
			$this->release_lock();
			return false;
		}

		update_option( self::LAST_OPTION, time(), false );
		$ok = $this->mail( wpcybersec()->settings->recipients(), $this->items_subject( $items, $scan ), $this->items_body( $items, $scan ) );
		$this->webhook( $this->items_webhook_text( $items, $scan ) );
		if ( ! $ok ) {
			$this->log( 'notify_failed', __( 'A security notification email could not be sent. Check the site\'s mail setup.', 'wp-cyber-security' ), array( 'items' => wp_list_pluck( $items, 'id' ) ) );
		}
		$this->release_lock();
		return $ok;
	}

	/* ------------------------------------------------------------------ */
	/* Queue and throttle                                                  */
	/* ------------------------------------------------------------------ */

	/**
	 * Sends now when the last email is older than THROTTLE, otherwise schedules it.
	 */
	private function maybe_flush() {
		$last = (int) get_option( self::LAST_OPTION, 0 );
		$due  = $last + self::THROTTLE;
		if ( $due <= time() ) {
			$this->flush();
			return;
		}
		$this->schedule_flush( $due );
	}

	/**
	 * @param int $timestamp When.
	 */
	private function schedule_flush( $timestamp ) {
		$next = wp_next_scheduled( self::FLUSH_HOOK );
		if ( $next && $next <= $timestamp ) {
			return;
		}
		if ( $next ) {
			wp_clear_scheduled_hook( self::FLUSH_HOOK );
		}
		wp_schedule_single_event( max( time() + 5, (int) $timestamp ), self::FLUSH_HOOK );
	}

	/**
	 * @param int $id Item id.
	 */
	private function enqueue( $id ) {
		$queue = $this->queue();
		if ( ! in_array( $id, $queue, true ) ) {
			$queue[] = $id;
		}
		if ( count( $queue ) > self::MAX_QUEUE ) {
			$queue = array_slice( $queue, -self::MAX_QUEUE );
		}
		update_option( self::QUEUE_OPTION, $queue, false );
	}

	/**
	 * @return int[]
	 */
	private function queue() {
		$queue = get_option( self::QUEUE_OPTION, array() );
		return is_array( $queue ) ? array_values( array_map( 'intval', $queue ) ) : array();
	}

	/**
	 * Empties the queue.
	 */
	private function clear_queue() {
		delete_option( self::QUEUE_OPTION );
	}

	/**
	 * Mutex so two requests do not send the same batch twice.
	 *
	 * @return bool
	 */
	private function acquire_lock() {
		if ( add_option( self::LOCK_OPTION, time(), '', false ) ) {
			return true;
		}
		$since = (int) get_option( self::LOCK_OPTION, 0 );
		if ( $since && $since < time() - 120 ) {
			update_option( self::LOCK_OPTION, time(), false ); // Stale lock from a crashed request.
			return true;
		}
		return false;
	}

	/**
	 * Releases the mutex.
	 */
	private function release_lock() {
		delete_option( self::LOCK_OPTION );
	}

	/* ------------------------------------------------------------------ */
	/* Composing                                                           */
	/* ------------------------------------------------------------------ */

	/**
	 * @param array[] $items Items.
	 * @param array   $scan  Scan summary.
	 * @return string
	 */
	private function items_subject( array $items, array $scan ) {
		$threats = 0;
		foreach ( $items as $item ) {
			if ( Store::TYPE_THREAT === $item['type'] ) {
				++$threats;
			}
		}
		if ( 1 === count( $items ) ) {
			$item = $items[0];
			return $this->subject( $this->item_title( $item ) . ': ' . $this->item_name( $item ) );
		}
		if ( ! $items ) {
			$found = isset( $scan['threats'] ) ? (int) $scan['threats'] : 0;
			/* translators: %d: number of threats */
			return $this->subject( sprintf( _n( 'Scan finished: %d possible threat', 'Scan finished: %d possible threats', $found, 'wp-cyber-security' ), $found ) );
		}
		/* translators: %d: number of items */
		$text = sprintf( _n( '%d item needs your review', '%d items need your review', count( $items ), 'wp-cyber-security' ), count( $items ) );
		if ( $threats ) {
			/* translators: 1: number of threats, 2: "N items need your review" */
			$text = sprintf( _n( '%1$d possible threat - %2$s', '%1$d possible threats - %2$s', $threats, 'wp-cyber-security' ), $threats, $text );
		}
		return $this->subject( $text );
	}

	/**
	 * @param array[] $items Items.
	 * @param array   $scan  Scan summary.
	 * @return string
	 */
	private function items_body( array $items, array $scan ) {
		$lines = array();
		if ( $items ) {
			$lines[] = sprintf(
				/* translators: 1: site name, 2: site url */
				__( 'WP Cyber Security on %1$s (%2$s) needs your attention:', 'wp-cyber-security' ),
				$this->site_name(),
				home_url( '/' )
			);
		} else {
			$lines[] = sprintf(
				/* translators: 1: site name, 2: site url */
				__( 'A security scan on %1$s (%2$s) found something:', 'wp-cyber-security' ),
				$this->site_name(),
				home_url( '/' )
			);
		}
		$lines[] = '';

		if ( $scan ) {
			$lines   = array_merge( $lines, $this->scan_lines( $scan ) );
			$lines[] = '';
		}

		$number = 0;
		foreach ( array_slice( $items, 0, self::MAX_DETAILED ) as $item ) {
			++$number;
			$lines   = array_merge( $lines, $this->item_lines( $item, $number ) );
			$lines[] = '';
		}
		if ( count( $items ) > self::MAX_DETAILED ) {
			/* translators: %d: number of items */
			$lines[] = sprintf( __( 'And %d more. See the Reports page for everything.', 'wp-cyber-security' ), count( $items ) - self::MAX_DETAILED );
			$lines[] = '';
		}

		$lines[] = __( 'Review everything here:', 'wp-cyber-security' );
		$lines[] = $this->reports_url( $this->has_threat( $items, $scan ) ? 'threats' : 'pending' );
		return $this->body( $lines, true );
	}

	/**
	 * Detailed block for one item.
	 *
	 * @param array $item   Item.
	 * @param int   $number Position.
	 * @return string[]
	 */
	private function item_lines( array $item, $number ) {
		$details = is_array( $item['details'] ) ? $item['details'] : array();
		$lines   = array( $number . '. ' . $this->item_title( $item ) );
		$rows    = array();

		if ( Store::TYPE_INSTALL === $item['type'] ) {
			$name    = ! empty( $details['name'] ) ? (string) $details['name'] : $this->item_name( $item );
			$version = ! empty( $details['version'] ) ? ' ' . $details['version'] : '';
			$slug    = ! empty( $details['slug'] ) ? ' (' . $details['slug'] . ')' : '';
			$rows[]  = array( __( 'Package', 'wp-cyber-security' ), $name . $version . $slug );
			$rows[]  = array( __( 'Source', 'wp-cyber-security' ), $this->install_source_label( isset( $details['install_source'] ) ? (string) $details['install_source'] : '' ) );
		} else {
			$rows[] = array( __( 'File', 'wp-cyber-security' ), (string) $item['path'] );
			if ( (int) $item['size'] > 0 ) {
				$rows[] = array( __( 'Size', 'wp-cyber-security' ), size_format( (int) $item['size'], 1 ) );
			}
			if ( '' !== (string) $item['sha256'] ) {
				$rows[] = array( __( 'SHA-256', 'wp-cyber-security' ), (string) $item['sha256'] );
			}
		}

		$rows[] = array( __( 'By', 'wp-cyber-security' ), $this->who( $item ) );
		$where  = $this->where( $item );
		if ( '' !== $where ) {
			$rows[] = array( __( 'From', 'wp-cyber-security' ), $where );
		}
		if ( ! empty( $item['created_at'] ) ) {
			$rows[] = array( __( 'When', 'wp-cyber-security' ), $this->format_date( (string) $item['created_at'] ) );
		}
		$rows[] = array( __( 'Verdict', 'wp-cyber-security' ), $this->verdict( $item ) );
		$rows[] = array( __( 'Review', 'wp-cyber-security' ), $this->reports_url( Store::TYPE_THREAT === $item['type'] ? 'threats' : 'pending' ) );

		$width = 0;
		foreach ( $rows as $row ) {
			$width = max( $width, $this->strlen( $row[0] ) );
		}
		foreach ( $rows as $row ) {
			$lines[] = '   ' . $row[0] . ':' . str_repeat( ' ', $width - $this->strlen( $row[0] ) + 2 ) . $this->plain( $row[1] );
		}
		return $lines;
	}

	/**
	 * @param array $scan Scan summary.
	 * @return string[]
	 */
	private function scan_lines( array $scan ) {
		$mode  = isset( $scan['mode'] ) ? (string) $scan['mode'] : '';
		$modes = array(
			'incremental' => __( 'Quick scan', 'wp-cyber-security' ),
			'full'        => __( 'Full malware scan', 'wp-cyber-security' ),
			'baseline'    => __( 'Baseline scan', 'wp-cyber-security' ),
		);
		$label = isset( $modes[ $mode ] ) ? $modes[ $mode ] : __( 'Scan', 'wp-cyber-security' );
		$lines = array(
			sprintf(
				/* translators: 1: scan type, 2: files checked */
				__( '%1$s finished: %2$s files checked.', 'wp-cyber-security' ),
				$label,
				number_format_i18n( isset( $scan['files_done'] ) ? (int) $scan['files_done'] : 0 )
			),
			sprintf(
				/* translators: 1: new, 2: modified, 3: deleted, 4: threats, 5: quarantined */
				__( 'New files: %1$d, modified: %2$d, deleted: %3$d, possible threats: %4$d, moved to quarantine: %5$d.', 'wp-cyber-security' ),
				isset( $scan['new'] ) ? (int) $scan['new'] : 0,
				isset( $scan['modified'] ) ? (int) $scan['modified'] : 0,
				isset( $scan['deleted'] ) ? (int) $scan['deleted'] : 0,
				isset( $scan['threats'] ) ? (int) $scan['threats'] : 0,
				isset( $scan['quarantined'] ) ? (int) $scan['quarantined'] : 0
			),
		);
		return $lines;
	}

	/**
	 * Short single line for digests and webhooks.
	 *
	 * @param array $item Item.
	 * @return string
	 */
	private function one_line( array $item ) {
		$text = $this->item_title( $item ) . ': ' . $this->item_name( $item );
		if ( (int) $item['severity'] > 0 ) {
			$text .= ' [' . Store::severity_label( (int) $item['severity'] ) . ']';
		}
		if ( ! empty( $item['created_at'] ) ) {
			$text .= ' - ' . $this->format_date( (string) $item['created_at'] );
		}
		return $this->plain( $text );
	}

	/**
	 * @param array[] $items Items.
	 * @param array   $scan  Scan summary.
	 * @return string
	 */
	private function items_webhook_text( array $items, array $scan ) {
		$parts = array();
		foreach ( array_slice( $items, 0, 10 ) as $item ) {
			$parts[] = '- ' . $this->one_line( $item );
		}
		if ( count( $items ) > 10 ) {
			/* translators: %d: number of items */
			$parts[] = sprintf( __( '- and %d more', 'wp-cyber-security' ), count( $items ) - 10 );
		}
		if ( $items ) {
			$head = sprintf(
				/* translators: 1: site name, 2: number of items */
				_n( 'WP Cyber Security on %1$s: %2$d item needs review.', 'WP Cyber Security on %1$s: %2$d items need review.', count( $items ), 'wp-cyber-security' ),
				$this->site_name(),
				count( $items )
			);
		} else {
			$head = sprintf(
				/* translators: 1: site name, 2: number of threats */
				__( 'WP Cyber Security on %1$s: a scan found %2$d possible threats.', 'wp-cyber-security' ),
				$this->site_name(),
				isset( $scan['threats'] ) ? (int) $scan['threats'] : 0
			);
		}
		/* translators: %s: url */
		$parts[] = sprintf( __( 'Review: %s', 'wp-cyber-security' ), $this->reports_url( $this->has_threat( $items, $scan ) ? 'threats' : 'pending' ) );
		return $head . "\n" . implode( "\n", $parts );
	}

	/**
	 * @param array $item Item.
	 * @return string
	 */
	private function item_title( array $item ) {
		$details = is_array( $item['details'] ) ? $item['details'] : array();
		switch ( $item['type'] ) {
			case Store::TYPE_UPLOAD:
				return 'guard' === $item['source']
					? __( 'Upload held by the early guard', 'wp-cyber-security' )
					: __( 'Upload waiting for approval', 'wp-cyber-security' );
			case Store::TYPE_INSTALL:
				$theme = isset( $details['install_type'] ) && 'theme' === $details['install_type'];
				if ( ! empty( $details['update'] ) ) {
					return $theme ? __( 'Theme update waiting for approval', 'wp-cyber-security' ) : __( 'Plugin update waiting for approval', 'wp-cyber-security' );
				}
				return $theme ? __( 'Theme install waiting for approval', 'wp-cyber-security' ) : __( 'Plugin install waiting for approval', 'wp-cyber-security' );
			case Store::TYPE_THREAT:
				return __( 'Possible malware found', 'wp-cyber-security' );
			default:
				if ( Store::STATUS_QUARANTINED === $item['status'] || '' !== (string) $item['quarantine_path'] ) {
					return __( 'Unknown file moved to quarantine', 'wp-cyber-security' );
				}
				return isset( $details['change'] ) && 'modified' === $details['change']
					? __( 'Modified file needs review', 'wp-cyber-security' )
					: __( 'New file needs review', 'wp-cyber-security' );
		}
	}

	/**
	 * @param array $item Item.
	 * @return string
	 */
	private function item_name( array $item ) {
		$details = is_array( $item['details'] ) ? $item['details'] : array();
		if ( Store::TYPE_INSTALL === $item['type'] && ! empty( $details['name'] ) ) {
			return $this->plain( (string) $details['name'] );
		}
		if ( Store::TYPE_UPLOAD === $item['type'] ) {
			return $this->plain( (string) $item['path'] );
		}
		return $this->plain( (string) $item['path'] );
	}

	/**
	 * Who caused the item.
	 *
	 * @param array $item Item.
	 * @return string
	 */
	private function who( array $item ) {
		if ( 'scan' === $item['source'] ) {
			return __( 'Found by a scan (the file was already on the server)', 'wp-cyber-security' );
		}
		$user = ! empty( $item['user_id'] ) ? get_userdata( (int) $item['user_id'] ) : false;
		if ( $user ) {
			/* translators: 1: display name, 2: login, 3: user id */
			return sprintf( __( '%1$s (%2$s, user #%3$d)', 'wp-cyber-security' ), $user->display_name, $user->user_login, $user->ID );
		}
		if ( 'guard' === $item['source'] ) {
			return __( 'Unknown sender (held before WordPress loaded)', 'wp-cyber-security' );
		}
		if ( 'sideload' === $item['source'] ) {
			return __( 'Downloaded by WordPress (importer or remote media)', 'wp-cyber-security' );
		}
		return __( 'A visitor who was not logged in', 'wp-cyber-security' );
	}

	/**
	 * Where it came from.
	 *
	 * @param array $item Item.
	 * @return string
	 */
	private function where( array $item ) {
		$details = is_array( $item['details'] ) ? $item['details'] : array();
		$parts   = array();
		if ( ! empty( $item['ip'] ) ) {
			/* translators: %s: IP address */
			$parts[] = sprintf( __( 'IP %s', 'wp-cyber-security' ), $item['ip'] );
		}
		if ( 'guard' === $item['source'] && ! empty( $details['script'] ) ) {
			$parts[] = (string) $details['script'];
		} elseif ( ! empty( $details['request_uri'] ) ) {
			$parts[] = (string) $details['request_uri'];
		}
		return implode( ', ', $parts );
	}

	/**
	 * Severity and hits summary.
	 *
	 * @param array $item Item.
	 * @return string
	 */
	private function verdict( array $item ) {
		$details = is_array( $item['details'] ) ? $item['details'] : array();
		$hits    = isset( $details['hits'] ) && is_array( $details['hits'] ) ? $details['hits'] : array();
		if ( ! $hits ) {
			if ( isset( $details['checksum'] ) && 'mismatch' === $details['checksum'] ) {
				return __( 'Differs from the official WordPress.org checksum', 'wp-cyber-security' );
			}
			if ( in_array( $item['type'], array( Store::TYPE_UPLOAD, Store::TYPE_INSTALL ), true ) ) {
				return __( 'No malware signatures matched. Held because it is new and not approved yet.', 'wp-cyber-security' );
			}
			return __( 'No malware signatures matched. Reported because it is not part of the known files.', 'wp-cyber-security' );
		}
		$titles = array();
		foreach ( array_slice( $hits, 0, 3 ) as $hit ) {
			if ( ! is_array( $hit ) ) {
				continue;
			}
			$title = isset( $hit['title'] ) ? (string) $hit['title'] : ( isset( $hit['sig'] ) ? (string) $hit['sig'] : '' );
			if ( ! empty( $hit['line'] ) ) {
				/* translators: %d: line number */
				$title .= ' ' . sprintf( __( '(line %d)', 'wp-cyber-security' ), (int) $hit['line'] );
			}
			if ( ! empty( $hit['file'] ) ) {
				$title .= ' ' . sprintf( '[%s]', $hit['file'] );
			}
			$titles[] = $title;
		}
		$text = sprintf(
			/* translators: 1: severity, 2: number of matches, 3: list */
			_n( '%1$s - %2$d signature matched: %3$s', '%1$s - %2$d signatures matched: %3$s', count( $hits ), 'wp-cyber-security' ),
			Store::severity_label( (int) $item['severity'] ),
			count( $hits ),
			implode( '; ', $titles )
		);
		return $text;
	}

	/**
	 * @param string $source install_source value.
	 * @return string
	 */
	private function install_source_label( $source ) {
		switch ( $source ) {
			case 'wporg':
				return __( 'WordPress.org directory', 'wp-cyber-security' );
			case 'upload':
				return __( 'Uploaded ZIP file', 'wp-cyber-security' );
			default:
				return __( 'Other source (URL, command line or another plugin)', 'wp-cyber-security' );
		}
	}

	/**
	 * @param array[] $items Items.
	 * @param array   $scan  Scan summary.
	 * @return bool
	 */
	private function has_threat( array $items, array $scan ) {
		foreach ( $items as $item ) {
			if ( Store::TYPE_THREAT === $item['type'] ) {
				return true;
			}
		}
		return ! empty( $scan['threats'] );
	}

	/**
	 * Adds the footer and joins lines.
	 *
	 * @param string[] $lines     Lines.
	 * @param bool     $throttled Mention the 10 minute batching.
	 * @return string
	 */
	private function body( array $lines, $throttled = false ) {
		$lines[] = '';
		$lines[] = '-- ';
		/* translators: %s: site url */
		$lines[] = sprintf( __( 'Sent by WP Cyber Security on %s.', 'wp-cyber-security' ), home_url( '/' ) );
		if ( $throttled && 'instant' === $this->mode() ) {
			$lines[] = __( 'At most one email is sent every 10 minutes; anything that happens in between is included in the next one.', 'wp-cyber-security' );
		}
		/* translators: %s: settings url */
		$lines[] = sprintf( __( 'Change who gets these emails: %s', 'wp-cyber-security' ), admin_url( 'admin.php?page=wpcybersec-settings' ) );
		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * @param string $text Subject text.
	 * @return string
	 */
	private function subject( $text ) {
		return $this->plain( sprintf( '[%s] %s', $this->site_name(), $text ) );
	}

	/**
	 * @param string[] $to      Recipients.
	 * @param string   $subject Subject.
	 * @param string   $body    Plain-text body.
	 * @return bool
	 */
	private function mail( array $to, $subject, $body ) {
		$to = array_values( array_filter( $to, 'is_email' ) );
		if ( ! $to ) {
			return false;
		}
		try {
			return (bool) wp_mail( $to, $subject, $body, array( 'Content-Type: text/plain; charset=UTF-8' ) );
		} catch ( \Throwable $e ) {
			$this->log(
				'notify_failed',
				/* translators: %s: error message */
				sprintf( __( 'Sending a notification failed: %s', 'wp-cyber-security' ), $e->getMessage() )
			);
			return false;
		}
	}

	/**
	 * Posts {"text": "..."} to the webhook without waiting for the answer. Only
	 * https:// URLs on public hosts are used (no loopback or private addresses),
	 * because the message carries text an uploader controls (file names, URLs).
	 *
	 * @param string $text Message.
	 * @return bool|null Null without a webhook, false when the URL was refused, true when sent.
	 */
	private function webhook( $text ) {
		$url = (string) wpcybersec()->settings->get( 'webhook_url', '' );
		if ( '' === $url ) {
			return null;
		}
		if ( 0 !== strpos( $url, 'https://' ) || ! wp_http_validate_url( $url ) ) {
			return false;
		}
		$host    = (string) wp_parse_url( $url, PHP_URL_HOST );
		$payload = array( 'text' => $text );
		if ( preg_match( '/(^|\.)discord(app)?\.com$/i', $host ) && false === strpos( $url, '/slack' ) ) {
			$payload = array( 'content' => function_exists( 'mb_substr' ) ? mb_substr( $text, 0, 1900 ) : substr( $text, 0, 1900 ) );
		}
		wp_safe_remote_post(
			$url,
			array(
				'timeout'            => 3,
				'blocking'           => false,
				'redirection'        => 0,
				'reject_unsafe_urls' => true,
				'headers'            => array( 'Content-Type' => 'application/json; charset=utf-8' ),
				'body'               => wp_json_encode( $payload ),
			)
		);
		return true;
	}

	/* ------------------------------------------------------------------ */
	/* Small helpers                                                       */
	/* ------------------------------------------------------------------ */

	/**
	 * @return string instant | digest | off
	 */
	private function mode() {
		$mode = (string) wpcybersec()->settings->get( 'notify_mode', 'instant' );
		return in_array( $mode, array( 'instant', 'digest', 'off' ), true ) ? $mode : 'instant';
	}

	/**
	 * @param string $mode Mode.
	 * @return string
	 */
	private function mode_label( $mode ) {
		$labels = array(
			'instant' => __( 'Instant (at most one email every 10 minutes)', 'wp-cyber-security' ),
			'digest'  => __( 'Daily summary', 'wp-cyber-security' ),
			'off'     => __( 'Off (test emails only)', 'wp-cyber-security' ),
		);
		return isset( $labels[ $mode ] ) ? $labels[ $mode ] : $mode;
	}

	/**
	 * @return string Site name without HTML entities.
	 */
	private function site_name() {
		$name = wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES );
		return '' !== trim( $name ) ? $name : (string) wp_parse_url( home_url(), PHP_URL_HOST );
	}

	/**
	 * @param string $tab pending | threats.
	 * @return string
	 */
	private function reports_url( $tab ) {
		return admin_url( 'admin.php?page=wpcybersec-reports&tab=' . ( 'threats' === $tab ? 'threats' : 'pending' ) );
	}

	/**
	 * @param string $utc UTC datetime.
	 * @return string Site-local datetime.
	 */
	private function format_date( $utc ) {
		return get_date_from_gmt( $utc, get_option( 'date_format' ) . ' ' . get_option( 'time_format' ) );
	}

	/**
	 * Plain text: no tags, no control characters, no entities.
	 *
	 * @param string $text Text.
	 * @return string
	 */
	private function plain( $text ) {
		$text = wp_specialchars_decode( wp_strip_all_tags( (string) $text ), ENT_QUOTES );
		return trim( (string) preg_replace( '/[\x00-\x08\x0B-\x1F\x7F]+/', ' ', $text ) );
	}

	/**
	 * @param string $text Text.
	 * @return int Characters.
	 */
	private function strlen( $text ) {
		return function_exists( 'mb_strlen' ) ? mb_strlen( $text ) : strlen( $text );
	}

	/**
	 * Next 08:00 site time.
	 *
	 * @return int
	 */
	private function next_digest_time() {
		try {
			$now  = new \DateTimeImmutable( 'now', wp_timezone() );
			$when = $now->setTime( 8, 0 );
			if ( $when <= $now ) {
				$when = $when->modify( '+1 day' );
			}
			return $when->getTimestamp();
		} catch ( \Exception $e ) {
			return time() + DAY_IN_SECONDS;
		}
	}

	/**
	 * @param string $event   Event.
	 * @param string $message Message.
	 * @param array  $context Context.
	 */
	private function log( $event, $message, array $context = array() ) {
		$logger = wpcybersec()->logger;
		if ( $logger ) {
			$logger->log( $event, $message, $context );
		}
	}
}

<?php
/**
 * Database access for items, manifest and activity log.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Tables (prefix = $wpdb->prefix . 'wpcybersec_'):
 *
 * items     Everything that needs or had an admin decision: held uploads,
 *           held installs, unknown files, malware threats (files and database
 *           content), new administrator accounts.
 * manifest  Known files: relative path -> sha256, size, mtime, state.
 * allowlist Approved hashes and installs (managed by Allowlist).
 * log       Activity log.
 *
 * All datetimes are UTC ("Y-m-d H:i:s").
 */
class Store {

	/* Item types. */
	const TYPE_UPLOAD  = 'upload';
	const TYPE_INSTALL = 'install';
	const TYPE_FILE    = 'file';
	const TYPE_THREAT  = 'threat';
	const TYPE_USER    = 'user';    // An account that gained administrator rights (User_Watch).

	/* Item sources that are not files. */
	const SOURCE_DATABASE = 'database'; // Threat found in the database (Db_Scanner); path "db:option:<name>" or "db:post:<id>".

	/* Item statuses. */
	const STATUS_PENDING     = 'pending';     // Waiting for an admin decision.
	const STATUS_APPROVED    = 'approved';    // Allowed (and remembered in the allowlist).
	const STATUS_DENIED      = 'denied';      // Rejected; held copy removed.
	const STATUS_IGNORED     = 'ignored';     // Threat marked safe (hash allowlisted).
	const STATUS_QUARANTINED = 'quarantined'; // Moved to quarantine by a decision.
	const STATUS_RESTORED    = 'restored';    // Put back without trusting.
	const STATUS_DELETED     = 'deleted';     // Permanently deleted.
	const STATUS_RESOLVED    = 'resolved';    // File gone or fixed outside the plugin.

	/* Severities. */
	const SEV_INFO     = 0;
	const SEV_MEDIUM   = 1;
	const SEV_HIGH     = 2;
	const SEV_CRITICAL = 3;

	/* Manifest states. */
	const STATE_TRUSTED = 'trusted';
	const STATE_PENDING = 'pending';
	const STATE_THREAT  = 'threat';

	/**
	 * @param string $name items | manifest | allowlist | log.
	 * @return string Full table name.
	 */
	public static function table( $name ) {
		global $wpdb;
		return $wpdb->prefix . 'wpcybersec_' . $name;
	}

	/**
	 * @return string Current UTC datetime.
	 */
	public static function now() {
		return gmdate( 'Y-m-d H:i:s' );
	}

	/**
	 * Severity number to label.
	 *
	 * @param int $severity Severity.
	 * @return string
	 */
	public static function severity_label( $severity ) {
		$labels = array(
			self::SEV_INFO     => __( 'Info', 'cybergate-security' ),
			self::SEV_MEDIUM   => __( 'Medium', 'cybergate-security' ),
			self::SEV_HIGH     => __( 'High', 'cybergate-security' ),
			self::SEV_CRITICAL => __( 'Critical', 'cybergate-security' ),
		);
		return isset( $labels[ (int) $severity ] ) ? $labels[ (int) $severity ] : $labels[0];
	}

	/**
	 * Makes text safe for a utf8mb4 column. File names come straight from
	 * readdir() and may hold bytes that are not valid UTF-8 (Latin-1 legacy
	 * uploads, or a webshell named "x\xff.php" on purpose). wpdb refuses a whole
	 * query that contains such bytes, so every invalid byte becomes "?".
	 *
	 * @param string $text Raw text.
	 * @return string Valid UTF-8 (unchanged when it already was).
	 */
	public static function db_text( $text ) {
		$text = (string) $text;
		if ( '' === $text || 1 === @preg_match( '//u', $text ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return $text;
		}
		$out = preg_replace_callback(
			'/[\x00-\x7F]+|[\xC2-\xDF][\x80-\xBF]|\xE0[\xA0-\xBF][\x80-\xBF]|[\xE1-\xEC\xEE\xEF][\x80-\xBF]{2}|\xED[\x80-\x9F][\x80-\xBF]|\xF0[\x90-\xBF][\x80-\xBF]{2}|[\xF1-\xF3][\x80-\xBF]{3}|\xF4[\x80-\x8F][\x80-\xBF]{2}|(.)/s',
			static function ( $m ) {
				return isset( $m[1] ) ? '?' : $m[0];
			},
			$text
		);
		return is_string( $out ) ? $out : (string) preg_replace( '/[\x80-\xFF]/', '?', $text );
	}

	/* ------------------------------------------------------------------ */
	/* Items                                                               */
	/* ------------------------------------------------------------------ */

	/**
	 * @param array $data Columns. details may be an array (stored as JSON).
	 * @return int New id, 0 on failure.
	 */
	public function item_insert( array $data ) {
		global $wpdb;
		$now  = self::now();
		$row  = array_merge(
			array(
				'type'            => self::TYPE_FILE,
				'status'          => self::STATUS_PENDING,
				'severity'        => 0,
				'path'            => '',
				'original_path'   => '',
				'quarantine_path' => '',
				'sha256'          => '',
				'size'            => 0,
				'mime'            => '',
				'source'          => '',
				'user_id'         => get_current_user_id(),
				'ip'              => self::client_ip(),
				'details'         => array(),
				'created_at'      => $now,
				'updated_at'      => $now,
				'decided_by'      => 0,
			),
			$data
		);
		if ( ! is_array( $row['details'] ) ) {
			$row['details'] = array();
		}
		// Keep the exact bytes of a path that is not valid UTF-8 (base64) so the
		// file can still be found, restored or deleted; the columns get a safe copy.
		foreach ( array( 'path', 'original_path', 'quarantine_path' ) as $col ) {
			$safe = self::db_text( $row[ $col ] );
			if ( $safe !== (string) $row[ $col ] ) {
				if ( 'original_path' === $col ) {
					$row['details']['raw_path'] = base64_encode( (string) $row[ $col ] ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
				} elseif ( 'quarantine_path' === $col ) {
					$row['details']['raw_quarantine_path'] = base64_encode( (string) $row[ $col ] ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
				}
				$row[ $col ] = $safe;
			}
		}
		$row['details'] = wp_json_encode( $row['details'] );
		$ok             = $wpdb->insert( self::table( 'items' ), $row ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		return $ok ? (int) $wpdb->insert_id : 0;
	}

	/**
	 * @param int $id Item id.
	 * @return array|null Row with details decoded.
	 */
	public function item_get( $id ) {
		global $wpdb;
		$row = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . self::table( 'items' ) . ' WHERE id = %d', $id ), ARRAY_A ); // phpcs:ignore
		return $row ? self::decode_item( $row ) : null;
	}

	/**
	 * @param int   $id   Item id.
	 * @param array $data Columns to change. details arrays are merged into the existing details.
	 * @return bool
	 */
	public function item_update( $id, array $data ) {
		global $wpdb;
		if ( isset( $data['details'] ) && is_array( $data['details'] ) ) {
			$current         = $this->item_get( $id );
			$data['details'] = wp_json_encode( array_merge( $current ? $current['details'] : array(), $data['details'] ) );
		}
		$data['updated_at'] = self::now();
		return false !== $wpdb->update( self::table( 'items' ), $data, array( 'id' => (int) $id ) ); // phpcs:ignore
	}

	/**
	 * Lists items.
	 *
	 * @param array $args {
	 *     @type string|string[] $type      Item type(s).
	 *     @type string|string[] $status    Status(es).
	 *     @type bool            $held      Only items with a quarantine copy.
	 *     @type int             $min_severity Minimum severity.
	 *     @type string          $search    Matches path or sha256.
	 *     @type string          $orderby   id | created_at | severity | size | path. Default created_at.
	 *     @type string          $order     ASC | DESC. Default DESC.
	 *     @type int             $per_page  Default 20.
	 *     @type int             $page      1-based. Default 1.
	 * }
	 * @return array { rows: array[], total: int }
	 */
	public function items_query( array $args = array() ) {
		global $wpdb;
		$args = array_merge(
			array(
				'type'         => '',
				'status'       => '',
				'held'         => false,
				'min_severity' => 0,
				'search'       => '',
				'orderby'      => 'created_at',
				'order'        => 'DESC',
				'per_page'     => 20,
				'page'         => 1,
			),
			$args
		);

		list( $where, $params ) = $this->items_where( $args );
		$orderby                = in_array( $args['orderby'], array( 'id', 'created_at', 'severity', 'size', 'path', 'updated_at' ), true ) ? $args['orderby'] : 'created_at';
		$order                  = 'ASC' === strtoupper( $args['order'] ) ? 'ASC' : 'DESC';
		$per_page               = max( 1, (int) $args['per_page'] );
		$offset                 = max( 0, ( (int) $args['page'] - 1 ) * $per_page );
		$table                  = self::table( 'items' );

		$count_sql = "SELECT COUNT(*) FROM {$table} WHERE {$where}";
		$rows_sql  = "SELECT * FROM {$table} WHERE {$where} ORDER BY {$orderby} {$order}, id DESC LIMIT %d OFFSET %d";

		// phpcs:disable WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- $table is Store::table(): $wpdb->prefix plus a fixed name; $where holds only fixed conditions with placeholders, ORDER BY is allowlisted.
		$total = (int) ( $params ? $wpdb->get_var( $wpdb->prepare( $count_sql, $params ) ) : $wpdb->get_var( $count_sql ) );
		$rows  = $wpdb->get_results( $wpdb->prepare( $rows_sql, array_merge( $params, array( $per_page, $offset ) ) ), ARRAY_A );
		// phpcs:enable

		return array(
			'rows'  => array_map( array( __CLASS__, 'decode_item' ), $rows ? $rows : array() ),
			'total' => $total,
		);
	}

	/**
	 * @param array $args Same filters as items_query().
	 * @return int
	 */
	public function items_count( array $args = array() ) {
		global $wpdb;
		list( $where, $params ) = $this->items_where(
			array_merge(
				array(
					'type'         => '',
					'status'       => '',
					'held'         => false,
					'min_severity' => 0,
					'search'       => '',
				),
				$args
			)
		);
		$sql = 'SELECT COUNT(*) FROM ' . self::table( 'items' ) . " WHERE {$where}";
		return (int) ( $params ? $wpdb->get_var( $wpdb->prepare( $sql, $params ) ) : $wpdb->get_var( $sql ) ); // phpcs:ignore
	}

	/**
	 * Counts used for menu badges and dashboard cards.
	 *
	 * @return array { pending: int (uploads+installs+files+new administrators), threats: int (files and database), quarantined: int }
	 */
	public function counts() {
		return array(
			'pending'     => $this->items_count(
				array(
					'type'   => array( self::TYPE_UPLOAD, self::TYPE_INSTALL, self::TYPE_FILE, self::TYPE_USER ),
					'status' => self::STATUS_PENDING,
				)
			),
			'threats'     => $this->items_count(
				array(
					'type'   => self::TYPE_THREAT,
					'status' => self::STATUS_PENDING,
				)
			),
			'quarantined' => $this->items_count(
				array(
					'held'   => true,
					'status' => array( self::STATUS_PENDING, self::STATUS_QUARANTINED ),
				)
			),
		);
	}

	/**
	 * Finds an open (pending) item for the same thing, to avoid duplicates.
	 *
	 * @param string $type   Item type.
	 * @param string $path   Path (relative path, file name or install key).
	 * @param string $sha256 Optional hash; when given it must match too.
	 * @return array|null
	 */
	public function item_find_open( $type, $path, $sha256 = '' ) {
		global $wpdb;
		$table = self::table( 'items' );
		$path  = self::db_text( $path ); // Same form item_insert() stored.
		if ( $sha256 ) {
			$sql = $wpdb->prepare( "SELECT * FROM {$table} WHERE type = %s AND status = %s AND path = %s AND sha256 = %s ORDER BY id DESC LIMIT 1", $type, self::STATUS_PENDING, $path, $sha256 ); // phpcs:ignore
		} else {
			$sql = $wpdb->prepare( "SELECT * FROM {$table} WHERE type = %s AND status = %s AND path = %s ORDER BY id DESC LIMIT 1", $type, self::STATUS_PENDING, $path ); // phpcs:ignore
		}
		$row = $wpdb->get_row( $sql, ARRAY_A ); // phpcs:ignore
		return $row ? self::decode_item( $row ) : null;
	}

	/**
	 * Closes open file/threat items for a path that no longer need a decision
	 * (the file is now verified original or approved elsewhere, or it is gone).
	 * Items with a held quarantine copy are left alone: their original being
	 * gone is expected.
	 *
	 * @param string $rel    Relative path.
	 * @param string $reason now_trusted | file_gone.
	 * @return int Items closed.
	 */
	public function items_resolve_open( $rel, $reason ) {
		global $wpdb;
		$table = self::table( 'items' );
		$ids   = $wpdb->get_col( $wpdb->prepare( "SELECT id FROM {$table} WHERE type IN (%s, %s) AND status = %s AND path = %s AND quarantine_path = '' AND source <> %s", self::TYPE_FILE, self::TYPE_THREAT, self::STATUS_PENDING, self::db_text( $rel ), self::SOURCE_DATABASE ) ); // phpcs:ignore
		foreach ( (array) $ids as $id ) {
			$this->item_update(
				(int) $id,
				array(
					'status'     => self::STATUS_RESOLVED,
					'decided_at' => self::now(),
					'details'    => array( 'resolution' => $reason ),
				)
			);
		}
		if ( $ids ) {
			$message = 'file_gone' === $reason
				/* translators: %s: file path */
				? sprintf( __( 'Closed the report for %s: the file no longer exists.', 'cybergate-security' ), $rel )
				/* translators: %s: file path */
				: sprintf( __( 'Closed the report for %s: the file now matches its official checksum or an approved fingerprint.', 'cybergate-security' ), $rel );
			$this->log_insert( 'item_auto_resolved', $message, array( 'ids' => array_map( 'intval', $ids ) ) );
		}
		return count( (array) $ids );
	}

	/**
	 * @param int[] $ids Ids.
	 * @return int Rows deleted.
	 */
	public function items_delete( array $ids ) {
		global $wpdb;
		$ids = array_filter( array_map( 'intval', $ids ) );
		if ( ! $ids ) {
			return 0;
		}
		return (int) $wpdb->query( 'DELETE FROM ' . self::table( 'items' ) . ' WHERE id IN (' . implode( ',', $ids ) . ')' ); // phpcs:ignore
	}

	/**
	 * @param array $args Filters.
	 * @return array [ where sql, params ]
	 */
	private function items_where( array $args ) {
		global $wpdb;
		$where  = array( '1=1' );
		$params = array();

		foreach ( array( 'type', 'status' ) as $col ) {
			$values = array_filter( (array) $args[ $col ], 'strlen' );
			if ( $values ) {
				$where[] = $col . ' IN (' . implode( ',', array_fill( 0, count( $values ), '%s' ) ) . ')';
				$params  = array_merge( $params, array_values( $values ) );
			}
		}
		if ( ! empty( $args['held'] ) ) {
			$where[] = "quarantine_path <> ''";
		}
		if ( ! empty( $args['min_severity'] ) ) {
			$where[]  = 'severity >= %d';
			$params[] = (int) $args['min_severity'];
		}
		if ( '' !== (string) $args['search'] ) {
			$like     = '%' . $wpdb->esc_like( $args['search'] ) . '%';
			$where[]  = '(path LIKE %s OR sha256 LIKE %s)';
			$params[] = $like;
			$params[] = $like;
		}
		return array( implode( ' AND ', $where ), $params );
	}

	/**
	 * @param array $row Raw row.
	 * @return array
	 */
	public static function decode_item( $row ) {
		$details        = json_decode( (string) $row['details'], true );
		$row['details'] = is_array( $details ) ? $details : array();
		foreach ( array( 'id', 'severity', 'size', 'user_id', 'decided_by' ) as $int ) {
			$row[ $int ] = (int) $row[ $int ];
		}
		return $row;
	}

	/* ------------------------------------------------------------------ */
	/* Manifest                                                            */
	/* ------------------------------------------------------------------ */

	/**
	 * @param string[] $path_hashes Paths::hash() values.
	 * @return array path_hash => row
	 */
	public function manifest_get_many( array $path_hashes ) {
		global $wpdb;
		$path_hashes = array_values( array_unique( array_filter( $path_hashes ) ) );
		$out         = array();
		foreach ( array_chunk( $path_hashes, 500 ) as $chunk ) {
			$sql  = 'SELECT * FROM ' . self::table( 'manifest' ) . ' WHERE path_hash IN (' . implode( ',', array_fill( 0, count( $chunk ), '%s' ) ) . ')';
			$rows = $wpdb->get_results( $wpdb->prepare( $sql, $chunk ), ARRAY_A ); // phpcs:ignore
			foreach ( (array) $rows as $row ) {
				$out[ $row['path_hash'] ] = $row;
			}
		}
		return $out;
	}

	/**
	 * @param string $rel Relative path.
	 * @return array|null
	 */
	public function manifest_get( $rel ) {
		$rows = $this->manifest_get_many( array( Paths::hash( $rel ) ) );
		return $rows ? reset( $rows ) : null;
	}

	/**
	 * Inserts or replaces manifest rows.
	 *
	 * path_hash is computed from the exact path bytes (that is how rows are
	 * looked up); the path column gets a UTF-8 safe copy for display and
	 * prefix queries. When a batch statement fails, the rows are written one by
	 * one so a single bad row can never drop the others.
	 *
	 * @param array $rows Each: path (relative), sha256, size, mtime, state, run_id. path_hash is computed.
	 */
	public function manifest_upsert_many( array $rows ) {
		$now = self::now();
		foreach ( array_chunk( $rows, 200 ) as $chunk ) {
			if ( false === $this->manifest_upsert_chunk( $chunk, $now ) && count( $chunk ) > 1 ) {
				foreach ( $chunk as $row ) {
					$this->manifest_upsert_chunk( array( $row ), $now );
				}
			}
		}
	}

	/**
	 * One INSERT ... ON DUPLICATE KEY UPDATE statement.
	 *
	 * @param array  $chunk Rows (at most 200).
	 * @param string $now   Datetime.
	 * @return int|false Rows affected, false on a database error.
	 */
	private function manifest_upsert_chunk( array $chunk, $now ) {
		global $wpdb;
		$values = array();
		$params = array();
		foreach ( $chunk as $row ) {
			$values[] = '(%s,%s,%s,%d,%d,%s,%s,%s)';
			array_push(
				$params,
				Paths::hash( $row['path'] ),
				self::db_text( $row['path'] ),
				isset( $row['sha256'] ) ? (string) $row['sha256'] : '',
				isset( $row['size'] ) ? (int) $row['size'] : 0,
				isset( $row['mtime'] ) ? (int) $row['mtime'] : 0,
				isset( $row['state'] ) ? (string) $row['state'] : self::STATE_TRUSTED,
				isset( $row['run_id'] ) ? (string) $row['run_id'] : '',
				$now
			);
		}
		if ( ! $values ) {
			return 0;
		}
		$sql = 'INSERT INTO ' . self::table( 'manifest' ) . ' (path_hash, path, sha256, size, mtime, state, run_id, updated_at) VALUES ' . implode( ',', $values )
			. ' ON DUPLICATE KEY UPDATE path = VALUES(path), sha256 = VALUES(sha256), size = VALUES(size), mtime = VALUES(mtime), state = VALUES(state), run_id = VALUES(run_id), updated_at = VALUES(updated_at)';
		return $wpdb->query( $wpdb->prepare( $sql, $params ) ); // phpcs:ignore
	}

	/**
	 * Marks rows as seen by a scan run.
	 *
	 * @param string[] $path_hashes Hashes.
	 * @param string   $run_id      Run id.
	 */
	public function manifest_touch( array $path_hashes, $run_id ) {
		global $wpdb;
		foreach ( array_chunk( array_values( array_unique( $path_hashes ) ), 500 ) as $chunk ) {
			$sql = 'UPDATE ' . self::table( 'manifest' ) . ' SET run_id = %s WHERE path_hash IN (' . implode( ',', array_fill( 0, count( $chunk ), '%s' ) ) . ')';
			$wpdb->query( $wpdb->prepare( $sql, array_merge( array( $run_id ), $chunk ) ) ); // phpcs:ignore
		}
	}

	/**
	 * Rows not seen by a run (deleted files), optionally under a path prefix.
	 *
	 * Rows written after the run started (by trust_file(), a rebaseline after an
	 * update, an approved upload...) are never returned when $before is given:
	 * they describe files that exist even though this run did not list them.
	 *
	 * @param string $run_id Run id.
	 * @param int    $limit  Max rows.
	 * @param string $prefix Relative path prefix ("" for all).
	 * @param string $before Only rows last written before this UTC datetime ("Y-m-d H:i:s"; "" for no limit).
	 * @return array[]
	 */
	public function manifest_unseen( $run_id, $limit = 500, $prefix = '', $before = '' ) {
		global $wpdb;
		$table  = self::table( 'manifest' );
		$where  = 'run_id <> %s';
		$params = array( (string) $run_id );
		if ( '' !== (string) $prefix ) {
			$where   .= ' AND path LIKE %s';
			$params[] = $wpdb->esc_like( self::db_text( $prefix ) ) . '%';
		}
		if ( '' !== (string) $before ) {
			$where   .= ' AND updated_at < %s';
			$params[] = (string) $before;
		}
		$params[] = (int) $limit;
		$sql      = $wpdb->prepare( "SELECT * FROM {$table} WHERE {$where} LIMIT %d", $params ); // phpcs:ignore
		return (array) $wpdb->get_results( $sql, ARRAY_A ); // phpcs:ignore
	}

	/**
	 * @param string[] $path_hashes Hashes.
	 */
	public function manifest_delete( array $path_hashes ) {
		global $wpdb;
		foreach ( array_chunk( array_values( array_unique( array_filter( $path_hashes ) ) ), 500 ) as $chunk ) {
			$sql = 'DELETE FROM ' . self::table( 'manifest' ) . ' WHERE path_hash IN (' . implode( ',', array_fill( 0, count( $chunk ), '%s' ) ) . ')';
			$wpdb->query( $wpdb->prepare( $sql, $chunk ) ); // phpcs:ignore
		}
	}

	/**
	 * @param string $prefix Relative path prefix.
	 */
	public function manifest_delete_prefix( $prefix ) {
		global $wpdb;
		$wpdb->query( $wpdb->prepare( 'DELETE FROM ' . self::table( 'manifest' ) . ' WHERE path LIKE %s', $wpdb->esc_like( self::db_text( $prefix ) ) . '%' ) ); // phpcs:ignore
	}

	/**
	 * @param string $state Optional state filter.
	 * @return int
	 */
	public function manifest_count( $state = '' ) {
		global $wpdb;
		$table = self::table( 'manifest' );
		if ( $state ) {
			return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE state = %s", $state ) ); // phpcs:ignore
		}
		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" ); // phpcs:ignore
	}

	/**
	 * @param string $rel   Relative path.
	 * @param string $state New state.
	 */
	public function manifest_set_state( $rel, $state ) {
		global $wpdb;
		$wpdb->update( self::table( 'manifest' ), array( 'state' => $state, 'updated_at' => self::now() ), array( 'path_hash' => Paths::hash( $rel ) ) ); // phpcs:ignore
	}

	/**
	 * Empties the manifest (before a full re-baseline).
	 */
	public function manifest_truncate() {
		global $wpdb;
		$wpdb->query( 'TRUNCATE TABLE ' . self::table( 'manifest' ) ); // phpcs:ignore
	}

	/**
	 * Every trusted row, in pages (for exports such as the fapolicyd trust file).
	 *
	 * @param int $limit  Rows.
	 * @param int $offset Offset.
	 * @return array[]
	 */
	public function manifest_page( $limit, $offset ) {
		global $wpdb;
		return (array) $wpdb->get_results( $wpdb->prepare( 'SELECT path, sha256, size FROM ' . self::table( 'manifest' ) . ' WHERE state = %s ORDER BY path LIMIT %d OFFSET %d', self::STATE_TRUSTED, $limit, $offset ), ARRAY_A ); // phpcs:ignore
	}

	/* ------------------------------------------------------------------ */
	/* Log                                                                 */
	/* ------------------------------------------------------------------ */

	/**
	 * @param string $event   Machine name, e.g. upload_held.
	 * @param string $message Human message.
	 * @param array  $context Extra data.
	 * @return int
	 */
	public function log_insert( $event, $message, array $context = array() ) {
		global $wpdb;
		$wpdb->insert( // phpcs:ignore
			self::table( 'log' ),
			array(
				'event'      => substr( (string) $event, 0, 50 ),
				'message'    => self::db_text( $message ), // Messages often quote file names.
				'context'    => wp_json_encode( $context ),
				'user_id'    => get_current_user_id(),
				'ip'         => self::client_ip(),
				'created_at' => self::now(),
			)
		);
		return (int) $wpdb->insert_id;
	}

	/**
	 * @param array $args { event, search, per_page (50), page (1) }.
	 * @return array { rows, total }
	 */
	public function log_query( array $args = array() ) {
		global $wpdb;
		$args   = array_merge( array( 'event' => '', 'search' => '', 'per_page' => 50, 'page' => 1 ), $args );
		$table  = self::table( 'log' );
		$where  = array( '1=1' );
		$params = array();
		if ( $args['event'] ) {
			$where[]  = 'event = %s';
			$params[] = $args['event'];
		}
		if ( $args['search'] ) {
			$where[]  = 'message LIKE %s';
			$params[] = '%' . $wpdb->esc_like( $args['search'] ) . '%';
		}
		$where    = implode( ' AND ', $where );
		$per_page = max( 1, (int) $args['per_page'] );
		$offset   = max( 0, ( (int) $args['page'] - 1 ) * $per_page );
		// phpcs:disable WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- $table is Store::table(): $wpdb->prefix plus a fixed name; $where holds only fixed conditions with placeholders.
		$total = (int) ( $params ? $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE {$where}", $params ) ) : $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" ) );
		$rows  = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table} WHERE {$where} ORDER BY id DESC LIMIT %d OFFSET %d", array_merge( $params, array( $per_page, $offset ) ) ), ARRAY_A );
		// phpcs:enable
		foreach ( $rows as &$row ) {
			$context        = json_decode( (string) $row['context'], true );
			$row['context'] = is_array( $context ) ? $context : array();
		}
		return array(
			'rows'  => $rows,
			'total' => $total,
		);
	}

	/**
	 * Distinct event names (for the Activity filter).
	 *
	 * @return string[]
	 */
	public function log_events() {
		global $wpdb;
		return (array) $wpdb->get_col( 'SELECT DISTINCT event FROM ' . self::table( 'log' ) . ' ORDER BY event LIMIT 200' ); // phpcs:ignore
	}

	/**
	 * @param int $days Keep this many days.
	 */
	public function log_prune( $days ) {
		global $wpdb;
		$cutoff = gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS * (int) $days );
		$wpdb->query( $wpdb->prepare( 'DELETE FROM ' . self::table( 'log' ) . ' WHERE created_at < %s', $cutoff ) ); // phpcs:ignore
	}

	/* ------------------------------------------------------------------ */
	/* Helpers                                                             */
	/* ------------------------------------------------------------------ */

	/**
	 * Best-effort client IP (REMOTE_ADDR only; proxies headers are spoofable).
	 *
	 * @return string
	 */
	public static function client_ip() {
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '';
	}
}

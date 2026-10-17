<?php
/**
 * Admin decisions on items: approve, deny, ignore, quarantine, restore, delete.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Single entry point for every decision, used by the reports page, AJAX,
 * bulk actions and WP-CLI. Type specific work is delegated:
 *   upload  -> Upload_Gate::on_approve( $item ) / on_deny( $item )
 *   install -> Install_Gate::on_approve( $item ) / on_deny( $item )
 *   file    -> handled here + File_Monitor::trust_file() / forget_file()
 *   threat  -> handled here + File_Monitor::trust_file() / forget_file()
 *   threat with source "database" (Db_Scanner) -> only "ignore" (Mark safe:
 *              the fingerprint goes on the allowlist as kind db); never touches files
 *   user    -> User_Watch::approve_item() (trust the administrator) /
 *              deny_item() (remove the administrator role, sign the account out)
 */
class Decisions {

	const ACTIONS = array( 'approve', 'deny', 'ignore', 'quarantine', 'restore', 'delete', 'restore_official' );

	/**
	 * Files in the WordPress folder that the site cannot start without. They
	 * are never quarantined or deleted, whatever the settings or a bulk action
	 * say: moving one away takes the whole site down (including this screen).
	 */
	const CRITICAL_ROOT = array( 'wp-config.php', 'wp-load.php', 'wp-settings.php', 'wp-blog-header.php', 'index.php', '.htaccess' );

	/** @var array<string,bool> is_critical_path() results for this request. */
	private static $critical = array();

	/**
	 * Whether a file is critical: wp-config.php (also one folder up), the root
	 * bootstrap files listed in CRITICAL_ROOT, or a file in wp-admin/ or
	 * wp-includes/ that is part of the installed WordPress release (verified
	 * against the official core checksums; without them nothing there counts).
	 *
	 * @param string $abs Absolute path.
	 * @return bool
	 */
	public static function is_critical_path( $abs ) {
		$abs = wp_normalize_path( (string) $abs );
		if ( '' === $abs ) {
			return false;
		}
		if ( isset( self::$critical[ $abs ] ) ) {
			return self::$critical[ $abs ];
		}
		$result = false;
		$config = Config_Editor::path();
		$root   = trailingslashit( wp_normalize_path( ABSPATH ) );
		if ( '' !== $config && $config === $abs ) {
			$result = true;
		} elseif ( 0 === strpos( $abs, $root ) ) {
			$rel = substr( $abs, strlen( $root ) );
			if ( in_array( $rel, self::CRITICAL_ROOT, true ) ) {
				$result = true;
			} elseif ( preg_match( '~^wp-(?:admin|includes)/~', $rel ) ) {
				$scanner = function_exists( 'wpcybersec' ) ? wpcybersec()->scanner : null;
				$map     = ( $scanner && method_exists( $scanner, 'core_map' ) ) ? $scanner->core_map() : false;
				$result  = is_array( $map ) && isset( $map[ $rel ] );
			}
		}
		self::$critical[ $abs ] = $result;
		return $result;
	}

	/**
	 * Whether an item is about a critical file (see is_critical_path()).
	 *
	 * @param array $item Item row.
	 * @return bool
	 */
	public static function is_critical( array $item ) {
		if ( ! in_array( $item['type'], array( Store::TYPE_FILE, Store::TYPE_THREAT ), true ) || Db_Scanner::is_db_item( $item ) ) {
			return false;
		}
		return self::is_critical_path( self::item_abs( $item ) );
	}

	/**
	 * Absolute path of a file item (where it lives, or lived before quarantine).
	 *
	 * @param array $item Item row.
	 * @return string
	 */
	private static function item_abs( array $item ) {
		return wp_normalize_path( (string) ( ! empty( $item['original_path'] ) ? $item['original_path'] : Paths::abs( (string) $item['path'] ) ) );
	}

	/**
	 * Where the official copy of a critical core file comes from, when the
	 * live file differs from it and can be replaced by it.
	 *
	 * @param array $item Item row.
	 * @return array|null Originals::locate() result.
	 */
	public static function official_source( array $item ) {
		if ( '' !== (string) $item['quarantine_path'] || ! self::is_critical( $item ) || ! class_exists( __NAMESPACE__ . '\\Originals' ) ) {
			return null;
		}
		$abs = self::item_abs( $item );
		if ( ! @is_file( $abs ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return null;
		}
		$loc = ( new Originals() )->locate( (string) $item['path'] );
		// Localized WordPress builds set $wp_local_package in version.php: never swap it for the English copy.
		if ( ! is_array( $loc ) || 'core' !== $loc['source'] || '' === $loc['md5'] || 'wp-includes/version.php' === $loc['path'] ) {
			return null;
		}
		$md5 = (string) @md5_file( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		return ( '' !== $md5 && ! hash_equals( $loc['md5'], $md5 ) ) ? $loc : null;
	}

	/**
	 * Which actions make sense for an item right now.
	 *
	 * @param array $item Item row.
	 * @return string[]
	 */
	public static function available( array $item ) {
		$actions = self::available_raw( $item );
		if ( $actions && self::is_critical( $item ) ) {
			// Never move or delete a file the site needs to start.
			$actions = array_values( array_diff( $actions, array( 'quarantine', 'delete', 'deny' ) ) );
			$held    = '' !== (string) $item['quarantine_path'];
			if ( $held && ! in_array( 'restore', $actions, true ) && in_array( $item['status'], array( Store::STATUS_PENDING, Store::STATUS_QUARANTINED ), true ) ) {
				$actions[] = 'restore'; // Already held (older rule or settings): it must be possible to put it back.
			}
			if ( in_array( $item['status'], array( Store::STATUS_PENDING, Store::STATUS_RESTORED ), true ) && self::official_source( $item ) ) {
				$actions[] = 'restore_official';
			}
		}
		return $actions;
	}

	/**
	 * Actions by type and status, before the critical file rule.
	 *
	 * @param array $item Item row.
	 * @return string[]
	 */
	private static function available_raw( array $item ) {
		$held = '' !== (string) $item['quarantine_path'];
		// Not files: no quarantine, restore or delete, and nothing after the decision.
		if ( Store::TYPE_USER === $item['type'] ) {
			return Store::STATUS_PENDING === $item['status'] ? array( 'approve', 'deny' ) : array();
		}
		if ( Db_Scanner::is_db_item( $item ) ) {
			return Store::STATUS_PENDING === $item['status'] ? array( 'ignore' ) : array();
		}
		switch ( $item['status'] ) {
			case Store::STATUS_PENDING:
				if ( Store::TYPE_THREAT === $item['type'] ) {
					return $held ? array( 'ignore', 'restore', 'delete' ) : array( 'ignore', 'quarantine', 'delete' );
				}
				if ( Store::TYPE_FILE === $item['type'] ) {
					return $held ? array( 'approve', 'delete' ) : array( 'approve', 'quarantine', 'delete' );
				}
				return array( 'approve', 'deny' );
			case Store::STATUS_QUARANTINED:
				return array( 'approve', 'restore', 'delete' );
			case Store::STATUS_RESTORED:
				return array( 'approve', 'quarantine' );
			default:
				return array();
		}
	}

	/**
	 * Applies an action to one item.
	 *
	 * @param string $action One of self::ACTIONS.
	 * @param int    $id     Item id.
	 * @return true|\WP_Error
	 */
	public function apply( $action, $id ) {
		$store = wpcybersec()->store;
		$item  = $store->item_get( (int) $id );
		if ( ! $item ) {
			return new \WP_Error( 'wpcybersec_item', __( 'Item not found.', 'cybergate-security' ) );
		}
		if ( ! in_array( $action, self::available( $item ), true ) ) {
			if ( Store::STATUS_PENDING === $item['status'] && Db_Scanner::is_db_item( $item ) ) {
				return new \WP_Error( 'wpcybersec_action', __( 'This finding is stored in the database, not in a file. Clean it where it is stored (the post or widget), or use Mark safe.', 'cybergate-security' ) );
			}
			if ( Store::STATUS_PENDING === $item['status'] && Store::TYPE_USER === $item['type'] ) {
				return new \WP_Error( 'wpcybersec_action', __( 'For an administrator account, use Allow or Remove admin role.', 'cybergate-security' ) );
			}
			if ( in_array( $action, array( 'quarantine', 'delete', 'deny' ), true ) && self::is_critical( $item ) ) {
				/* translators: %s: file path */
				return new \WP_Error( 'wpcybersec_critical', sprintf( __( '%s is a critical file: it cannot be quarantined or deleted. If you did not make this change, restore it from a backup or the official copy.', 'cybergate-security' ), (string) $item['path'] ) );
			}
			if ( 'restore_official' === $action ) {
				return new \WP_Error( 'wpcybersec_action', __( 'The official copy is only offered for a changed WordPress core file that is still in place.', 'cybergate-security' ) );
			}
			/* translators: 1: action, 2: status */
			return new \WP_Error( 'wpcybersec_action', sprintf( __( 'Cannot %1$s an item that is %2$s.', 'cybergate-security' ), $action, $item['status'] ) );
		}

		switch ( $action ) {
			case 'approve':
				$result = $this->approve( $item );
				break;
			case 'deny':
				$result = $this->deny( $item );
				break;
			case 'ignore':
				$result = $this->ignore( $item );
				break;
			case 'quarantine':
				$result = $this->quarantine( $item );
				break;
			case 'restore':
				$result = $this->restore( $item );
				break;
			case 'delete':
				$result = $this->delete( $item );
				break;
			case 'restore_official':
				$result = $this->restore_official( $item );
				break;
			default:
				$result = new \WP_Error( 'wpcybersec_action', __( 'Unknown action.', 'cybergate-security' ) );
		}

		if ( is_wp_error( $result ) ) {
			wpcybersec()->logger->log(
				'decision_failed',
				/* translators: 1: action, 2: path, 3: error */
				sprintf( __( 'Could not %1$s %2$s: %3$s', 'cybergate-security' ), $action, self::label_for( $item ), $result->get_error_message() ),
				array( 'item_id' => $item['id'] )
			);
			return $result;
		}

		/**
		 * Fires after a decision was applied.
		 *
		 * @param string $action Action.
		 * @param array  $item   Item before the change.
		 */
		do_action( 'wpcybersec_decision', $action, $item );
		return true;
	}

	/**
	 * @param string $action Action.
	 * @param int[]  $ids    Ids.
	 * @return array { done: int, errors: string[] }
	 */
	public function bulk( $action, array $ids ) {
		$done   = 0;
		$errors = array();
		foreach ( $ids as $id ) {
			$result = $this->apply( $action, (int) $id );
			if ( is_wp_error( $result ) ) {
				$errors[] = '#' . (int) $id . ': ' . $result->get_error_message();
			} else {
				++$done;
			}
		}
		return array(
			'done'   => $done,
			'errors' => $errors,
		);
	}

	/* ------------------------------------------------------------------ */

	/**
	 * @param array $item Item.
	 * @return true|\WP_Error
	 */
	private function approve( array $item ) {
		$plugin = wpcybersec();

		if ( Store::TYPE_USER === $item['type'] ) {
			$result = $plugin->user_watch ? $plugin->user_watch->approve_item( $item ) : new \WP_Error( 'wpcybersec_module', __( 'The administrator watch is not available.', 'cybergate-security' ) );
			if ( is_wp_error( $result ) ) {
				if ( 'wpcybersec_user_gone' === $result->get_error_code() ) {
					/* translators: %s: user name of the administrator account */
					return $this->finish( $item, Store::STATUS_RESOLVED, 'admin_gone', __( 'Closed the report for %s: the account no longer exists.', 'cybergate-security' ) );
				}
				return $result;
			}
			/* translators: %s: user name of the administrator account */
			return $this->finish( $item, Store::STATUS_APPROVED, 'admin_approved', __( 'Allowed administrator %s. The account is trusted from now on.', 'cybergate-security' ) );
		}

		if ( Store::TYPE_UPLOAD === $item['type'] ) {
			$result = $plugin->upload_gate->on_approve( $item );
			if ( is_wp_error( $result ) ) {
				return $result;
			}
			/* translators: %s: file name of the upload */
			return $this->finish( $item, Store::STATUS_APPROVED, 'upload_approved', __( 'Approved upload %s. Identical files will pass automatically from now on.', 'cybergate-security' ), array( 'quarantine_path' => '' ) );
		}

		if ( Store::TYPE_INSTALL === $item['type'] ) {
			$result = $plugin->install_gate->on_approve( $item );
			if ( is_wp_error( $result ) ) {
				return $result;
			}
			/* translators: %s: name of the plugin or theme */
			return $this->finish( $item, Store::STATUS_APPROVED, 'install_approved', __( 'Approved install %s. It can now be installed and will not be held again.', 'cybergate-security' ), array( 'quarantine_path' => '' ) );
		}

		// File (or quarantined threat): put it back if held, then trust it.
		if ( '' !== (string) $item['quarantine_path'] ) {
			$restored = $plugin->quarantine->restore( $item );
			if ( is_wp_error( $restored ) ) {
				return $restored;
			}
		}
		$this->trust( $item );
		/* translators: %s: file path or name of the item */
		return $this->finish( $item, Store::STATUS_APPROVED, 'file_approved', __( 'Approved file %s. It will not be reported again unless its content changes.', 'cybergate-security' ), array( 'quarantine_path' => '' ) );
	}

	/**
	 * @param array $item Item.
	 * @return true|\WP_Error
	 */
	private function deny( array $item ) {
		$plugin = wpcybersec();
		if ( Store::TYPE_USER === $item['type'] ) {
			$result = $plugin->user_watch ? $plugin->user_watch->deny_item( $item ) : new \WP_Error( 'wpcybersec_module', __( 'The administrator watch is not available.', 'cybergate-security' ) );
			if ( is_wp_error( $result ) ) {
				if ( 'wpcybersec_user_gone' === $result->get_error_code() ) {
					/* translators: %s: user name of the administrator account */
					return $this->finish( $item, Store::STATUS_RESOLVED, 'admin_gone', __( 'Closed the report for %s: the account no longer exists.', 'cybergate-security' ) );
				}
				return $result;
			}
			/* translators: %s: user name of the administrator account */
			return $this->finish( $item, Store::STATUS_DENIED, 'admin_denied', __( 'Removed the administrator role from %s (now a subscriber) and signed the account out everywhere.', 'cybergate-security' ) );
		}
		if ( Store::TYPE_UPLOAD === $item['type'] && method_exists( $plugin->upload_gate, 'on_deny' ) ) {
			$plugin->upload_gate->on_deny( $item );
		}
		if ( Store::TYPE_INSTALL === $item['type'] && method_exists( $plugin->install_gate, 'on_deny' ) ) {
			$plugin->install_gate->on_deny( $item );
		}
		if ( '' !== (string) $item['quarantine_path'] ) {
			$plugin->quarantine->purge( $item );
		}
		/* translators: %s: file path or name of the item */
		return $this->finish( $item, Store::STATUS_DENIED, 'item_denied', __( 'Denied %s. The held copy was deleted.', 'cybergate-security' ), array( 'quarantine_path' => '' ) );
	}

	/**
	 * Threat marked safe: allowlist the hash so it is never flagged again.
	 *
	 * @param array $item Item.
	 * @return true|\WP_Error
	 */
	private function ignore( array $item ) {
		if ( Db_Scanner::is_db_item( $item ) ) {
			// Database value: remember its fingerprint. No file is involved.
			$label = Db_Scanner::location_label( $item );
			if ( ! wpcybersec()->allowlist->allow_db( (string) $item['sha256'], $label, sprintf( 'item #%d (database)', $item['id'] ) ) ) {
				return new \WP_Error( 'wpcybersec_db_allow', __( 'This finding has no fingerprint, so it cannot be marked safe.', 'cybergate-security' ) );
			}
			/* translators: %s: where the code was found, for example an option or post */
			return $this->finish( $item, Store::STATUS_IGNORED, 'db_threat_ignored', __( 'Marked %s as safe. The same content there will not be reported again.', 'cybergate-security' ) );
		}
		if ( '' !== (string) $item['quarantine_path'] ) {
			$restored = wpcybersec()->quarantine->restore( $item );
			if ( is_wp_error( $restored ) ) {
				return $restored;
			}
		}
		$this->trust( $item );
		/* translators: %s: file path or name of the item */
		return $this->finish( $item, Store::STATUS_IGNORED, 'threat_ignored', __( 'Marked %s as safe. It will not be flagged again unless its content changes.', 'cybergate-security' ), array( 'quarantine_path' => '' ) );
	}

	/**
	 * Moves the live file into quarantine.
	 *
	 * @param array $item Item.
	 * @return true|\WP_Error
	 */
	private function quarantine( array $item ) {
		$abs = $this->live_path( $item );
		if ( is_wp_error( $abs ) ) {
			return $abs;
		}
		$this->keep_copy( $abs, $item );
		$held = wpcybersec()->quarantine->hold( $abs, true );
		if ( is_wp_error( $held ) ) {
			return $held;
		}
		wpcybersec()->file_monitor->forget_file( $abs );
		return $this->finish(
			$item,
			Store::STATUS_QUARANTINED,
			'file_quarantined',
			/* translators: %s: file path or name of the item */
			__( 'Moved %s to quarantine.', 'cybergate-security' ),
			array(
				'quarantine_path' => $held['quarantine_path'],
				'original_path'   => $abs,
			)
		);
	}

	/**
	 * Puts a quarantined file back without trusting it.
	 *
	 * @param array $item Item.
	 * @return true|\WP_Error
	 */
	private function restore( array $item ) {
		$restored = wpcybersec()->quarantine->restore( $item );
		if ( is_wp_error( $restored ) ) {
			return $restored;
		}
		$this->remember_untrusted( $item );
		/* translators: %s: file path or name of the item */
		return $this->finish( $item, Store::STATUS_RESTORED, 'file_restored', __( 'Restored %s to its original location (not trusted yet).', 'cybergate-security' ), array( 'quarantine_path' => '' ) );
	}

	/**
	 * Records a restored file in the manifest as known but not trusted, so the
	 * next scan skips it while it stays unchanged instead of reporting (or, in
	 * strict mode, quarantining) it as a brand new file next to this item.
	 * The open item keeps the decision; any later change is reported again.
	 *
	 * @param array $item Item (original_path is where the file was put back).
	 */
	private function remember_untrusted( array $item ) {
		$abs = wp_normalize_path( (string) ( $item['original_path'] ? $item['original_path'] : Paths::abs( $item['path'] ) ) );
		clearstatcache( true, $abs );
		if ( '' === $abs || ! @is_file( $abs ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return;
		}
		$sha256 = (string) @hash_file( 'sha256', $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( '' === $sha256 ) {
			return;
		}
		$rel = Paths::rel( $abs );
		$row = wpcybersec()->store->manifest_get( $rel );
		if ( is_array( $row ) && Store::STATE_TRUSTED === (string) $row['state'] && hash_equals( (string) $row['sha256'], $sha256 ) ) {
			return; // These exact bytes were already trusted at this path; do not downgrade them.
		}
		wpcybersec()->store->manifest_upsert_many(
			array(
				array(
					'path'   => $rel,
					'sha256' => $sha256,
					'size'   => (int) @filesize( $abs ), // phpcs:ignore WordPress.PHP.NoSilencedErrors
					'mtime'  => (int) @filemtime( $abs ), // phpcs:ignore WordPress.PHP.NoSilencedErrors
					'state'  => Store::TYPE_THREAT === $item['type'] ? Store::STATE_THREAT : Store::STATE_PENDING,
					'run_id' => 'restore',
				),
			)
		);
	}

	/**
	 * Permanently deletes the held copy and/or the live file.
	 *
	 * @param array $item Item.
	 * @return true|\WP_Error
	 */
	private function delete( array $item ) {
		$plugin = wpcybersec();
		if ( '' !== (string) $item['quarantine_path'] ) {
			$plugin->quarantine->purge( $item );
		} elseif ( in_array( $item['type'], array( Store::TYPE_FILE, Store::TYPE_THREAT ), true ) ) {
			$abs = $this->live_path( $item );
			if ( is_wp_error( $abs ) ) {
				return $abs;
			}
			$this->keep_copy( $abs, $item );
			if ( ! Fs::delete( $abs ) ) {
				return new \WP_Error( 'wpcybersec_delete', __( 'Could not delete the file. Check file permissions.', 'cybergate-security' ) );
			}
			$plugin->file_monitor->forget_file( $abs );
		}
		/* translators: %s: file path or name of the item */
		return $this->finish( $item, Store::STATUS_DELETED, 'item_deleted', __( 'Deleted %s permanently.', 'cybergate-security' ), array( 'quarantine_path' => '' ) );
	}

	/**
	 * Replaces a changed critical core file with the verified official copy.
	 * The current version is saved as a copy first (so the changes view can
	 * still show it), and the file is swapped atomically: the site never sees
	 * a missing or half written file.
	 *
	 * @param array $item Item.
	 * @return true|\WP_Error
	 */
	private function restore_official( array $item ) {
		$abs = $this->live_path( $item );
		if ( is_wp_error( $abs ) ) {
			return $abs;
		}
		$loc = self::official_source( $item );
		if ( ! $loc ) {
			return new \WP_Error( 'wpcybersec_official', __( 'This file already matches the official copy, or no official copy is known for it.', 'cybergate-security' ) );
		}
		// The current version is saved as a gzip copy first; without zlib that is impossible.
		if ( ! function_exists( 'gzencode' ) || ! function_exists( 'gzdecode' ) ) {
			return new \WP_Error( 'wpcybersec_official', __( 'PHP\'s zlib extension is missing on this server, so the current version cannot be saved as a copy first and nothing was changed. Ask your host to enable zlib, or replace the file with the official one yourself (SFTP or your hosting file manager).', 'cybergate-security' ) );
		}
		$official = ( new Originals() )->fetch( (string) $item['path'] );
		if ( ! is_array( $official ) || ! Originals::accept( $loc, $official['content'] ) ) {
			return new \WP_Error( 'wpcybersec_official', __( 'The official copy could not be downloaded and verified, so nothing was changed. Restore the file from a backup, or try again later.', 'cybergate-security' ) );
		}
		$current = @file_get_contents( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file.
		$plugin  = wpcybersec();
		$kept    = ( false !== $current && $plugin->snapshots ) ? $plugin->snapshots->put_content( (string) $current ) : '';
		if ( '' === $kept ) {
			return new \WP_Error( 'wpcybersec_official', __( 'The current version could not be saved as a copy first, so nothing was changed. Check that the plugin\'s data folder is writable.', 'cybergate-security' ) );
		}
		$dir = dirname( $abs );
		$tmp = $dir . '/.wpcs-restore-' . strtolower( wp_generate_password( 10, false, false ) ) . '.tmp';
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents, WordPress.PHP.NoSilencedErrors -- temporary file next to the target for an atomic replace.
		if ( strlen( $official['content'] ) !== (int) @file_put_contents( $tmp, $official['content'], LOCK_EX ) ) {
			Fs::delete( $tmp );
			/* translators: %s: folder path */
			return new \WP_Error( 'wpcybersec_official', sprintf( __( 'WordPress cannot write to %s, so the file was not replaced. Upload the official file there yourself (SFTP or your hosting file manager).', 'cybergate-security' ), $dir ) );
		}
		$perms = @fileperms( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( $perms ) {
			Fs::chmod( $tmp, $perms & 0777 );
		}
		if ( ! hash_equals( $loc['md5'], (string) md5_file( $tmp ) ) || ! Fs::replace( $tmp, $abs ) ) {
			Fs::delete( $tmp );
			/* translators: %s: file path */
			return new \WP_Error( 'wpcybersec_official', sprintf( __( 'Could not replace %s. Upload the official file there yourself (SFTP or your hosting file manager).', 'cybergate-security' ), $abs ) );
		}
		clearstatcache( true, $abs );
		$plugin->file_monitor->trust_file( $abs, hash( 'sha256', $official['content'] ) );
		return $this->finish(
			$item,
			Store::STATUS_RESOLVED,
			'core_restored',
			/* translators: %s: file path */
			__( 'Replaced %s with the official WordPress file. The changed version was kept as a copy.', 'cybergate-security' ),
			array( 'details' => array( 'replaced_sha256' => $kept ) )
		);
	}

	/* ------------------------------------------------------------------ */

	/**
	 * Allowlists the item's hash and marks the file trusted in the manifest.
	 *
	 * @param array $item Item.
	 */
	private function trust( array $item ) {
		$plugin = wpcybersec();
		if ( $item['sha256'] ) {
			$plugin->allowlist->allow_hash( $item['sha256'], basename( (string) $item['path'] ), sprintf( 'item #%d (%s)', $item['id'], $item['type'] ), Paths::is_executable( (string) $item['path'] ) );
		}
		$abs = (string) ( $item['original_path'] ? $item['original_path'] : Paths::abs( $item['path'] ) );
		if ( $abs && is_file( $abs ) ) {
			$plugin->file_monitor->trust_file( $abs, $item['sha256'] );
		}
	}

	/**
	 * Keeps a copy of the reported version before the live file is moved or
	 * deleted, so the report can still show what the file contained.
	 *
	 * @param string $abs  Live path.
	 * @param array  $item Item.
	 */
	private function keep_copy( $abs, array $item ) {
		$snapshots = wpcybersec()->snapshots;
		if ( $snapshots && '' !== (string) $item['sha256'] ) {
			$snapshots->store( $abs, (string) $item['sha256'] );
		}
	}

	/**
	 * Absolute live path of a file/threat item, refusing anything outside the scan root.
	 *
	 * @param array $item Item.
	 * @return string|\WP_Error
	 */
	private function live_path( array $item ) {
		$abs = (string) ( $item['original_path'] ? $item['original_path'] : Paths::abs( $item['path'] ) );
		if ( ! is_file( $abs ) ) {
			wpcybersec()->store->item_update( $item['id'], array( 'status' => Store::STATUS_RESOLVED ) );
			return new \WP_Error( 'wpcybersec_gone', __( 'The file no longer exists; the item was marked resolved.', 'cybergate-security' ) );
		}
		// Whatever a whole-site scan covers (also wp-content, plugins or uploads
		// outside the scan root), never the plugin's own data folder.
		if ( ! Paths::in_scope( $abs ) || Storage::is_within( $abs, wpcybersec()->storage->data_dir() ) ) {
			return new \WP_Error( 'wpcybersec_outside', __( 'Refusing to touch a file outside the scanned folders.', 'cybergate-security' ) );
		}
		return $abs;
	}

	/**
	 * What an item is about, for messages: the path of a file, the login of
	 * an administrator account, the place of a database finding.
	 *
	 * @param array $item Item.
	 * @return string
	 */
	public static function label_for( array $item ) {
		if ( Store::TYPE_USER === $item['type'] ) {
			return User_Watch::item_login( $item );
		}
		if ( Db_Scanner::is_db_item( $item ) ) {
			return Db_Scanner::location_label( $item );
		}
		return (string) $item['path'];
	}

	/**
	 * Saves the new status and logs it.
	 *
	 * @param array  $item    Item.
	 * @param string $status  New status.
	 * @param string $event   Log event.
	 * @param string $message Message with %s for the path.
	 * @param array  $extra   Extra columns.
	 * @return true
	 */
	private function finish( array $item, $status, $event, $message, array $extra = array() ) {
		wpcybersec()->store->item_update(
			$item['id'],
			array_merge(
				array(
					'status'     => $status,
					'decided_by' => get_current_user_id(),
					'decided_at' => Store::now(),
				),
				$extra
			)
		);
		wpcybersec()->logger->log(
			$event,
			sprintf( $message, self::label_for( $item ) ),
			array(
				'item_id' => $item['id'],
				'type'    => $item['type'],
				'sha256'  => $item['sha256'],
			)
		);
		return true;
	}
}

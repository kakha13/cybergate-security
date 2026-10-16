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
 */
class Decisions {

	const ACTIONS = array( 'approve', 'deny', 'ignore', 'quarantine', 'restore', 'delete' );

	/**
	 * Which actions make sense for an item right now.
	 *
	 * @param array $item Item row.
	 * @return string[]
	 */
	public static function available( array $item ) {
		$held = '' !== (string) $item['quarantine_path'];
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
			return new \WP_Error( 'wpcybersec_item', __( 'Item not found.', 'wp-cyber-security' ) );
		}
		if ( ! in_array( $action, self::available( $item ), true ) ) {
			/* translators: 1: action, 2: status */
			return new \WP_Error( 'wpcybersec_action', sprintf( __( 'Cannot %1$s an item that is %2$s.', 'wp-cyber-security' ), $action, $item['status'] ) );
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
			default:
				$result = new \WP_Error( 'wpcybersec_action', __( 'Unknown action.', 'wp-cyber-security' ) );
		}

		if ( is_wp_error( $result ) ) {
			wpcybersec()->logger->log(
				'decision_failed',
				/* translators: 1: action, 2: path, 3: error */
				sprintf( __( 'Could not %1$s %2$s: %3$s', 'wp-cyber-security' ), $action, $item['path'], $result->get_error_message() ),
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

		if ( Store::TYPE_UPLOAD === $item['type'] ) {
			$result = $plugin->upload_gate->on_approve( $item );
			if ( is_wp_error( $result ) ) {
				return $result;
			}
			return $this->finish( $item, Store::STATUS_APPROVED, 'upload_approved', __( 'Approved upload %s. Identical files will pass automatically from now on.', 'wp-cyber-security' ), array( 'quarantine_path' => '' ) );
		}

		if ( Store::TYPE_INSTALL === $item['type'] ) {
			$result = $plugin->install_gate->on_approve( $item );
			if ( is_wp_error( $result ) ) {
				return $result;
			}
			return $this->finish( $item, Store::STATUS_APPROVED, 'install_approved', __( 'Approved install %s. It can now be installed and will not be held again.', 'wp-cyber-security' ), array( 'quarantine_path' => '' ) );
		}

		// File (or quarantined threat): put it back if held, then trust it.
		if ( '' !== (string) $item['quarantine_path'] ) {
			$restored = $plugin->quarantine->restore( $item );
			if ( is_wp_error( $restored ) ) {
				return $restored;
			}
		}
		$this->trust( $item );
		return $this->finish( $item, Store::STATUS_APPROVED, 'file_approved', __( 'Approved file %s. It will not be reported again unless its content changes.', 'wp-cyber-security' ), array( 'quarantine_path' => '' ) );
	}

	/**
	 * @param array $item Item.
	 * @return true|\WP_Error
	 */
	private function deny( array $item ) {
		$plugin = wpcybersec();
		if ( Store::TYPE_UPLOAD === $item['type'] && method_exists( $plugin->upload_gate, 'on_deny' ) ) {
			$plugin->upload_gate->on_deny( $item );
		}
		if ( Store::TYPE_INSTALL === $item['type'] && method_exists( $plugin->install_gate, 'on_deny' ) ) {
			$plugin->install_gate->on_deny( $item );
		}
		if ( '' !== (string) $item['quarantine_path'] ) {
			$plugin->quarantine->purge( $item );
		}
		return $this->finish( $item, Store::STATUS_DENIED, 'item_denied', __( 'Denied %s. The held copy was deleted.', 'wp-cyber-security' ), array( 'quarantine_path' => '' ) );
	}

	/**
	 * Threat marked safe: allowlist the hash so it is never flagged again.
	 *
	 * @param array $item Item.
	 * @return true|\WP_Error
	 */
	private function ignore( array $item ) {
		if ( '' !== (string) $item['quarantine_path'] ) {
			$restored = wpcybersec()->quarantine->restore( $item );
			if ( is_wp_error( $restored ) ) {
				return $restored;
			}
		}
		$this->trust( $item );
		return $this->finish( $item, Store::STATUS_IGNORED, 'threat_ignored', __( 'Marked %s as safe. It will not be flagged again unless its content changes.', 'wp-cyber-security' ), array( 'quarantine_path' => '' ) );
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
			__( 'Moved %s to quarantine.', 'wp-cyber-security' ),
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
		return $this->finish( $item, Store::STATUS_RESTORED, 'file_restored', __( 'Restored %s to its original location (not trusted yet).', 'wp-cyber-security' ), array( 'quarantine_path' => '' ) );
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
			if ( ! @unlink( $abs ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				return new \WP_Error( 'wpcybersec_delete', __( 'Could not delete the file. Check file permissions.', 'wp-cyber-security' ) );
			}
			$plugin->file_monitor->forget_file( $abs );
		}
		return $this->finish( $item, Store::STATUS_DELETED, 'item_deleted', __( 'Deleted %s permanently.', 'wp-cyber-security' ), array( 'quarantine_path' => '' ) );
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
			return new \WP_Error( 'wpcybersec_gone', __( 'The file no longer exists; the item was marked resolved.', 'wp-cyber-security' ) );
		}
		if ( ! Storage::is_within( $abs, Paths::scan_root() ) && ! Storage::is_within( $abs, ABSPATH ) ) {
			return new \WP_Error( 'wpcybersec_outside', __( 'Refusing to touch a file outside the scanned folder.', 'wp-cyber-security' ) );
		}
		return $abs;
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
			sprintf( $message, $item['path'] ),
			array(
				'item_id' => $item['id'],
				'type'    => $item['type'],
				'sha256'  => $item['sha256'],
			)
		);
		return true;
	}
}

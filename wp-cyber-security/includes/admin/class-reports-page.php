<?php
/**
 * Reports page: pending approvals, threats, quarantine, history, allowlist, activity.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity\Admin;

use WPCyberSecurity\Db_Scanner;
use WPCyberSecurity\Decisions;
use WPCyberSecurity\Diff;
use WPCyberSecurity\Store;
use WPCyberSecurity\User_Watch;

defined( 'ABSPATH' ) || exit;

/**
 * The page where administrators allow or reject what the plugin held.
 * Decisions run through AJAX (core.js data-wpcs-action / WPCyberSec.bulk);
 * every button is also a submit button of the bulk form, so the page keeps
 * working without JavaScript (admin-post wpcybersec_reports_bulk).
 */
class Reports_Page {

	const FORM_ID = 'wpcs-bulk-form';

	/** User meta: preferred diff layout (unified | split). */
	const META_LAYOUT = 'wpcybersec_diff_layout';

	/** Matches listed before the rest is folded away on the changes view. */
	const HITS_VISIBLE = 5;

	/** @var string Current tab. */
	private $tab = 'pending';

	/** @var string Search term. */
	private $search = '';

	/** @var int Current page (1-based). */
	private $paged = 1;

	/** @var string Sort column. */
	private $orderby = 'created_at';

	/** @var string ASC | DESC. */
	private $order = 'DESC';

	/** @var array Extra filters (severity, type, kind, event). */
	private $filters = array();

	/**
	 * Tabs: key => { label, icon, count (Store::counts key or '') }.
	 *
	 * @return array
	 */
	private function tabs() {
		return array(
			'pending'    => array( __( 'Pending approvals', 'wp-cyber-security' ), 'clock', 'pending' ),
			'threats'    => array( __( 'Threats', 'wp-cyber-security' ), 'warning', 'threats' ),
			'quarantine' => array( __( 'Quarantine', 'wp-cyber-security' ), 'lock', 'quarantined' ),
			'history'    => array( __( 'History', 'wp-cyber-security' ), 'backup', '' ),
			'allowlist'  => array( __( 'Allowlist', 'wp-cyber-security' ), 'yes-alt', '' ),
			'activity'   => array( __( 'Activity', 'wp-cyber-security' ), 'list-view', '' ),
		);
	}

	/**
	 * Prints the page.
	 */
	public function render() {
		if ( ! Admin::can() ) {
			wp_die( esc_html__( 'You are not allowed to view this page.', 'wp-cyber-security' ) );
		}
		$this->read_request();

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only routing.
		if ( isset( $_GET['view'] ) && 'changes' === sanitize_key( wp_unslash( $_GET['view'] ) ) ) {
			$this->render_changes();
			return;
		}

		echo '<div class="wrap wpcs-wrap wpcs-reports" data-wpcs-reports data-tab="' . esc_attr( $this->tab ) . '">';

		$actions  = '<a class="button" href="' . esc_url( Admin::page_url( Admin::PAGE_DASHBOARD ) ) . '"><span class="dashicons dashicons-dashboard" aria-hidden="true"></span> ' . esc_html__( 'Dashboard', 'wp-cyber-security' ) . '</a>';
		$actions .= '<a class="button" href="' . esc_url( Admin::page_url( Admin::PAGE_SETTINGS ) ) . '"><span class="dashicons dashicons-admin-generic" aria-hidden="true"></span> ' . esc_html__( 'Settings', 'wp-cyber-security' ) . '</a>';
		Admin::header(
			__( 'Reports', 'wp-cyber-security' ),
			__( 'Review what was held or found and decide. Anything you allow is remembered permanently.', 'wp-cyber-security' ),
			$actions
		);

		$this->render_result_notice();
		$this->render_tabs();

		switch ( $this->tab ) {
			case 'allowlist':
				$this->render_allowlist_tab();
				break;
			case 'activity':
				$this->render_activity_tab();
				break;
			default:
				$this->render_items_tab();
		}

		echo '</div>';
	}

	/**
	 * Reads and validates query args.
	 */
	private function read_request() {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only filters.
		$tab       = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'pending';
		$this->tab = array_key_exists( $tab, $this->tabs() ) ? $tab : 'pending';

		$this->search = isset( $_GET['s'] ) ? trim( sanitize_text_field( wp_unslash( $_GET['s'] ) ) ) : '';
		$this->search = function_exists( 'mb_substr' ) ? mb_substr( $this->search, 0, 200 ) : substr( $this->search, 0, 200 );
		$this->paged  = isset( $_GET['paged'] ) ? max( 1, absint( wp_unslash( $_GET['paged'] ) ) ) : 1;

		$defaults      = array(
			'threats' => 'severity',
			'history' => 'updated_at',
		);
		$this->orderby = isset( $defaults[ $this->tab ] ) ? $defaults[ $this->tab ] : 'created_at';
		$orderby       = isset( $_GET['orderby'] ) ? sanitize_key( wp_unslash( $_GET['orderby'] ) ) : '';
		if ( in_array( $orderby, array( 'created_at', 'severity', 'updated_at' ), true ) ) {
			$this->orderby = $orderby;
		}
		$order       = isset( $_GET['order'] ) ? strtoupper( sanitize_key( wp_unslash( $_GET['order'] ) ) ) : 'DESC';
		$this->order = 'ASC' === $order ? 'ASC' : 'DESC';

		$severity = isset( $_GET['severity'] ) ? absint( wp_unslash( $_GET['severity'] ) ) : 0;
		$type     = isset( $_GET['type'] ) ? sanitize_key( wp_unslash( $_GET['type'] ) ) : '';
		$kind     = isset( $_GET['kind'] ) ? sanitize_key( wp_unslash( $_GET['kind'] ) ) : '';
		$event    = isset( $_GET['event'] ) ? sanitize_key( wp_unslash( $_GET['event'] ) ) : '';
		// phpcs:enable

		$this->filters = array(
			'severity' => in_array( $severity, array( 2, 3 ), true ) ? $severity : 0,
			'type'     => in_array( $type, array( Store::TYPE_UPLOAD, Store::TYPE_INSTALL, Store::TYPE_FILE, Store::TYPE_THREAT, Store::TYPE_USER ), true ) ? $type : '',
			'kind'     => in_array( $kind, array( 'hash', 'install', 'db' ), true ) ? $kind : '',
			'event'    => substr( $event, 0, 50 ),
		);
	}

	/**
	 * URL of the current view with optional overrides.
	 *
	 * @param array $override Args to change (null removes).
	 * @return string
	 */
	private function view_url( array $override = array() ) {
		$args = array(
			'tab'      => $this->tab,
			's'        => $this->search,
			'severity' => $this->filters['severity'] ? $this->filters['severity'] : '',
			'type'     => $this->filters['type'],
			'kind'     => $this->filters['kind'],
			'event'    => $this->filters['event'],
		);
		if ( isset( $_GET['orderby'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$args['orderby'] = $this->orderby;
			$args['order']   = strtolower( $this->order );
		}
		foreach ( $override as $key => $value ) {
			$args[ $key ] = $value;
		}
		return Admin::page_url( Admin::PAGE_REPORTS, $args );
	}

	/* ------------------------------------------------------------------ */
	/* Notices and tabs                                                    */
	/* ------------------------------------------------------------------ */

	/**
	 * Result of a non-JS action (admin-post redirect).
	 */
	private function render_result_notice() {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- display only.
		$msg    = isset( $_GET['wpcs_msg'] ) ? sanitize_key( wp_unslash( $_GET['wpcs_msg'] ) ) : '';
		$done   = isset( $_GET['wpcs_done'] ) ? absint( wp_unslash( $_GET['wpcs_done'] ) ) : 0;
		$failed = isset( $_GET['wpcs_failed'] ) ? absint( wp_unslash( $_GET['wpcs_failed'] ) ) : 0;
		// phpcs:enable
		if ( '' === $msg ) {
			return;
		}

		switch ( $msg ) {
			case 'allowlist_removed':
				$this->notice( 'ok', 'yes-alt', __( 'Removed from the allowlist. The next time this file or install appears, it is held for your approval again.', 'wp-cyber-security' ) );
				break;
			case 'allowlist_missing':
				$this->notice( 'warn', 'info-outline', __( 'That allowlist entry no longer exists.', 'wp-cyber-security' ) );
				break;
			case 'no_action':
				$this->notice( 'warn', 'info-outline', __( 'Choose a bulk action first.', 'wp-cyber-security' ) );
				break;
			case 'no_items':
				$this->notice( 'warn', 'info-outline', __( 'Select at least one item first.', 'wp-cyber-security' ) );
				break;
			case 'failed':
				$this->notice( 'bad', 'warning', __( 'The action could not be completed. Reload the page and try again.', 'wp-cyber-security' ) );
				break;
			case 'bulk':
				if ( $done > 0 ) {
					$this->notice(
						'ok',
						'yes-alt',
						sprintf(
							/* translators: %s: number of items */
							_n( '%s item updated.', '%s items updated.', $done, 'wp-cyber-security' ),
							number_format_i18n( $done )
						)
					);
				}
				if ( $failed > 0 ) {
					$key    = 'wpcybersec_bulk_errors_' . get_current_user_id();
					$errors = get_transient( $key );
					delete_transient( $key );
					$errors = is_array( $errors ) ? $errors : array();
					$text   = sprintf(
						/* translators: %s: number of items */
						_n( '%s item could not be changed.', '%s items could not be changed.', $failed, 'wp-cyber-security' ),
						number_format_i18n( $failed )
					);
					$this->notice( 'bad', 'warning', $text, $errors );
				}
				break;
		}
	}

	/**
	 * Inline notice.
	 *
	 * @param string   $tone  ok | warn | bad | info.
	 * @param string   $icon  Dashicon name.
	 * @param string   $text  Plain text.
	 * @param string[] $lines Extra plain text lines.
	 */
	private function notice( $tone, $icon, $text, array $lines = array() ) {
		echo '<div class="wpcs-notice' . ( 'info' === $tone ? '' : ' wpcs-notice--' . esc_attr( $tone ) ) . '" role="status">';
		echo '<span class="dashicons dashicons-' . esc_attr( $icon ) . '" aria-hidden="true"></span><div><p>' . esc_html( $text ) . '</p>';
		foreach ( $lines as $line ) {
			echo '<p class="wpcs-mono">' . esc_html( (string) $line ) . '</p>';
		}
		echo '</div></div>';
	}

	/**
	 * Tab bar with live counts.
	 */
	private function render_tabs() {
		$counts = Admin::counts();
		echo '<nav class="nav-tab-wrapper wpcs-tabs" aria-label="' . esc_attr__( 'Report sections', 'wp-cyber-security' ) . '">';
		foreach ( $this->tabs() as $key => $tab ) {
			$active = $key === $this->tab;
			echo '<a href="' . esc_url( Admin::page_url( Admin::PAGE_REPORTS, array( 'tab' => $key ) ) ) . '" class="nav-tab' . ( $active ? ' nav-tab-active' : '' ) . '"' . ( $active ? ' aria-current="page"' : '' ) . '>';
			echo '<span class="dashicons dashicons-' . esc_attr( $tab[1] ) . '" aria-hidden="true"></span>' . esc_html( $tab[0] );
			if ( $tab[2] ) {
				$n = isset( $counts[ $tab[2] ] ) ? (int) $counts[ $tab[2] ] : 0;
				$c = 'wpcs-count' . ( $n ? '' : ' wpcs-count--zero' ) . ( 'threats' === $tab[2] ? ' wpcs-count--bad' : ' wpcs-count--neutral' );
				echo ' <span class="' . esc_attr( $c ) . '" data-wpcs-count="' . esc_attr( $tab[2] ) . '">' . esc_html( number_format_i18n( $n ) ) . '</span>';
			}
			echo '</a>';
		}
		echo '</nav>';
	}

	/* ------------------------------------------------------------------ */
	/* Item tabs (pending, threats, quarantine, history)                   */
	/* ------------------------------------------------------------------ */

	/**
	 * Query args for the current item tab.
	 *
	 * @return array
	 */
	private function item_args() {
		$per_page = (int) apply_filters( 'wpcybersec_reports_per_page', 20 );
		$args     = array(
			'search'   => $this->search,
			'orderby'  => $this->orderby,
			'order'    => $this->order,
			'per_page' => max( 5, min( 200, $per_page ) ),
			'page'     => $this->paged,
		);
		switch ( $this->tab ) {
			case 'threats':
				$args['type']         = Store::TYPE_THREAT;
				$args['status']       = Store::STATUS_PENDING;
				$args['min_severity'] = $this->filters['severity'];
				break;
			case 'quarantine':
				$args['held']   = true;
				$args['status'] = array( Store::STATUS_PENDING, Store::STATUS_QUARANTINED );
				if ( $this->filters['type'] ) {
					$args['type'] = $this->filters['type'];
				}
				break;
			case 'history':
				$args['status'] = array( Store::STATUS_APPROVED, Store::STATUS_DENIED, Store::STATUS_IGNORED, Store::STATUS_QUARANTINED, Store::STATUS_RESTORED, Store::STATUS_DELETED, Store::STATUS_RESOLVED );
				if ( $this->filters['type'] ) {
					$args['type'] = $this->filters['type'];
				}
				break;
			default:
				$types          = array( Store::TYPE_UPLOAD, Store::TYPE_INSTALL, Store::TYPE_FILE, Store::TYPE_USER );
				$args['type']   = in_array( $this->filters['type'], $types, true ) ? $this->filters['type'] : $types;
				$args['status'] = Store::STATUS_PENDING;
		}
		return $args;
	}

	/**
	 * Bulk actions offered per tab.
	 *
	 * @return array action => label
	 */
	private function bulk_actions() {
		$labels = $this->action_labels();
		$sets   = array(
			'pending'    => array( 'approve', 'deny', 'quarantine', 'delete' ),
			'threats'    => array( 'ignore', 'quarantine', 'restore', 'delete' ),
			'quarantine' => array( 'approve', 'restore', 'deny', 'delete' ),
			'history'    => array( 'approve', 'quarantine', 'restore', 'delete' ),
		);
		$out = array();
		foreach ( isset( $sets[ $this->tab ] ) ? $sets[ $this->tab ] : array() as $action ) {
			$out[ $action ] = $labels[ $action ][0];
		}
		return $out;
	}

	/**
	 * Labels, icons and classes per decision.
	 *
	 * @return array action => array( label, icon, class )
	 */
	private function action_labels() {
		return array(
			'approve'    => array( __( 'Allow', 'wp-cyber-security' ), 'yes', 'wpcs-btn-approve' ),
			'ignore'     => array( __( 'Mark safe', 'wp-cyber-security' ), 'yes-alt', 'wpcs-btn-safe' ),
			'quarantine' => array( __( 'Quarantine', 'wp-cyber-security' ), 'lock', '' ),
			'restore'    => array( __( 'Restore', 'wp-cyber-security' ), 'undo', '' ),
			'deny'       => array( __( 'Deny', 'wp-cyber-security' ), 'no-alt', '' ),
			'delete'     => array( __( 'Delete', 'wp-cyber-security' ), 'trash', 'wpcs-btn-danger' ),
		);
	}

	/**
	 * Pending, threats, quarantine and history tabs.
	 */
	private function render_items_tab() {
		$this->render_tab_intro();

		$args   = $this->item_args();
		$result = Admin::call( 'store', 'items_query', array( $args ), null );
		if ( ! is_array( $result ) ) {
			$this->notice( 'bad', 'warning', __( 'The report could not be loaded. The plugin database tables may be missing; deactivate and activate the plugin to recreate them.', 'wp-cyber-security' ) );
			return;
		}
		$rows  = isset( $result['rows'] ) ? (array) $result['rows'] : array();
		$total = isset( $result['total'] ) ? (int) $result['total'] : 0;

		$filtered = '' !== $this->search || $this->filters['type'] || $this->filters['severity'];
		if ( $rows || $filtered ) {
			$this->render_toolbar( $total );
		}

		if ( ! $rows ) {
			$this->render_items_empty();
			return;
		}

		echo '<div class="wpcs-card wpcs-card--flush wpcs-table-card">';
		echo '<table class="widefat wpcs-table wpcs-items">';
		echo '<thead><tr>';
		echo '<td class="wpcs-cb-cell"><input type="checkbox" class="wpcs-cb-all" aria-label="' . esc_attr__( 'Select all', 'wp-cyber-security' ) . '"></td>';
		echo '<th scope="col" class="column-type">' . esc_html__( 'Type', 'wp-cyber-security' ) . '</th>';
		echo '<th scope="col" class="column-item">' . esc_html__( 'Item', 'wp-cyber-security' ) . '</th>';
		echo '<th scope="col" class="column-source">' . esc_html__( 'Source', 'wp-cyber-security' ) . '</th>';
		$this->sort_th( 'created_at', __( 'Detected', 'wp-cyber-security' ), 'column-detected' );
		$this->sort_th( 'severity', __( 'Verdict', 'wp-cyber-security' ), 'column-verdict' );
		echo '<th scope="col" class="column-status">' . esc_html__( 'Status', 'wp-cyber-security' ) . '</th>';
		echo '<th scope="col" class="column-actions">' . esc_html__( 'Actions', 'wp-cyber-security' ) . '</th>';
		echo '</tr></thead><tbody>';
		foreach ( $rows as $item ) {
			if ( is_array( $item ) && isset( $item['id'] ) ) {
				$this->render_item_row( $item );
			}
		}
		echo '</tbody></table></div>';

		$this->render_pagination( $total, $args['per_page'] );
	}

	/**
	 * Explanation at the top of each item tab.
	 */
	private function render_tab_intro() {
		switch ( $this->tab ) {
			case 'pending':
				echo '<div class="wpcs-notice wpcs-promise"><span class="dashicons dashicons-yes-alt" aria-hidden="true"></span><div><p><strong>'
					. esc_html__( 'Allowed once, allowed always.', 'wp-cyber-security' ) . '</strong> '
					. esc_html__( 'When you allow a file, its SHA-256 fingerprint is remembered on the allowlist, so the exact same file is never held again, wherever it is uploaded. If the file changes, its fingerprint changes and it is checked again.', 'wp-cyber-security' )
					. '</p></div></div>';
				break;
			case 'threats':
				echo '<div class="wpcs-notice wpcs-notice--warn"><span class="dashicons dashicons-warning" aria-hidden="true"></span><div><p>'
					. esc_html__( 'Quarantine moves a file to a locked folder where it cannot run, and you can restore it later. Use "Mark safe" only for files you recognize: the exact file is then trusted and not flagged again.', 'wp-cyber-security' ) . ' '
					. esc_html__( 'Database findings (options, widgets, posts) are cleaned where they are stored, for example by editing the post; the report closes by itself after the next scan that no longer finds them.', 'wp-cyber-security' )
					. '</p></div></div>';
				break;
			case 'quarantine':
				echo '<div class="wpcs-notice"><span class="dashicons dashicons-lock" aria-hidden="true"></span><div><p>'
					. esc_html__( 'Held copies are stored in a protected folder with a random name and a .bin extension, so they cannot run even if someone finds them. Download a copy to inspect it on your computer.', 'wp-cyber-security' )
					. '</p></div></div>';
				break;
			case 'history':
				echo '<div class="wpcs-notice"><span class="dashicons dashicons-backup" aria-hidden="true"></span><div><p>'
					. esc_html__( 'Every decision is kept here for your records: who decided, when, and what happened to the file.', 'wp-cyber-security' )
					. '</p></div></div>';
				break;
		}
	}

	/**
	 * Bulk form (left) and filters/search (right).
	 *
	 * @param int $total Matching rows.
	 */
	private function render_toolbar( $total ) {
		$bulk = $this->bulk_actions();
		echo '<div class="wpcs-toolbar">';

		echo '<form id="' . esc_attr( self::FORM_ID ) . '" class="wpcs-bulk" method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="wpcybersec_reports_bulk">';
		echo '<input type="hidden" name="tab" value="' . esc_attr( $this->tab ) . '">';
		wp_nonce_field( 'wpcybersec_reports_bulk' );
		if ( $bulk && $total > 0 ) {
			echo '<label for="wpcs-bulk-action" class="screen-reader-text">' . esc_html__( 'Bulk action', 'wp-cyber-security' ) . '</label>';
			echo '<select id="wpcs-bulk-action" name="bulk_action"><option value="">' . esc_html__( 'Bulk actions', 'wp-cyber-security' ) . '</option>';
			foreach ( $bulk as $value => $label ) {
				echo '<option value="' . esc_attr( $value ) . '">' . esc_html( $label ) . '</option>';
			}
			echo '</select> <button type="submit" class="button" name="wpcs_bulk_apply" value="1">' . esc_html__( 'Apply', 'wp-cyber-security' ) . '</button>';
		}
		echo '</form>';

		echo '<form class="wpcs-filters" method="get" action="' . esc_url( admin_url( 'admin.php' ) ) . '">';
		echo '<input type="hidden" name="page" value="' . esc_attr( Admin::PAGE_REPORTS ) . '">';
		echo '<input type="hidden" name="tab" value="' . esc_attr( $this->tab ) . '">';

		if ( 'threats' === $this->tab ) {
			$this->select(
				'severity',
				(string) $this->filters['severity'],
				array(
					'0' => __( 'All severities', 'wp-cyber-security' ),
					'2' => __( 'High and critical', 'wp-cyber-security' ),
					'3' => __( 'Critical only', 'wp-cyber-security' ),
				),
				__( 'Filter by severity', 'wp-cyber-security' )
			);
		} else {
			$types = array(
				''                   => __( 'All types', 'wp-cyber-security' ),
				Store::TYPE_UPLOAD  => __( 'Uploads', 'wp-cyber-security' ),
				Store::TYPE_INSTALL => __( 'Installs', 'wp-cyber-security' ),
				Store::TYPE_FILE    => __( 'Files', 'wp-cyber-security' ),
			);
			if ( 'quarantine' !== $this->tab ) {
				$types[ Store::TYPE_USER ] = __( 'Administrators', 'wp-cyber-security' );
			}
			if ( 'pending' !== $this->tab ) {
				$types[ Store::TYPE_THREAT ] = __( 'Threats', 'wp-cyber-security' );
			}
			$this->select( 'type', $this->filters['type'], $types, __( 'Filter by type', 'wp-cyber-security' ) );
		}
		$this->search_box( __( 'Search file name, path or hash', 'wp-cyber-security' ) );
		echo '</form>';

		echo '</div>';

		if ( '' !== $this->search ) {
			echo '<p class="wpcs-search-note">' . esc_html(
				sprintf(
					/* translators: 1: number of results, 2: search term */
					_n( '%1$s result for "%2$s".', '%1$s results for "%2$s".', $total, 'wp-cyber-security' ),
					number_format_i18n( $total ),
					$this->search
				)
			) . ' <a href="' . esc_url( $this->view_url( array( 's' => '' ) ) ) . '">' . esc_html__( 'Clear search', 'wp-cyber-security' ) . '</a></p>';
		}
	}

	/**
	 * Select that submits its form on change (admin.js) with a no-JS fallback button.
	 *
	 * @param string $name    Field name.
	 * @param string $current Current value.
	 * @param array  $options value => label.
	 * @param string $label   Accessible label.
	 */
	private function select( $name, $current, array $options, $label ) {
		$id = 'wpcs-filter-' . $name;
		echo '<label for="' . esc_attr( $id ) . '" class="screen-reader-text">' . esc_html( $label ) . '</label>';
		echo '<select id="' . esc_attr( $id ) . '" name="' . esc_attr( $name ) . '" data-wpcs-autosubmit>';
		foreach ( $options as $value => $text ) {
			echo '<option value="' . esc_attr( (string) $value ) . '"' . selected( (string) $current, (string) $value, false ) . '>' . esc_html( $text ) . '</option>';
		}
		echo '</select>';
	}

	/**
	 * Search input + submit.
	 *
	 * @param string $placeholder Placeholder.
	 */
	private function search_box( $placeholder ) {
		echo '<label for="wpcs-search" class="screen-reader-text">' . esc_html( $placeholder ) . '</label>';
		echo '<input type="search" id="wpcs-search" name="s" value="' . esc_attr( $this->search ) . '" placeholder="' . esc_attr( $placeholder ) . '">';
		echo '<button type="submit" class="button">' . esc_html__( 'Search', 'wp-cyber-security' ) . '</button>';
	}

	/**
	 * Sortable column header.
	 *
	 * @param string $key   orderby value.
	 * @param string $label Label.
	 * @param string $class Column class.
	 */
	private function sort_th( $key, $label, $class ) {
		$current = $this->orderby === $key;
		$next    = $current && 'DESC' === $this->order ? 'asc' : 'desc';
		$url     = $this->view_url(
			array(
				'orderby' => $key,
				'order'   => $next,
			)
		);
		$aria    = $current ? ( 'ASC' === $this->order ? 'ascending' : 'descending' ) : 'none';
		$icon    = $current && 'ASC' === $this->order ? 'arrow-up-alt2' : 'arrow-down-alt2';
		echo '<th scope="col" class="' . esc_attr( $class . ' wpcs-sortable' . ( $current ? ' is-sorted' : '' ) ) . '" aria-sort="' . esc_attr( $aria ) . '">';
		echo '<a href="' . esc_url( $url ) . '"><span>' . esc_html( $label ) . '</span><span class="dashicons dashicons-' . esc_attr( $icon ) . '" aria-hidden="true"></span></a></th>';
	}

	/**
	 * One item row plus its hidden details row.
	 *
	 * @param array $item Item.
	 */
	private function render_item_row( array $item ) {
		$id        = (int) $item['id'];
		$type      = (string) $item['type'];
		$status    = (string) $item['status'];
		$held      = $this->has_held_copy( $item );
		$available = class_exists( '\WPCyberSecurity\Decisions' ) ? Decisions::available( $item ) : array();
		$details   = isset( $item['details'] ) && is_array( $item['details'] ) ? $item['details'] : array();
		$severity  = (int) $item['severity'];

		$classes = array( 'wpcs-item', 'wpcs-item--' . sanitize_html_class( $type ), 'wpcs-sev-' . $severity );
		if ( ! $available ) {
			$classes[] = 'is-done';
		}
		echo '<tr class="' . esc_attr( implode( ' ', $classes ) ) . '" data-item-id="' . esc_attr( (string) $id ) . '" data-type="' . esc_attr( $type ) . '" data-held="' . ( $held ? '1' : '0' ) . '">';

		// Checkbox.
		echo '<th scope="row" class="wpcs-cb-cell"><input type="checkbox" class="wpcs-cb-item" name="ids[]" value="' . esc_attr( (string) $id ) . '" form="' . esc_attr( self::FORM_ID ) . '"'
			. ( $available ? '' : ' disabled' )
			/* translators: %s: file name */
			. ' aria-label="' . esc_attr( sprintf( __( 'Select %s', 'wp-cyber-security' ), $this->item_title( $item ) ) ) . '"></th>';

		// Type.
		echo '<td class="column-type">' . $this->type_badge( $type, $item ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput -- built with escaping.

		// Item.
		echo '<td class="column-item">' . $this->item_cell( $item, $details ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput -- built with escaping.

		// Source.
		echo '<td class="column-source">' . $this->source_cell( $item, $details ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput -- built with escaping.

		// Detected.
		$ts = Admin::utc_ts( $item['created_at'] );
		echo '<td class="column-detected"><span title="' . esc_attr( Admin::datetime( $ts ) ) . '">' . esc_html( Admin::ago( $ts ) ) . '</span><span class="wpcs-sub">' . esc_html( $ts ? wp_date( get_option( 'date_format' ), $ts ) : '' ) . '</span></td>';

		// Verdict.
		echo '<td class="column-verdict">' . $this->verdict_cell( $item, $details ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput -- built with escaping.

		// Status.
		echo '<td class="column-status" data-wpcs-status>' . $this->status_cell( $item, $held ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput -- built with escaping.

		// Actions.
		echo '<td class="column-actions">' . $this->actions_cell( $item, $available, $held ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput -- built with escaping.

		echo '</tr>';

		echo '<tr class="wpcs-details-row" id="wpcs-details-' . esc_attr( (string) $id ) . '" hidden><td colspan="8">';
		$this->render_details( $item, $details );
		echo '</td></tr>';
	}

	/**
	 * Whether a held copy really exists for an open item (approved uploads may
	 * keep a stale quarantine_path after the copy was imported and purged).
	 *
	 * @param array $item Item.
	 * @return bool
	 */
	private function has_held_copy( array $item ) {
		if ( '' === (string) $item['quarantine_path'] ) {
			return false;
		}
		if ( ! in_array( $item['status'], array( Store::STATUS_PENDING, Store::STATUS_QUARANTINED ), true ) ) {
			return false;
		}
		return (bool) Admin::call( 'quarantine', 'exists', array( $item ), false );
	}

	/**
	 * Readable name of an item.
	 *
	 * @param array $item Item.
	 * @return string
	 */
	private function item_title( array $item ) {
		$details = isset( $item['details'] ) && is_array( $item['details'] ) ? $item['details'] : array();
		if ( Store::TYPE_INSTALL === $item['type'] && ! empty( $details['name'] ) ) {
			return (string) $details['name'];
		}
		if ( Store::TYPE_USER === $item['type'] ) {
			return User_Watch::item_login( $item );
		}
		if ( Db_Scanner::is_db_item( $item ) ) {
			return Db_Scanner::location_label( $item );
		}
		return basename( (string) $item['path'] );
	}

	/**
	 * @param string     $type Item type.
	 * @param array|null $item Item (database findings get their own badge).
	 * @return string HTML.
	 */
	private function type_badge( $type, $item = null ) {
		$map = array(
			Store::TYPE_UPLOAD  => array( __( 'Upload', 'wp-cyber-security' ), 'upload' ),
			Store::TYPE_INSTALL => array( __( 'Install', 'wp-cyber-security' ), 'admin-plugins' ),
			Store::TYPE_FILE    => array( __( 'File', 'wp-cyber-security' ), 'media-code' ),
			Store::TYPE_THREAT  => array( __( 'Threat', 'wp-cyber-security' ), 'warning' ),
			Store::TYPE_USER    => array( __( 'New administrator', 'wp-cyber-security' ), 'admin-users' ),
		);
		$entry = isset( $map[ $type ] ) ? $map[ $type ] : array( ucfirst( $type ), 'marker' );
		$class = $type;
		if ( is_array( $item ) && Db_Scanner::is_db_item( $item ) ) {
			$entry = array( __( 'Database', 'wp-cyber-security' ), 'database' );
			$class = 'database';
		}
		return '<span class="wpcs-badge wpcs-type wpcs-type--' . esc_attr( sanitize_html_class( $class ) ) . '"><span class="dashicons dashicons-' . esc_attr( $entry[1] ) . '" aria-hidden="true"></span>' . esc_html( $entry[0] ) . '</span>';
	}

	/**
	 * Place of a database finding, with an edit link for posts.
	 *
	 * @param array $item Item.
	 * @return string HTML.
	 */
	private function db_location_html( array $item ) {
		$label   = Db_Scanner::location_label( $item );
		$post_id = Db_Scanner::post_id( $item );
		$link    = $post_id ? get_edit_post_link( $post_id, 'raw' ) : '';
		if ( $link ) {
			return '<a class="wpcs-item-name" href="' . esc_url( $link ) . '">' . esc_html( $label ) . '</a>';
		}
		return '<strong class="wpcs-item-name">' . esc_html( $label ) . '</strong>';
	}

	/**
	 * How an account became an administrator.
	 *
	 * @param array $details Item details.
	 * @return string
	 */
	private function admin_how( array $details ) {
		$how = isset( $details['how'] ) ? (string) $details['how'] : '';
		switch ( $how ) {
			case 'registered':
				return __( 'New account created as administrator', 'wp-cyber-security' );
			case 'super_admin':
				return __( 'Made a network super admin', 'wp-cyber-security' );
			case 'scan':
				return __( 'Found by the administrator check of a scan', 'wp-cyber-security' );
			default:
				return __( 'Existing account given the administrator role', 'wp-cyber-security' );
		}
	}

	/**
	 * Who gave an account administrator rights.
	 *
	 * @param array $item    Item.
	 * @param array $details Details.
	 * @return string
	 */
	private function admin_granted_by( array $item, array $details ) {
		if ( 'scan' === (string) $item['source'] ) {
			return __( 'Unknown (possibly added straight to the database)', 'wp-cyber-security' );
		}
		$name = Admin::user_name( $item['user_id'] );
		if ( '' !== $name ) {
			return ! empty( $details['granted_by_login'] ) ? $name . ' (' . (string) $details['granted_by_login'] . ')' : $name;
		}
		if ( ! empty( $details['granted_by_login'] ) ) {
			return (string) $details['granted_by_login'];
		}
		$contexts = array(
			'cli'  => __( 'No logged-in user (WP-CLI)', 'wp-cyber-security' ),
			'cron' => __( 'No logged-in user (scheduled task)', 'wp-cyber-security' ),
		);
		$context  = isset( $details['context'] ) ? (string) $details['context'] : '';
		return isset( $contexts[ $context ] ) ? $contexts[ $context ] : __( 'No logged-in user', 'wp-cyber-security' );
	}

	/**
	 * Path display that emphasises the file name.
	 *
	 * @param string $path Path or name.
	 * @return string HTML.
	 */
	private function path_html( $path ) {
		$path = (string) $path;
		$pos  = strrpos( $path, '/' );
		if ( false === $pos ) {
			return '<span class="wpcs-path"><span class="wpcs-path__file">' . esc_html( $path ) . '</span></span>';
		}
		return '<span class="wpcs-path"><span class="wpcs-path__dir">' . esc_html( substr( $path, 0, $pos + 1 ) ) . '</span><span class="wpcs-path__file">' . esc_html( substr( $path, $pos + 1 ) ) . '</span></span>';
	}

	/**
	 * Shortened hash with the full value in the title.
	 *
	 * @param string $hash SHA-256.
	 * @return string HTML.
	 */
	private function short_hash( $hash ) {
		$hash = (string) $hash;
		if ( '' === $hash ) {
			return '';
		}
		$short = strlen( $hash ) > 16 ? substr( $hash, 0, 12 ) . '...' . substr( $hash, -4 ) : $hash;
		return '<span class="wpcs-hash" title="' . esc_attr( 'SHA-256: ' . $hash ) . '">' . esc_html( $short ) . '</span>';
	}

	/**
	 * @param array $item    Item.
	 * @param array $details Details.
	 * @return string HTML.
	 */
	private function item_cell( array $item, array $details ) {
		$html = '';
		if ( Store::TYPE_USER === $item['type'] ) {
			$html  = '<strong class="wpcs-item-name">' . esc_html( User_Watch::item_login( $item ) ) . '</strong>';
			$html .= ' <span class="wpcs-muted">' . esc_html( '#' . User_Watch::item_user_id( $item ) ) . '</span>';
			if ( ! empty( $details['user_email'] ) ) {
				$html .= '<span class="wpcs-sub">' . esc_html( (string) $details['user_email'] ) . '</span>';
			}
			$html .= '<span class="wpcs-sub">' . esc_html( $this->admin_how( $details ) ) . '</span>';
			list( $who, $context ) = $this->source_parts( $item, $details );
			$html .= '<span class="wpcs-sub wpcs-narrow-when">' . esc_html( Admin::ago( Admin::utc_ts( $item['created_at'] ) ) ) . '</span>';
			$html .= '<span class="wpcs-sub wpcs-narrow-source">' . esc_html( $who . ', ' . $context ) . '</span>';
			return $html;
		}
		if ( Db_Scanner::is_db_item( $item ) ) {
			$html = $this->db_location_html( $item );
			$meta = array();
			if ( ! empty( $details['post_type'] ) ) {
				$meta[] = esc_html( (string) $details['post_type'] . ( ! empty( $details['post_status'] ) ? ', ' . (string) $details['post_status'] : '' ) );
			}
			if ( (int) $item['size'] > 0 ) {
				$meta[] = esc_html( size_format( (int) $item['size'], (int) $item['size'] >= KB_IN_BYTES ? 1 : 0 ) );
			}
			if ( $meta ) {
				$html .= '<span class="wpcs-sub wpcs-meta">' . implode( '<span class="wpcs-sep" aria-hidden="true"></span>', $meta ) . '</span>';
			}
			list( $who, $context ) = $this->source_parts( $item, $details );
			$html .= '<span class="wpcs-sub wpcs-narrow-when">' . esc_html( Admin::ago( Admin::utc_ts( $item['created_at'] ) ) ) . '</span>';
			$html .= '<span class="wpcs-sub wpcs-narrow-source">' . esc_html( $who . ', ' . $context ) . '</span>';
			return $html;
		}
		if ( Store::TYPE_INSTALL === $item['type'] ) {
			$name = ! empty( $details['name'] ) ? (string) $details['name'] : ( ! empty( $details['slug'] ) ? (string) $details['slug'] : (string) $item['path'] );
			$html = '<strong class="wpcs-item-name">' . esc_html( $name ) . '</strong>';
			if ( ! empty( $details['version'] ) ) {
				/* translators: %s: version number */
				$html .= ' <span class="wpcs-muted">' . esc_html( sprintf( __( 'version %s', 'wp-cyber-security' ), $details['version'] ) ) . '</span>';
			}
			$html .= '<span class="wpcs-sub wpcs-mono">' . esc_html( (string) $item['path'] ) . '</span>';
		} else {
			$html = $this->path_html( $item['path'] );
		}

		$meta = array();
		if ( (int) $item['size'] > 0 ) {
			$meta[] = esc_html( size_format( (int) $item['size'], (int) $item['size'] >= KB_IN_BYTES ? 1 : 0 ) );
		}
		if ( '' !== (string) $item['mime'] ) {
			$meta[] = esc_html( (string) $item['mime'] );
		}
		if ( '' !== (string) $item['sha256'] ) {
			$meta[] = $this->short_hash( $item['sha256'] );
		}
		if ( ! empty( $details['change'] ) && Store::TYPE_FILE === $item['type'] ) {
			$meta[] = 'modified' === $details['change']
				? '<span class="wpcs-chip wpcs-chip--warn">' . esc_html__( 'modified', 'wp-cyber-security' ) . '</span>'
				: '<span class="wpcs-chip">' . esc_html__( 'new', 'wp-cyber-security' ) . '</span>';
		}
		if ( $meta ) {
			$html .= '<span class="wpcs-sub wpcs-meta">' . implode( '<span class="wpcs-sep" aria-hidden="true"></span>', $meta ) . '</span>';
		}

		// Shown only on narrow screens, where the Source and Detected columns are hidden.
		list( $who, $context ) = $this->source_parts( $item, $details );
		$html .= '<span class="wpcs-sub wpcs-narrow-when">' . esc_html( Admin::ago( Admin::utc_ts( $item['created_at'] ) ) ) . '</span>';
		$html .= '<span class="wpcs-sub wpcs-narrow-source">' . esc_html( $who . ', ' . $context ) . '</span>';
		return $html;
	}

	/**
	 * Who sent it and from where.
	 *
	 * @param array $item    Item.
	 * @param array $details Details.
	 * @return string HTML.
	 */
	private function source_cell( array $item, array $details ) {
		list( $who, $context ) = $this->source_parts( $item, $details );

		$html  = '<span class="wpcs-source__who">' . esc_html( $who ) . '</span>';
		$html .= '<span class="wpcs-sub">' . esc_html( $context ) . '</span>';
		if ( '' !== (string) $item['ip'] ) {
			$html .= '<span class="wpcs-sub wpcs-mono">' . esc_html( (string) $item['ip'] ) . '</span>';
		}
		return $html;
	}

	/**
	 * Who sent it and the context label.
	 *
	 * @param array $item    Item.
	 * @param array $details Details.
	 * @return array { who, context }
	 */
	private function source_parts( array $item, array $details ) {
		$source = (string) $item['source'];
		if ( '' === $source && ! empty( $details['context'] ) ) {
			$source = (string) $details['context'];
		}
		$user = Admin::user_name( $item['user_id'] );

		if ( Store::TYPE_USER === $item['type'] ) {
			$who      = $this->admin_granted_by( $item, $details );
			$contexts = array(
				'admin'  => __( 'Admin screens', 'wp-cyber-security' ),
				'ajax'   => __( 'Admin AJAX request', 'wp-cyber-security' ),
				'rest'   => __( 'REST API', 'wp-cyber-security' ),
				'xmlrpc' => __( 'XML-RPC', 'wp-cyber-security' ),
				'cli'    => __( 'WP-CLI', 'wp-cyber-security' ),
				'cron'   => __( 'Scheduled task', 'wp-cyber-security' ),
				'front'  => __( 'Front end request', 'wp-cyber-security' ),
				'scan'   => __( 'Administrator check', 'wp-cyber-security' ),
			);
			$context  = isset( $details['context'], $contexts[ (string) $details['context'] ] ) ? $contexts[ (string) $details['context'] ] : __( 'Administrator watch', 'wp-cyber-security' );
			return array( $who, $context );
		}
		if ( Store::SOURCE_DATABASE === $source ) {
			/* translators: %s: user display name */
			$who = '' !== $user ? sprintf( __( 'Scan by %s', 'wp-cyber-security' ), $user ) : __( 'Scheduled scan', 'wp-cyber-security' );
			return array( $who, __( 'Database scan', 'wp-cyber-security' ) );
		}

		if ( 'scan' === $source || ( '' === $source && in_array( $item['type'], array( Store::TYPE_FILE, Store::TYPE_THREAT ), true ) ) ) {
			/* translators: %s: user display name */
			$who     = '' !== $user ? sprintf( __( 'Scan by %s', 'wp-cyber-security' ), $user ) : __( 'Scheduled scan', 'wp-cyber-security' );
			$context = __( 'File scan', 'wp-cyber-security' );
		} elseif ( 'install' === $source || Store::TYPE_INSTALL === $item['type'] ) {
			$who     = '' !== $user ? $user : __( 'Unknown user', 'wp-cyber-security' );
			$context = $this->install_context( $details );
		} else {
			$who      = '' !== $user ? $user : __( 'Visitor', 'wp-cyber-security' );
			$contexts = array(
				'media'      => __( 'Media Library', 'wp-cyber-security' ),
				'sideload'   => __( 'Downloaded by WordPress', 'wp-cyber-security' ),
				'rest'       => __( 'REST API', 'wp-cyber-security' ),
				'plugin_zip' => __( 'Plugin ZIP', 'wp-cyber-security' ),
				'theme_zip'  => __( 'Theme ZIP', 'wp-cyber-security' ),
				'guard'      => __( 'Early guard', 'wp-cyber-security' ),
			);
			$context  = isset( $contexts[ $source ] ) ? $contexts[ $source ] : ( '' !== $source ? ucfirst( str_replace( '_', ' ', $source ) ) : __( 'Upload', 'wp-cyber-security' ) );
			if ( 'guard' === $source ) {
				$script = ! empty( $details['script'] ) ? (string) $details['script'] : ( ! empty( $details['request_uri'] ) ? (string) $details['request_uri'] : '' );
				if ( '' !== $script ) {
					$context .= ': ' . $script;
				}
			}
		}

		return array( $who, $context );
	}

	/**
	 * @param array $details Install details.
	 * @return string
	 */
	private function install_context( array $details ) {
		$is_theme = isset( $details['install_type'] ) && 'theme' === $details['install_type'];
		$src      = isset( $details['install_source'] ) ? (string) $details['install_source'] : '';
		if ( 'wporg' === $src ) {
			return $is_theme ? __( 'Theme from WordPress.org', 'wp-cyber-security' ) : __( 'Plugin from WordPress.org', 'wp-cyber-security' );
		}
		if ( 'upload' === $src ) {
			return $is_theme ? __( 'Theme ZIP upload', 'wp-cyber-security' ) : __( 'Plugin ZIP upload', 'wp-cyber-security' );
		}
		if ( 'url' === $src ) {
			return $is_theme ? __( 'Theme from a URL', 'wp-cyber-security' ) : __( 'Plugin from a URL', 'wp-cyber-security' );
		}
		return $is_theme ? __( 'Theme install', 'wp-cyber-security' ) : __( 'Plugin install', 'wp-cyber-security' );
	}

	/**
	 * Severity + top hit, or the reason it was held.
	 *
	 * @param array $item    Item.
	 * @param array $details Details.
	 * @return string HTML.
	 */
	private function verdict_cell( array $item, array $details ) {
		if ( Store::TYPE_USER === $item['type'] ) {
			return Admin::severity_badge( (int) $item['severity'] ) . '<span class="wpcs-verdict__title">' . esc_html__( 'New administrator account', 'wp-cyber-security' ) . '</span><span class="wpcs-sub">' . esc_html__( 'Not on your trusted administrator list', 'wp-cyber-security' ) . '</span>';
		}
		$hits = $this->hits( $details );
		if ( $hits ) {
			$top   = $hits[0];
			$sev   = max( (int) $item['severity'], isset( $top['severity'] ) ? (int) $top['severity'] : 0 );
			$title = ! empty( $top['title'] ) ? (string) $top['title'] : ( ! empty( $top['sig'] ) ? (string) $top['sig'] : __( 'Suspicious code', 'wp-cyber-security' ) );
			$html  = Admin::severity_badge( $sev ) . '<span class="wpcs-verdict__title">' . esc_html( $title ) . '</span>';
			if ( count( $hits ) > 1 ) {
				$html .= '<span class="wpcs-sub">' . esc_html(
					sprintf(
						/* translators: %s: number of further matches */
						_n( '+%s more match', '+%s more matches', count( $hits ) - 1, 'wp-cyber-security' ),
						number_format_i18n( count( $hits ) - 1 )
					)
				) . '</span>';
			}
			return $html;
		}

		$checksum = isset( $details['checksum'] ) ? (string) $details['checksum'] : '';
		if ( 'mismatch' === $checksum ) {
			return '<span class="wpcs-badge wpcs-badge--high">' . esc_html__( 'Checksum mismatch', 'wp-cyber-security' ) . '</span><span class="wpcs-sub">' . esc_html__( 'Differs from the official WordPress.org file', 'wp-cyber-security' ) . '</span>';
		}
		if ( 'unknown_file' === $checksum ) {
			return '<span class="wpcs-badge wpcs-badge--medium">' . esc_html__( 'Unknown file', 'wp-cyber-security' ) . '</span><span class="wpcs-sub">' . esc_html__( 'Not part of the official release', 'wp-cyber-security' ) . '</span>';
		}

		switch ( $item['type'] ) {
			case Store::TYPE_UPLOAD:
				return '<span class="wpcs-badge wpcs-badge--ok">' . esc_html__( 'Clean', 'wp-cyber-security' ) . '</span><span class="wpcs-sub">' . esc_html__( 'Held by policy', 'wp-cyber-security' ) . '</span>';
			case Store::TYPE_INSTALL:
				return '<span class="wpcs-badge wpcs-badge--ok">' . esc_html__( 'Clean', 'wp-cyber-security' ) . '</span><span class="wpcs-sub">' . esc_html__( 'New install held by policy', 'wp-cyber-security' ) . '</span>';
			case Store::TYPE_FILE:
				if ( isset( $details['change'] ) && 'modified' === $details['change'] ) {
					return '<span class="wpcs-badge wpcs-badge--medium">' . esc_html__( 'Modified', 'wp-cyber-security' ) . '</span><span class="wpcs-sub">' . esc_html__( 'Changed since the baseline', 'wp-cyber-security' ) . '</span>';
				}
				return '<span class="wpcs-badge wpcs-badge--info">' . esc_html__( 'New file', 'wp-cyber-security' ) . '</span><span class="wpcs-sub">' . esc_html__( 'Not in your trusted baseline', 'wp-cyber-security' ) . '</span>';
			default:
				return Admin::severity_badge( (int) $item['severity'] ) . '<span class="wpcs-sub">' . esc_html__( 'Flagged by the scanner', 'wp-cyber-security' ) . '</span>';
		}
	}

	/**
	 * Hits sorted by severity, highest first.
	 *
	 * @param array $details Details.
	 * @return array
	 */
	private function hits( array $details ) {
		$hits = isset( $details['hits'] ) && is_array( $details['hits'] ) ? array_values( array_filter( $details['hits'], 'is_array' ) ) : array();
		usort(
			$hits,
			static function ( $a, $b ) {
				$sa = isset( $a['severity'] ) ? (int) $a['severity'] : 0;
				$sb = isset( $b['severity'] ) ? (int) $b['severity'] : 0;
				return $sb - $sa;
			}
		);
		return $hits;
	}

	/**
	 * Status badge plus a short explanation.
	 *
	 * @param array $item Item.
	 * @param bool  $held Whether a held copy exists.
	 * @return string HTML.
	 */
	private function status_cell( array $item, $held ) {
		$html = Admin::status_badge( $item['status'] );
		if ( Store::STATUS_PENDING === $item['status'] ) {
			if ( $held ) {
				$html .= '<span class="wpcs-sub">' . esc_html__( 'Held in quarantine', 'wp-cyber-security' ) . '</span>';
			} elseif ( Store::TYPE_USER === $item['type'] ) {
				$html .= '<span class="wpcs-sub">' . esc_html__( 'Has administrator rights', 'wp-cyber-security' ) . '</span>';
			} elseif ( Db_Scanner::is_db_item( $item ) ) {
				$html .= '<span class="wpcs-sub">' . esc_html__( 'Still in the database', 'wp-cyber-security' ) . '</span>';
			} elseif ( in_array( $item['type'], array( Store::TYPE_FILE, Store::TYPE_THREAT ), true ) ) {
				$html .= '<span class="wpcs-sub">' . esc_html__( 'Still in place', 'wp-cyber-security' ) . '</span>';
			}
			return $html;
		}
		$decided = Admin::utc_ts( isset( $item['decided_at'] ) ? $item['decided_at'] : '' );
		$user    = Admin::user_name( isset( $item['decided_by'] ) ? $item['decided_by'] : 0 );
		$parts   = array();
		if ( '' !== $user ) {
			/* translators: %s: user display name */
			$parts[] = sprintf( __( 'by %s', 'wp-cyber-security' ), $user );
		}
		if ( $decided ) {
			$parts[] = Admin::ago( $decided );
		}
		if ( $parts ) {
			$html .= '<span class="wpcs-sub" title="' . esc_attr( Admin::datetime( $decided ) ) . '">' . esc_html( implode( ', ', $parts ) ) . '</span>';
		}
		return $html;
	}

	/**
	 * Decision buttons (all relevant ones rendered, unavailable ones hidden so
	 * core.js can reveal them after a status change), Download and Details.
	 *
	 * @param array    $item      Item.
	 * @param string[] $available Available actions now.
	 * @param bool     $held      Held copy exists.
	 * @param array    $opts      { details: bool (Details toggle), changes: bool (View changes link) }.
	 * @return string HTML.
	 */
	private function actions_cell( array $item, array $available, $held, array $opts = array() ) {
		$opts = array_merge(
			array(
				'details' => true,
				'changes' => true,
			),
			$opts
		);
		$id     = (int) $item['id'];
		$type   = (string) $item['type'];
		$labels = $this->action_labels();
		$name   = $this->item_title( $item );

		$not_file = Store::TYPE_USER === $type || Db_Scanner::is_db_item( $item );
		if ( Store::TYPE_USER === $type ) {
			$set                = array( 'approve', 'deny' );
			$labels['approve']  = array( __( 'Allow', 'wp-cyber-security' ), 'yes', 'wpcs-btn-approve' );
			$labels['deny']     = array( __( 'Remove admin role', 'wp-cyber-security' ), 'admin-users', 'wpcs-btn-danger' );
		} elseif ( Db_Scanner::is_db_item( $item ) ) {
			$set = array( 'ignore' );
		} elseif ( in_array( $type, array( Store::TYPE_UPLOAD, Store::TYPE_INSTALL ), true ) ) {
			$set = array( 'approve', 'deny', 'restore', 'delete' );
		} elseif ( Store::TYPE_THREAT === $type ) {
			$set = array( 'approve', 'ignore', 'quarantine', 'restore', 'delete' );
		} else {
			$set = array( 'approve', 'quarantine', 'restore', 'delete' );
		}

		$titles = array(
			'approve'    => Store::TYPE_INSTALL === $type
				? __( 'Allow this plugin or theme and remember it permanently', 'wp-cyber-security' )
				: __( 'Allow and remember this file permanently', 'wp-cyber-security' ),
			'ignore'     => __( 'False positive: trust this exact file from now on', 'wp-cyber-security' ),
			'quarantine' => __( 'Move the file to the locked quarantine folder where it cannot run', 'wp-cyber-security' ),
			'restore'    => __( 'Put the file back where it was, without trusting it', 'wp-cyber-security' ),
			'deny'       => __( 'Reject it and delete the held copy', 'wp-cyber-security' ),
			'delete'     => __( 'Delete permanently', 'wp-cyber-security' ),
		);
		if ( Store::TYPE_USER === $type ) {
			$titles['approve'] = __( 'This administrator is expected: trust the account from now on', 'wp-cyber-security' );
			$titles['deny']    = __( 'Make the account a subscriber, revoke super admin and sign it out everywhere', 'wp-cyber-security' );
		} elseif ( Db_Scanner::is_db_item( $item ) ) {
			$titles['ignore'] = __( 'False positive: trust this exact content at this place from now on', 'wp-cyber-security' );
		}
		$confirm_delete = $held
			/* translators: %s: file name */
			? sprintf( __( 'Delete the held copy of %s permanently? This cannot be undone.', 'wp-cyber-security' ), $name )
			/* translators: %s: file name */
			: sprintf( __( 'Delete %s from the server permanently? This cannot be undone.', 'wp-cyber-security' ), $name );

		$html = '<div class="wpcs-actions">';
		foreach ( $set as $action ) {
			$label   = $labels[ $action ];
			$classes = 'button button-small wpcs-act wpcs-act--' . $action . ( $label[2] ? ' ' . $label[2] : '' ) . ( in_array( $action, $available, true ) ? '' : ' wpcs-hidden' );
			$html   .= '<button type="submit" form="' . esc_attr( self::FORM_ID ) . '" name="wpcs_single" value="' . esc_attr( $action . ':' . $id ) . '"'
				. ' class="' . esc_attr( $classes ) . '" data-wpcs-action="' . esc_attr( $action ) . '" data-id="' . esc_attr( (string) $id ) . '"'
				. ' title="' . esc_attr( $titles[ $action ] ) . '"'
				. ( 'delete' === $action ? ' data-confirm="' . esc_attr( $confirm_delete ) . '"' : '' )
				. ( Store::TYPE_USER === $type && 'deny' === $action
					/* translators: %s: user login */
					? ' data-confirm="' . esc_attr( sprintf( __( 'Remove the administrator role from %s? The account becomes a subscriber and is signed out everywhere.', 'wp-cyber-security' ), $name ) ) . '"'
					: '' )
				. '><span class="dashicons dashicons-' . esc_attr( $label[1] ) . '" aria-hidden="true"></span>' . esc_html( $label[0] ) . '</button>';
		}
		$html .= '</div>';

		$html  .= '<div class="wpcs-row-links">';
		$button = $opts['changes'] ? Diff::view_button( $item, $held ) : null;
		if ( $button ) {
			$html .= '<a class="wpcs-view-changes" href="' . esc_url( $this->changes_url( $item ) ) . '" title="' . esc_attr( $button['title'] ) . '"><span class="dashicons dashicons-editor-code" aria-hidden="true"></span>' . esc_html( $button['label'] ) . '</a>';
		}
		$download = wp_nonce_url(
			add_query_arg(
				array(
					'action' => 'wpcybersec_download',
					'id'     => $id,
				),
				admin_url( 'admin-post.php' )
			),
			'wpcybersec_download_' . $id
		);
		if ( ! $not_file ) {
			$html .= '<a class="wpcs-download' . ( $held ? '' : ' wpcs-hidden' ) . '" href="' . esc_url( $download ) . '" title="' . esc_attr__( 'Download the held copy to inspect it (saved with a .quarantined extension)', 'wp-cyber-security' ) . '"><span class="dashicons dashicons-download" aria-hidden="true"></span>' . esc_html__( 'Download', 'wp-cyber-security' ) . '</a>';
		}
		if ( $opts['details'] ) {
			$html .= '<button type="button" class="button-link wpcs-details-toggle" aria-expanded="false" aria-controls="wpcs-details-' . esc_attr( (string) $id ) . '"><span class="dashicons dashicons-arrow-down-alt2" aria-hidden="true"></span><span class="wpcs-details-toggle__text">' . esc_html__( 'Details', 'wp-cyber-security' ) . '</span></button>';
		}
		$html .= '</div>';
		return $html;
	}

	/**
	 * Address of the changes view of an item.
	 *
	 * @param array  $item Item.
	 * @param string $from Tab to go back to ('' for the current one).
	 * @param array  $args Extra query args.
	 * @return string Unescaped URL.
	 */
	private function changes_url( array $item, $from = '', array $args = array() ) {
		return Admin::page_url(
			Admin::PAGE_REPORTS,
			array_merge(
				array(
					'view' => 'changes',
					'item' => (int) $item['id'],
					'from' => '' !== $from ? $from : $this->tab,
				),
				$args
			)
		);
	}

	/**
	 * Expanded details: hits with snippets, hashes, paths, request, install info.
	 *
	 * @param array $item    Item.
	 * @param array $details Details.
	 */
	private function render_details( array $item, array $details ) {
		$id   = (int) $item['id'];
		$hits = $this->hits( $details );
		$name = basename( (string) $item['path'] );

		echo '<div class="wpcs-details">';

		$button = Diff::view_button( $item, $this->has_held_copy( $item ) );
		if ( $button ) {
			$lazy = in_array( $item['type'], array( Store::TYPE_FILE, Store::TYPE_THREAT ), true );
			$text = 'changes' === $button['kind']
				? __( 'Changes: open the comparison to see exactly which lines changed.', 'wp-cyber-security' )
				: __( 'Read the file with the matched lines highlighted.', 'wp-cyber-security' );
			echo '<p class="wpcs-diff-summary"' . ( $lazy ? ' data-wpcs-diff-summary="' . esc_attr( (string) $id ) . '"' : '' ) . '><span class="dashicons dashicons-editor-code" aria-hidden="true"></span>'
				. '<span class="wpcs-diff-summary__text">' . esc_html( $text ) . '</span> '
				. '<a href="' . esc_url( $this->changes_url( $item ) ) . '">' . esc_html( 'changes' === $button['kind'] ? __( 'View changes', 'wp-cyber-security' ) : __( 'View code', 'wp-cyber-security' ) ) . '</a></p>';
		}

		if ( $hits ) {
			echo '<div class="wpcs-hits"><h4>' . esc_html(
				sprintf(
					/* translators: %s: number of matches */
					_n( '%s malware signature match', '%s malware signature matches', count( $hits ), 'wp-cyber-security' ),
					number_format_i18n( count( $hits ) )
				)
			) . '</h4><ol>';
			foreach ( array_slice( $hits, 0, 25 ) as $hit ) {
				$title   = ! empty( $hit['title'] ) ? (string) $hit['title'] : __( 'Suspicious code', 'wp-cyber-security' );
				$snippet = isset( $hit['snippet'] ) ? Diff::redact_snippet( (string) $hit['snippet'], ! empty( $hit['file'] ) ? basename( (string) $hit['file'] ) : $name ) : '';
				if ( strlen( $snippet ) > 600 ) {
					$snippet = ( function_exists( 'mb_substr' ) ? mb_substr( $snippet, 0, 600 ) : substr( $snippet, 0, 600 ) ) . ' ...';
				}
				echo '<li class="wpcs-hit"><div class="wpcs-hit__head">' . Admin::severity_badge( isset( $hit['severity'] ) ? (int) $hit['severity'] : 0 ) // phpcs:ignore WordPress.Security.EscapeOutput -- escaped in severity_badge().
					. ' <strong>' . esc_html( $title ) . '</strong>';
				if ( ! empty( $hit['file'] ) ) {
					// File inside a held plugin or theme package (install items).
					echo ' <code class="wpcs-hit__file" title="' . esc_attr__( 'File inside the package', 'wp-cyber-security' ) . '">' . esc_html( (string) $hit['file'] ) . '</code>';
				}
				if ( ! empty( $hit['line'] ) ) {
					/* translators: %s: line number */
					echo ' <span class="wpcs-muted">' . esc_html( sprintf( __( 'line %s', 'wp-cyber-security' ), number_format_i18n( (int) $hit['line'] ) ) ) . '</span>';
				}
				if ( ! empty( $hit['sig'] ) ) {
					echo ' <code class="wpcs-hit__sig">' . esc_html( (string) $hit['sig'] ) . '</code>';
				}
				echo '</div>';
				if ( '' !== $snippet ) {
					echo '<pre>' . esc_html( $snippet ) . '</pre>';
				}
				echo '</li>';
			}
			echo '</ol></div>';
		}

		$rows = array();
		if ( Store::TYPE_USER === $item['type'] ) {
			$user_id = User_Watch::item_user_id( $item );
			$edit    = $user_id ? get_edit_user_link( $user_id ) : '';
			$account = esc_html( User_Watch::item_login( $item ) . ' (#' . $user_id . ')' );
			$rows[ __( 'Account', 'wp-cyber-security' ) ] = $edit ? '<a href="' . esc_url( $edit ) . '">' . $account . '</a>' : $account;
			foreach (
				array(
					'user_email'   => __( 'Email', 'wp-cyber-security' ),
					'display_name' => __( 'Display name', 'wp-cyber-security' ),
				) as $key => $label
			) {
				if ( ! empty( $details[ $key ] ) ) {
					$rows[ $label ] = esc_html( (string) $details[ $key ] );
				}
			}
			if ( ! empty( $details['user_registered'] ) ) {
				$rows[ __( 'Registered', 'wp-cyber-security' ) ] = esc_html( Admin::datetime( Admin::utc_ts( (string) $details['user_registered'] ) ) );
			}
			$rows[ __( 'How', 'wp-cyber-security' ) ]        = esc_html( $this->admin_how( $details ) );
			$rows[ __( 'Granted by', 'wp-cyber-security' ) ] = esc_html( $this->admin_granted_by( $item, $details ) );
			if ( '' !== (string) $item['ip'] ) {
				$rows[ __( 'IP address', 'wp-cyber-security' ) ] = '<code>' . esc_html( (string) $item['ip'] ) . '</code>';
			}
			if ( ! empty( $details['roles'] ) && is_array( $details['roles'] ) ) {
				$rows[ __( 'Roles when reported', 'wp-cyber-security' ) ] = esc_html( implode( ', ', array_map( 'strval', $details['roles'] ) ) );
			}
		}
		if ( Db_Scanner::is_db_item( $item ) ) {
			$rows[ __( 'Location', 'wp-cyber-security' ) ] = $this->db_location_html( $item );
			if ( ! empty( $details['table'] ) ) {
				$rows[ __( 'Table and key', 'wp-cyber-security' ) ] = '<code>' . esc_html( (string) $details['table'] . ' / ' . ( isset( $details['key'] ) ? (string) $details['key'] : '' ) ) . '</code>';
			}
			$rows[ __( 'Fingerprint', 'wp-cyber-security' ) ] = '<code class="wpcs-hash-full">' . esc_html( (string) $item['sha256'] ) . '</code>';
		} elseif ( '' !== (string) $item['sha256'] ) {
			$rows[ __( 'SHA-256', 'wp-cyber-security' ) ] = '<code id="wpcs-sha-' . esc_attr( (string) $id ) . '" class="wpcs-hash-full">' . esc_html( (string) $item['sha256'] ) . '</code>'
				. ' <button type="button" class="button-link wpcs-copy-link" data-wpcs-copy="#wpcs-sha-' . esc_attr( (string) $id ) . '">' . esc_html__( 'Copy', 'wp-cyber-security' ) . '</button>';
		}
		if ( ! empty( $details['previous_sha256'] ) ) {
			$rows[ __( 'Previous SHA-256', 'wp-cyber-security' ) ] = '<code class="wpcs-hash-full">' . esc_html( (string) $details['previous_sha256'] ) . '</code>';
		}
		if ( '' !== (string) $item['original_path'] ) {
			$rows[ __( 'Location', 'wp-cyber-security' ) ] = '<span class="wpcs-path">' . esc_html( (string) $item['original_path'] ) . '</span>';
		} elseif ( Store::TYPE_UPLOAD === $item['type'] ) {
			$rows[ __( 'Original name', 'wp-cyber-security' ) ] = '<span class="wpcs-path">' . esc_html( (string) $item['path'] ) . '</span>';
		}
		if ( $this->has_held_copy( $item ) ) {
			$rows[ __( 'Held copy', 'wp-cyber-security' ) ] = '<span class="wpcs-path">' . esc_html( (string) $item['quarantine_path'] ) . '</span>';
		}
		if ( Store::TYPE_INSTALL === $item['type'] ) {
			$parts = array();
			foreach ( array( 'name', 'version', 'slug' ) as $key ) {
				if ( ! empty( $details[ $key ] ) ) {
					$parts[] = (string) $details[ $key ];
				}
			}
			$parts[] = $this->install_context( $details );
			$rows[ __( 'Install', 'wp-cyber-security' ) ] = esc_html( implode( ', ', $parts ) );
		}
		if ( ! empty( $details['request_uri'] ) ) {
			$rows[ __( 'Request', 'wp-cyber-security' ) ] = '<span class="wpcs-path">' . esc_html( (string) $details['request_uri'] ) . '</span>';
		}
		if ( ! empty( $details['script'] ) ) {
			$rows[ __( 'Receiving script', 'wp-cyber-security' ) ] = '<span class="wpcs-path">' . esc_html( (string) $details['script'] ) . '</span>';
		}
		if ( ! empty( $details['field'] ) ) {
			$rows[ __( 'Form field', 'wp-cyber-security' ) ] = '<code>' . esc_html( (string) $details['field'] ) . '</code>';
		}
		if ( ! empty( $details['post_id'] ) ) {
			$post_id = (int) $details['post_id'];
			$link    = get_edit_post_link( $post_id );
			$title   = get_the_title( $post_id );
			/* translators: %d: post id */
			$text = '' !== (string) $title ? $title : sprintf( __( 'Post #%d', 'wp-cyber-security' ), $post_id );
			$rows[ __( 'Attach to', 'wp-cyber-security' ) ] = $link ? '<a href="' . esc_url( $link ) . '">' . esc_html( $text ) . '</a>' : esc_html( $text );
		}
		if ( ! empty( $details['attachment_id'] ) ) {
			$link = get_edit_post_link( (int) $details['attachment_id'] );
			if ( $link ) {
				$rows[ __( 'Media Library', 'wp-cyber-security' ) ] = '<a href="' . esc_url( $link ) . '">' . esc_html__( 'View the imported file', 'wp-cyber-security' ) . '</a>';
			}
		}
		if ( ! empty( $details['verified'] ) ) {
			$sources  = array(
				'core'   => __( 'WordPress core', 'wp-cyber-security' ),
				'plugin' => __( 'wordpress.org plugin', 'wp-cyber-security' ),
				'self'   => __( 'This plugin (checksums.json)', 'wp-cyber-security' ),
			);
			$verified = array();
			foreach ( (array) $details['verified'] as $source ) {
				$verified[] = isset( $sources[ (string) $source ] ) ? $sources[ (string) $source ] : (string) $source;
			}
			$verified = implode( ', ', $verified );
			$rows[ __( 'Official checksum', 'wp-cyber-security' ) ] = esc_html( $verified );
		}
		if ( Store::STATUS_PENDING !== $item['status'] ) {
			$decided = Admin::utc_ts( isset( $item['decided_at'] ) ? $item['decided_at'] : '' );
			$user    = Admin::user_name( isset( $item['decided_by'] ) ? $item['decided_by'] : 0 );
			$text    = trim( wp_strip_all_tags( Admin::status_badge( $item['status'] ) ) );
			if ( '' !== $user ) {
				/* translators: %s: user display name */
				$text .= ' ' . sprintf( __( 'by %s', 'wp-cyber-security' ), $user );
			}
			if ( $decided ) {
				$text .= ', ' . Admin::datetime( $decided );
			}
			$rows[ __( 'Decision', 'wp-cyber-security' ) ] = esc_html( $text );
		}
		if ( Store::STATUS_APPROVED === $item['status'] && ! empty( $details['approval_note'] ) ) {
			// What the admin still has to do after approving (for example upload the ZIP again).
			$rows[ __( 'Next step', 'wp-cyber-security' ) ] = esc_html( (string) $details['approval_note'] );
		}
		$rows[ __( 'Item', 'wp-cyber-security' ) ] = esc_html( '#' . $id );

		echo '<dl class="wpcs-details__grid">';
		foreach ( $rows as $label => $value ) {
			echo '<div><dt>' . esc_html( $label ) . '</dt><dd>' . wp_kses( $value, $this->details_kses() ) . '</dd></div>';
		}
		echo '</dl></div>';
	}

	/* ------------------------------------------------------------------ */
	/* Changes view (view=changes&item=<id>)                               */
	/* ------------------------------------------------------------------ */

	/**
	 * What changed in a reported file: the item, every malware match, and a
	 * line by line comparison with the last trusted or the official version
	 * (or the full content when there is nothing to compare with).
	 */
	private function render_changes() {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only view.
		$id     = isset( $_GET['item'] ) ? absint( wp_unslash( $_GET['item'] ) ) : 0;
		$layout = isset( $_GET['layout'] ) ? sanitize_key( wp_unslash( $_GET['layout'] ) ) : '';
		$from   = isset( $_GET['from'] ) ? sanitize_key( wp_unslash( $_GET['from'] ) ) : '';
		// phpcs:enable

		$user_id = get_current_user_id();
		if ( in_array( $layout, array( 'unified', 'split' ), true ) ) {
			if ( get_user_meta( $user_id, self::META_LAYOUT, true ) !== $layout ) {
				update_user_meta( $user_id, self::META_LAYOUT, $layout );
			}
		} else {
			$layout = 'split' === get_user_meta( $user_id, self::META_LAYOUT, true ) ? 'split' : 'unified';
		}

		$item = $id ? Admin::call( 'store', 'item_get', array( $id ), null ) : null;
		$item = is_array( $item ) && ! empty( $item['id'] ) ? $item : null;

		$tabs = $this->tabs();
		if ( ! isset( $tabs[ $from ] ) || in_array( $from, array( 'allowlist', 'activity' ), true ) ) {
			$from = $item ? $this->tab_for( $item ) : 'pending';
		}
		$back = '<a class="button" href="' . esc_url( Admin::page_url( Admin::PAGE_REPORTS, array( 'tab' => $from ) ) ) . '"><span class="dashicons dashicons-arrow-left-alt" aria-hidden="true"></span> '
			/* translators: %s: name of a Reports tab, such as Threats */
			. esc_html( sprintf( __( 'Back to %s', 'wp-cyber-security' ), $tabs[ $from ][0] ) ) . '</a>';

		echo '<div class="wrap wpcs-wrap wpcs-reports wpcs-changes" data-wpcs-changes>';
		if ( ! $item ) {
			Admin::header( __( 'Changes', 'wp-cyber-security' ), '', $back );
			$this->empty_state(
				'search',
				__( 'Report not found', 'wp-cyber-security' ),
				__( 'This report no longer exists, so there is nothing to show.', 'wp-cyber-security' ),
				'<a class="button" href="' . esc_url( Admin::page_url( Admin::PAGE_REPORTS, array( 'tab' => $from ) ) ) . '">' . esc_html__( 'Back to the reports', 'wp-cyber-security' ) . '</a>'
			);
			echo '</div>';
			return;
		}

		$held   = $this->has_held_copy( $item );
		$button = Diff::view_button( $item, $held );
		try {
			$result = Diff::for_item( $item, array( 'layout' => $layout ) );
		} catch ( \Throwable $e ) {
			Admin::debug_log( $e );
			$result = array(
				'mode'          => 'unavailable',
				'reason'        => 'error',
				'reason_text'   => __( 'The file could not be compared because of an unexpected error. Try again in a moment.', 'wp-cyber-security' ),
				'base_label'    => '',
				'current_label' => '',
				'added'         => 0,
				'removed'       => 0,
				'html'          => '',
				'notes'         => array(),
				'hit_lines'     => array(),
				'layout'        => $layout,
			);
		}

		Admin::header(
			$button && 'changes' === $button['kind'] ? __( 'What changed', 'wp-cyber-security' ) : __( 'File contents', 'wp-cyber-security' ),
			(string) $item['path'],
			$back
		);
		$this->render_result_notice();

		// No-JS fallback target of the decision buttons (core.js sends them through AJAX).
		echo '<form id="' . esc_attr( self::FORM_ID ) . '" method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="wpcybersec_reports_bulk"><input type="hidden" name="tab" value="' . esc_attr( $from ) . '">';
		wp_nonce_field( 'wpcybersec_reports_bulk' );
		echo '</form>';

		$this->render_change_item( $item, $held );
		$this->render_change_hits( $item, $result );
		$this->render_change_diff( $item, $result, $from );
		echo '</div>';
	}

	/**
	 * Reports tab an item belongs to.
	 *
	 * @param array $item Item.
	 * @return string
	 */
	private function tab_for( array $item ) {
		if ( Store::STATUS_PENDING === $item['status'] ) {
			return Store::TYPE_THREAT === $item['type'] ? 'threats' : 'pending';
		}
		return Store::STATUS_QUARANTINED === $item['status'] ? 'quarantine' : 'history';
	}

	/**
	 * Summary card: what the file is, its state, and the decision buttons.
	 *
	 * @param array $item Item.
	 * @param bool  $held Held copy exists.
	 */
	private function render_change_item( array $item, $held ) {
		$details   = isset( $item['details'] ) && is_array( $item['details'] ) ? $item['details'] : array();
		$available = Decisions::available( $item );
		$hits      = $this->hits( $details );
		$severity  = (int) $item['severity'];
		$ts        = Admin::utc_ts( $item['created_at'] );

		echo '<section class="wpcs-card wpcs-change-item wpcs-sev-' . esc_attr( (string) $severity ) . '" data-item-id="' . esc_attr( (string) $item['id'] ) . '" data-held="' . ( $held ? '1' : '0' ) . '">';
		echo '<div class="wpcs-change-item__badges">' . $this->type_badge( (string) $item['type'], $item ); // phpcs:ignore WordPress.Security.EscapeOutput -- built with escaping.
		if ( Store::TYPE_THREAT === $item['type'] || $hits ) {
			echo Admin::severity_badge( $severity ); // phpcs:ignore WordPress.Security.EscapeOutput -- escaped in severity_badge().
		}
		if ( ! empty( $details['change'] ) ) {
			echo 'modified' === $details['change']
				? '<span class="wpcs-chip wpcs-chip--warn">' . esc_html__( 'modified', 'wp-cyber-security' ) . '</span>'
				: '<span class="wpcs-chip">' . esc_html__( 'new', 'wp-cyber-security' ) . '</span>';
		}
		if ( isset( $details['checksum'] ) && 'mismatch' === $details['checksum'] ) {
			echo '<span class="wpcs-chip wpcs-chip--warn">' . esc_html__( 'differs from the official file', 'wp-cyber-security' ) . '</span>';
		}
		echo '</div>';
		echo '<h2 class="wpcs-change-item__path">' . $this->path_html( (string) $item['path'] ) . '</h2>'; // phpcs:ignore WordPress.Security.EscapeOutput -- built with escaping.

		list( $who, $context ) = $this->source_parts( $item, $details );
		$facts = array(
			__( 'Status', 'wp-cyber-security' )   => '<span data-wpcs-status>' . $this->status_cell( $item, $held ) . '</span>',
			__( 'Detected', 'wp-cyber-security' ) => '<span title="' . esc_attr( Admin::datetime( $ts ) ) . '">' . esc_html( Admin::ago( $ts ) ) . '</span><span class="wpcs-sub">' . esc_html( Admin::datetime( $ts ) ) . '</span>',
			__( 'Found by', 'wp-cyber-security' ) => esc_html( $who ) . '<span class="wpcs-sub">' . esc_html( $context ) . '</span>',
		);
		if ( (int) $item['size'] > 0 ) {
			$facts[ __( 'Size', 'wp-cyber-security' ) ] = esc_html( size_format( (int) $item['size'], (int) $item['size'] >= KB_IN_BYTES ? 1 : 0 ) );
		}
		if ( '' !== (string) $item['sha256'] ) {
			$facts[ __( 'SHA-256', 'wp-cyber-security' ) ] = $this->short_hash( (string) $item['sha256'] );
		}
		if ( ! empty( $details['previous_sha256'] ) ) {
			$facts[ __( 'Previous SHA-256', 'wp-cyber-security' ) ] = $this->short_hash( (string) $details['previous_sha256'] );
		}
		echo '<dl class="wpcs-change-item__facts">';
		foreach ( $facts as $label => $value ) {
			echo '<div><dt>' . esc_html( $label ) . '</dt><dd>' . $value . '</dd></div>'; // phpcs:ignore WordPress.Security.EscapeOutput -- built with escaping.
		}
		echo '</dl>';

		echo '<div class="wpcs-change-item__actions">' . $this->actions_cell( $item, $available, $held, array( 'details' => false, 'changes' => false ) ) . '</div>'; // phpcs:ignore WordPress.Security.EscapeOutput -- built with escaping.
		echo '</section>';
	}

	/**
	 * Every malware match, each linked to its line below.
	 *
	 * @param array $item   Item.
	 * @param array $result Diff::for_item() result.
	 */
	private function render_change_hits( array $item, array $result ) {
		$details = isset( $item['details'] ) && is_array( $item['details'] ) ? $item['details'] : array();
		$hits    = $this->hits( $details );
		if ( ! $hits ) {
			return;
		}
		$name  = basename( (string) $item['path'] );
		$count = count( $hits );
		$html  = isset( $result['html'] ) ? (string) $result['html'] : '';

		echo '<section class="wpcs-card wpcs-change-hits">';
		echo '<h2 class="wpcs-card__title"><span class="dashicons dashicons-warning" aria-hidden="true"></span>' . esc_html(
			sprintf(
				/* translators: %s: number of matches */
				_n( '%s malware signature match', '%s malware signature matches', $count, 'wp-cyber-security' ),
				number_format_i18n( $count )
			)
		) . '</h2>';
		echo '<ol class="wpcs-hitlist">';
		foreach ( $hits as $i => $hit ) {
			if ( self::HITS_VISIBLE === $i && $count > self::HITS_VISIBLE + 1 ) {
				echo '</ol><details class="wpcs-more-hits"><summary>' . esc_html(
					sprintf(
						/* translators: %s: number of matches */
						_n( 'Show %s more match', 'Show %s more matches', $count - self::HITS_VISIBLE, 'wp-cyber-security' ),
						number_format_i18n( $count - self::HITS_VISIBLE )
					)
				) . '</summary><ol class="wpcs-hitlist" start="' . esc_attr( (string) ( self::HITS_VISIBLE + 1 ) ) . '">';
			}
			$title = ! empty( $hit['title'] ) ? (string) $hit['title'] : __( 'Suspicious code', 'wp-cyber-security' );
			$line  = isset( $hit['line'] ) ? (int) $hit['line'] : 0;
			$code  = $this->hit_code( $hit, $line, $result, ! empty( $hit['file'] ) ? basename( (string) $hit['file'] ) : $name );

			echo '<li class="wpcs-hit"><div class="wpcs-hit__head">' . Admin::severity_badge( isset( $hit['severity'] ) ? (int) $hit['severity'] : 0 ) // phpcs:ignore WordPress.Security.EscapeOutput -- escaped in severity_badge().
				. ' <strong>' . esc_html( $title ) . '</strong>';
			if ( $line > 0 ) {
				/* translators: %s: line number */
				$text = sprintf( __( 'line %s', 'wp-cyber-security' ), number_format_i18n( $line ) );
				if ( false !== strpos( $html, ' id="L' . $line . '"' ) ) {
					echo ' <a class="wpcs-hit__line" href="#L' . esc_attr( (string) $line ) . '">' . esc_html( $text ) . '</a>';
				} else {
					echo ' <span class="wpcs-muted">' . esc_html( $text ) . '</span>';
				}
			}
			if ( ! empty( $hit['file'] ) ) {
				echo ' <code class="wpcs-hit__file">' . esc_html( (string) $hit['file'] ) . '</code>';
			}
			if ( ! empty( $hit['sig'] ) ) {
				echo ' <code class="wpcs-hit__sig">' . esc_html( (string) $hit['sig'] ) . '</code>';
			}
			echo '</div>';
			if ( '' !== $code ) {
				echo '<pre class="wpcs-hit__code">' . esc_html( $code ) . '</pre>';
			}
			echo '</li>';
		}
		echo '</ol>';
		if ( $count > self::HITS_VISIBLE + 1 ) {
			echo '</details>';
		}
		echo '</section>';
	}

	/**
	 * Code to show for one match: the redacted line from the file when it is
	 * known (a window around the match for very long lines), else the stored
	 * snippet, redacted.
	 *
	 * @param array  $hit    Hit.
	 * @param int    $line   Line number.
	 * @param array  $result Diff::for_item() result.
	 * @param string $name   File name.
	 * @return string Plain text.
	 */
	private function hit_code( array $hit, $line, array $result, $name ) {
		$snippet = isset( $hit['snippet'] ) ? trim( (string) $hit['snippet'] ) : '';
		if ( $line > 0 && isset( $result['hit_lines'][ $line ] ) ) {
			$text = (string) $result['hit_lines'][ $line ];
			if ( strlen( $text ) <= 600 ) {
				return trim( $text );
			}
			$pos   = '' !== $snippet ? strpos( $text, substr( $snippet, 0, 40 ) ) : false;
			$start = false === $pos ? 0 : max( 0, $pos - 120 );
			$part  = function_exists( 'mb_strcut' ) ? mb_strcut( $text, $start, 600, 'UTF-8' ) : substr( $text, $start, 600 );
			return ( $start > 0 ? '... ' : '' ) . $part . ' ...';
		}
		if ( '' === $snippet ) {
			return '';
		}
		$snippet = Diff::redact_snippet( $snippet, $name );
		if ( strlen( $snippet ) > 600 ) {
			$snippet = ( function_exists( 'mb_substr' ) ? mb_substr( $snippet, 0, 600 ) : substr( $snippet, 0, 600 ) ) . ' ...';
		}
		return $snippet;
	}

	/**
	 * The comparison (or the content, or why neither can be shown).
	 *
	 * @param array  $item   Item.
	 * @param array  $result Diff::for_item() result.
	 * @param string $from   Tab to go back to.
	 */
	private function render_change_diff( array $item, array $result, $from ) {
		$mode   = (string) $result['mode'];
		$layout = isset( $result['layout'] ) && 'split' === $result['layout'] ? 'split' : 'unified';

		echo '<section class="wpcs-card wpcs-diff-card" id="wpcs-diff">';
		echo '<div class="wpcs-diff-head"><div class="wpcs-diff-head__text">';
		if ( 'diff' === $mode ) {
			echo '<h2 class="wpcs-card__title"><span class="dashicons dashicons-editor-code" aria-hidden="true"></span>' . esc_html__( 'Line by line', 'wp-cyber-security' )
				. ' <span class="wpcs-diffstat" title="' . esc_attr__( 'Lines added and removed', 'wp-cyber-security' ) . '">'
				. '<span class="wpcs-diffstat__add">+' . esc_html( number_format_i18n( (int) $result['added'] ) ) . '</span>'
				. '<span class="wpcs-diffstat__del">-' . esc_html( number_format_i18n( (int) $result['removed'] ) ) . '</span></span></h2>';
			echo '<p class="wpcs-diff-head__compare"><span class="wpcs-diff-head__base">' . esc_html( (string) $result['base_label'] ) . '</span>'
				. '<span class="dashicons dashicons-arrow-right-alt" aria-hidden="true"></span><span class="screen-reader-text">' . esc_html__( 'compared with', 'wp-cyber-security' ) . '</span>'
				. '<span class="wpcs-diff-head__current">' . esc_html( (string) $result['current_label'] ) . '</span></p>';
		} elseif ( 'content' === $mode ) {
			echo '<h2 class="wpcs-card__title"><span class="dashicons dashicons-media-code" aria-hidden="true"></span>' . esc_html__( 'Full content', 'wp-cyber-security' ) . '</h2>';
			if ( '' !== (string) $result['current_label'] ) {
				echo '<p class="wpcs-diff-head__compare"><span class="wpcs-diff-head__current">' . esc_html( (string) $result['current_label'] ) . '</span></p>';
			}
		} else {
			echo '<h2 class="wpcs-card__title"><span class="dashicons dashicons-media-code" aria-hidden="true"></span>' . esc_html__( 'Nothing to show', 'wp-cyber-security' ) . '</h2>';
		}
		echo '</div>';

		if ( 'diff' === $mode && (int) $result['added'] + (int) $result['removed'] > 0 ) {
			echo '<div class="wpcs-segmented" role="group" aria-label="' . esc_attr__( 'Layout', 'wp-cyber-security' ) . '">';
			foreach ( array(
				'unified' => __( 'Unified', 'wp-cyber-security' ),
				'split'   => __( 'Split', 'wp-cyber-security' ),
			) as $value => $label ) {
				$url = $this->changes_url( $item, $from, array( 'layout' => $value ) ) . '#wpcs-diff';
				echo '<a class="button button-small' . ( $value === $layout ? ' button-primary is-active' : '' ) . '" href="' . esc_url( $url ) . '"' . ( $value === $layout ? ' aria-current="true"' : '' ) . '>' . esc_html( $label ) . '</a>';
			}
			echo '</div>';
		}
		echo '</div>';

		if ( 'content' === $mode && '' !== (string) $result['reason_text'] ) {
			$this->notice( 'info', 'info-outline', (string) $result['reason_text'] );
		}
		foreach ( isset( $result['notes'] ) ? (array) $result['notes'] : array() as $note ) {
			$tone = isset( $note[0] ) ? (string) $note[0] : 'info';
			$icon = 'warn' === $tone ? 'warning' : ( 'ok' === $tone ? 'yes-alt' : 'info-outline' );
			$this->notice( $tone, $icon, isset( $note[1] ) ? (string) $note[1] : '' );
		}

		if ( 'unavailable' === $mode ) {
			echo '<div class="wpcs-empty wpcs-empty--compact"><span class="dashicons dashicons-media-code" aria-hidden="true"></span><p>' . esc_html( (string) $result['reason_text'] ) . '</p></div>';
		} elseif ( '' !== (string) $result['html'] ) {
			// Built by Diff with every line passed through esc_html().
			echo '<div class="wpcs-diff-body">' . $result['html'] . '</div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		}
		echo '</section>';
	}

	/**
	 * @return array
	 */
	private function details_kses() {
		return array(
			'a'      => array( 'href' => true, 'class' => true ),
			'code'   => array( 'id' => true, 'class' => true ),
			'span'   => array( 'class' => true, 'title' => true ),
			'strong' => array( 'class' => true ),
			'button' => array( 'type' => true, 'class' => true, 'data-wpcs-copy' => true ),
		);
	}

	/**
	 * Empty state for item tabs.
	 */
	private function render_items_empty() {
		if ( '' !== $this->search || $this->filters['type'] || $this->filters['severity'] ) {
			$this->empty_state(
				'search',
				__( 'No matching items', 'wp-cyber-security' ),
				__( 'Nothing matches the current search or filter.', 'wp-cyber-security' ),
				'<a class="button" href="' . esc_url( Admin::page_url( Admin::PAGE_REPORTS, array( 'tab' => $this->tab ) ) ) . '">' . esc_html__( 'Show everything', 'wp-cyber-security' ) . '</a>'
			);
			return;
		}
		$dashboard = '<a class="button" href="' . esc_url( Admin::page_url( Admin::PAGE_DASHBOARD ) ) . '">' . esc_html__( 'Go to the dashboard', 'wp-cyber-security' ) . '</a>';
		switch ( $this->tab ) {
			case 'threats':
				$this->empty_state( 'shield', __( 'No threats found', 'wp-cyber-security' ), __( 'No file currently matches a malware signature. Run a full malware scan from the dashboard any time.', 'wp-cyber-security' ), $dashboard );
				break;
			case 'quarantine':
				$this->empty_state( 'lock', __( 'Quarantine is empty', 'wp-cyber-security' ), __( 'Held uploads and quarantined files appear here. They are stored where they cannot run.', 'wp-cyber-security' ) );
				break;
			case 'history':
				$this->empty_state( 'backup', __( 'No decisions yet', 'wp-cyber-security' ), __( 'When you allow, deny or quarantine something, the decision is recorded here.', 'wp-cyber-security' ) );
				break;
			default:
				$this->empty_state( 'yes-alt', __( 'Nothing waiting for approval', 'wp-cyber-security' ), __( 'New uploads, plugin or theme installs and unknown files appear here until you allow or deny them.', 'wp-cyber-security' ) );
		}
	}

	/**
	 * Empty state card.
	 *
	 * @param string $icon        Dashicon name.
	 * @param string $title       Title.
	 * @param string $text        Text.
	 * @param string $action_html Escaped button HTML.
	 */
	private function empty_state( $icon, $title, $text, $action_html = '' ) {
		echo '<div class="wpcs-card wpcs-empty-card"><div class="wpcs-empty"><span class="dashicons dashicons-' . esc_attr( $icon ) . '" aria-hidden="true"></span>';
		echo '<h3>' . esc_html( $title ) . '</h3><p>' . esc_html( $text ) . '</p>';
		if ( '' !== $action_html ) {
			echo '<p>' . wp_kses( $action_html, array( 'a' => array( 'class' => true, 'href' => true ) ) ) . '</p>';
		}
		echo '</div></div>';
	}

	/**
	 * Count + page links.
	 *
	 * @param int $total    Total rows.
	 * @param int $per_page Rows per page.
	 */
	private function render_pagination( $total, $per_page ) {
		$per_page = max( 1, (int) $per_page );
		$pages    = (int) ceil( $total / $per_page );
		echo '<div class="wpcs-tablenav"><span class="wpcs-muted">' . esc_html(
			sprintf(
				/* translators: %s: number of items */
				_n( '%s item', '%s items', $total, 'wp-cyber-security' ),
				number_format_i18n( $total )
			)
		) . '</span>';
		if ( $pages > 1 ) {
			$links = paginate_links(
				array(
					'base'      => add_query_arg( 'paged', '%#%', $this->view_url() ),
					'format'    => '',
					'current'   => min( $this->paged, $pages ),
					'total'     => $pages,
					'prev_text' => '<span aria-hidden="true">&lsaquo;</span><span class="screen-reader-text">' . esc_html__( 'Previous page', 'wp-cyber-security' ) . '</span>',
					'next_text' => '<span aria-hidden="true">&rsaquo;</span><span class="screen-reader-text">' . esc_html__( 'Next page', 'wp-cyber-security' ) . '</span>',
					'mid_size'  => 1,
				)
			);
			echo '<nav class="wpcs-pagination" aria-label="' . esc_attr__( 'Pages', 'wp-cyber-security' ) . '">' . wp_kses_post( (string) $links ) . '</nav>';
		}
		echo '</div>';
	}

	/* ------------------------------------------------------------------ */
	/* Allowlist tab                                                       */
	/* ------------------------------------------------------------------ */

	/**
	 * Allowlist entries with Remove.
	 */
	private function render_allowlist_tab() {
		echo '<div class="wpcs-notice"><span class="dashicons dashicons-yes-alt" aria-hidden="true"></span><div><p><strong>'
			. esc_html__( 'Everything you allowed, remembered permanently.', 'wp-cyber-security' ) . '</strong> '
			. esc_html__( 'File fingerprints (SHA-256) pass wherever the same file shows up again; plugin and theme entries let that install through; database entries stop one exact value at one place (an option or a post) from being reported. Removing an entry does not delete anything: it only means the file, install or value is reported again the next time it is found.', 'wp-cyber-security' )
			. '</p></div></div>';

		$per_page = 50;
		$result   = Admin::call(
			'allowlist',
			'query',
			array(
				array(
					'kind'     => $this->filters['kind'],
					'search'   => $this->search,
					'per_page' => $per_page,
					'page'     => $this->paged,
				),
			),
			null
		);
		if ( ! is_array( $result ) ) {
			$this->notice( 'bad', 'warning', __( 'The allowlist could not be loaded.', 'wp-cyber-security' ) );
			return;
		}
		$rows  = isset( $result['rows'] ) ? (array) $result['rows'] : array();
		$total = isset( $result['total'] ) ? (int) $result['total'] : 0;

		echo '<div class="wpcs-toolbar"><div></div>';
		echo '<form class="wpcs-filters" method="get" action="' . esc_url( admin_url( 'admin.php' ) ) . '">';
		echo '<input type="hidden" name="page" value="' . esc_attr( Admin::PAGE_REPORTS ) . '"><input type="hidden" name="tab" value="allowlist">';
		$this->select(
			'kind',
			$this->filters['kind'],
			array(
				''        => __( 'All entries', 'wp-cyber-security' ),
				'hash'    => __( 'File fingerprints', 'wp-cyber-security' ),
				'install' => __( 'Plugins and themes', 'wp-cyber-security' ),
				'db'      => __( 'Database values', 'wp-cyber-security' ),
			),
			__( 'Filter by kind', 'wp-cyber-security' )
		);
		$this->search_box( __( 'Search name or hash', 'wp-cyber-security' ) );
		echo '</form></div>';

		if ( ! $rows ) {
			if ( '' !== $this->search || $this->filters['kind'] ) {
				$this->empty_state( 'search', __( 'No matching entries', 'wp-cyber-security' ), __( 'Nothing on the allowlist matches the current search or filter.', 'wp-cyber-security' ), '<a class="button" href="' . esc_url( Admin::page_url( Admin::PAGE_REPORTS, array( 'tab' => 'allowlist' ) ) ) . '">' . esc_html__( 'Show everything', 'wp-cyber-security' ) . '</a>' );
			} else {
				$this->empty_state( 'yes-alt', __( 'The allowlist is empty', 'wp-cyber-security' ), __( 'When you allow a file, its SHA-256 fingerprint is remembered here so the same file is never held again.', 'wp-cyber-security' ) );
			}
			return;
		}

		echo '<div class="wpcs-card wpcs-card--flush wpcs-table-card"><table class="widefat wpcs-table wpcs-allowlist">';
		echo '<thead><tr>';
		foreach ( array(
			'kind'   => __( 'Kind', 'wp-cyber-security' ),
			'label'  => __( 'Name', 'wp-cyber-security' ),
			'value'  => __( 'Fingerprint or install', 'wp-cyber-security' ),
			'by'     => __( 'Added by', 'wp-cyber-security' ),
			'when'   => __( 'Added', 'wp-cyber-security' ),
			'note'   => __( 'Note', 'wp-cyber-security' ),
			'remove' => '<span class="screen-reader-text">' . esc_html__( 'Actions', 'wp-cyber-security' ) . '</span>',
		) as $key => $label ) {
			echo '<th scope="col" class="column-' . esc_attr( $key ) . '">' . wp_kses( $label, array( 'span' => array( 'class' => true ) ) ) . '</th>';
		}
		echo '</tr></thead><tbody>';

		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) || empty( $row['id'] ) ) {
				continue;
			}
			$entry_id = (int) $row['id'];
			$kind     = isset( $row['kind'] ) ? (string) $row['kind'] : '';
			$value    = isset( $row['value'] ) ? (string) $row['value'] : '';
			$label    = isset( $row['label'] ) && '' !== (string) $row['label'] ? (string) $row['label'] : $value;
			$ts       = Admin::utc_ts( isset( $row['created_at'] ) ? $row['created_at'] : '' );
			$by       = Admin::user_name( isset( $row['created_by'] ) ? $row['created_by'] : 0 );

			if ( 'db' === $kind ) {
				$badge   = '<span class="wpcs-badge wpcs-type wpcs-type--database"><span class="dashicons dashicons-database" aria-hidden="true"></span>' . esc_html__( 'Database', 'wp-cyber-security' ) . '</span>';
				$value_h = $this->short_hash( $value );
			} elseif ( 'install' === $kind ) {
				$is_theme = 0 === strpos( $value, 'theme:' );
				$badge    = '<span class="wpcs-badge wpcs-type wpcs-type--install"><span class="dashicons dashicons-' . ( $is_theme ? 'admin-appearance' : 'admin-plugins' ) . '" aria-hidden="true"></span>' . esc_html( $is_theme ? __( 'Theme', 'wp-cyber-security' ) : __( 'Plugin', 'wp-cyber-security' ) ) . '</span>';
				$value_h  = '<code class="wpcs-mono">' . esc_html( $value ) . '</code>';
			} else {
				$badge   = '<span class="wpcs-badge wpcs-type wpcs-type--hash"><span class="dashicons dashicons-media-default" aria-hidden="true"></span>' . esc_html__( 'File', 'wp-cyber-security' ) . '</span>';
				$value_h = $this->short_hash( $value );
			}

			$remove = wp_nonce_url(
				add_query_arg(
					array(
						'action' => 'wpcybersec_allowlist_remove',
						'entry'  => $entry_id,
					),
					admin_url( 'admin-post.php' )
				),
				'wpcybersec_allowlist_remove_' . $entry_id
			);
			/* translators: %s: entry name */
			$confirm = sprintf( __( 'Remove "%s" from the allowlist? No file is deleted, but the next time it appears it is held for your approval again.', 'wp-cyber-security' ), $label );

			echo '<tr>';
			echo '<td class="column-kind">' . $badge . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput -- built with escaping.
			echo '<td class="column-label"><span class="wpcs-path">' . esc_html( $label ) . '</span></td>';
			echo '<td class="column-value">' . $value_h . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput -- built with escaping.
			echo '<td class="column-by">' . esc_html( '' !== $by ? $by : __( 'System', 'wp-cyber-security' ) ) . '</td>';
			echo '<td class="column-when"><span title="' . esc_attr( Admin::datetime( $ts ) ) . '">' . esc_html( Admin::ago( $ts ) ) . '</span></td>';
			echo '<td class="column-note"><span class="wpcs-sub">' . esc_html( isset( $row['note'] ) ? (string) $row['note'] : '' ) . '</span></td>';
			echo '<td class="column-remove"><a class="button button-small wpcs-btn-danger" href="' . esc_url( $remove ) . '" data-wpcs-confirm="' . esc_attr( $confirm ) . '"><span class="dashicons dashicons-minus" aria-hidden="true"></span>' . esc_html__( 'Remove', 'wp-cyber-security' ) . '</a></td>';
			echo '</tr>';
		}
		echo '</tbody></table></div>';

		$this->render_pagination( $total, $per_page );
	}

	/* ------------------------------------------------------------------ */
	/* Activity tab                                                        */
	/* ------------------------------------------------------------------ */

	/**
	 * Activity log with event filter.
	 */
	private function render_activity_tab() {
		$per_page = 50;
		$result   = Admin::call(
			'store',
			'log_query',
			array(
				array(
					'event'    => $this->filters['event'],
					'search'   => $this->search,
					'per_page' => $per_page,
					'page'     => $this->paged,
				),
			),
			null
		);
		if ( ! is_array( $result ) ) {
			$this->notice( 'bad', 'warning', __( 'The activity log could not be loaded.', 'wp-cyber-security' ) );
			return;
		}
		$rows  = isset( $result['rows'] ) ? (array) $result['rows'] : array();
		$total = isset( $result['total'] ) ? (int) $result['total'] : 0;

		$retention = (int) Admin::setting( 'log_retention_days', 90 );
		echo '<p class="wpcs-muted wpcs-tab-hint">' . esc_html(
			$retention > 0
				/* translators: %s: number of days */
				? sprintf( _n( 'Everything the plugin did or was asked to do. Entries are kept for %s day.', 'Everything the plugin did or was asked to do. Entries are kept for %s days.', $retention, 'wp-cyber-security' ), number_format_i18n( $retention ) )
				: __( 'Everything the plugin did or was asked to do. Entries are kept until you delete the plugin data.', 'wp-cyber-security' )
		) . '</p>';

		$options = array( '' => __( 'All events', 'wp-cyber-security' ) );
		foreach ( $this->log_events() as $event ) {
			$meta              = Admin::event_meta( $event );
			$options[ $event ] = $meta['label'];
		}
		if ( $this->filters['event'] && ! isset( $options[ $this->filters['event'] ] ) ) {
			$meta                                = Admin::event_meta( $this->filters['event'] );
			$options[ $this->filters['event'] ] = $meta['label'];
		}

		echo '<div class="wpcs-toolbar"><div></div>';
		echo '<form class="wpcs-filters" method="get" action="' . esc_url( admin_url( 'admin.php' ) ) . '">';
		echo '<input type="hidden" name="page" value="' . esc_attr( Admin::PAGE_REPORTS ) . '"><input type="hidden" name="tab" value="activity">';
		$this->select( 'event', $this->filters['event'], $options, __( 'Filter by event', 'wp-cyber-security' ) );
		$this->search_box( __( 'Search messages', 'wp-cyber-security' ) );
		echo '</form></div>';

		if ( ! $rows ) {
			if ( '' !== $this->search || $this->filters['event'] ) {
				$this->empty_state( 'search', __( 'No matching activity', 'wp-cyber-security' ), __( 'Nothing in the log matches the current search or filter.', 'wp-cyber-security' ), '<a class="button" href="' . esc_url( Admin::page_url( Admin::PAGE_REPORTS, array( 'tab' => 'activity' ) ) ) . '">' . esc_html__( 'Show everything', 'wp-cyber-security' ) . '</a>' );
			} else {
				$this->empty_state( 'list-view', __( 'No activity recorded yet', 'wp-cyber-security' ), __( 'Held uploads, decisions, scans and setting changes are recorded here.', 'wp-cyber-security' ) );
			}
			return;
		}

		echo '<div class="wpcs-card wpcs-card--flush wpcs-table-card"><table class="widefat wpcs-table wpcs-activity-table">';
		echo '<thead><tr>';
		echo '<th scope="col" class="column-when">' . esc_html__( 'When', 'wp-cyber-security' ) . '</th>';
		echo '<th scope="col" class="column-event">' . esc_html__( 'Event', 'wp-cyber-security' ) . '</th>';
		echo '<th scope="col" class="column-message">' . esc_html__( 'Message', 'wp-cyber-security' ) . '</th>';
		echo '<th scope="col" class="column-user">' . esc_html__( 'User', 'wp-cyber-security' ) . '</th>';
		echo '<th scope="col" class="column-ip">' . esc_html__( 'IP address', 'wp-cyber-security' ) . '</th>';
		echo '</tr></thead><tbody>';
		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$event = isset( $row['event'] ) ? (string) $row['event'] : '';
			$meta  = Admin::event_meta( $event );
			$ts    = Admin::utc_ts( isset( $row['created_at'] ) ? $row['created_at'] : '' );
			$user  = Admin::user_name( isset( $row['user_id'] ) ? $row['user_id'] : 0 );
			$url   = Admin::page_url(
				Admin::PAGE_REPORTS,
				array(
					'tab'   => 'activity',
					'event' => $event,
				)
			);
			echo '<tr>';
			echo '<td class="column-when"><span title="' . esc_attr( Admin::datetime( $ts ) ) . '">' . esc_html( Admin::ago( $ts ) ) . '</span><span class="wpcs-sub">' . esc_html( Admin::datetime( $ts ) ) . '</span></td>';
			echo '<td class="column-event"><a class="wpcs-event wpcs-event--' . esc_attr( $meta['tone'] ) . '" href="' . esc_url( $url ) . '" title="' . esc_attr__( 'Show only this event', 'wp-cyber-security' ) . '"><span class="dashicons dashicons-' . esc_attr( $meta['icon'] ) . '" aria-hidden="true"></span>' . esc_html( $meta['label'] ) . '</a></td>';
			echo '<td class="column-message">' . esc_html( isset( $row['message'] ) ? (string) $row['message'] : '' ) . '</td>';
			echo '<td class="column-user">' . esc_html( '' !== $user ? $user : __( 'System', 'wp-cyber-security' ) ) . '</td>';
			echo '<td class="column-ip"><span class="wpcs-mono">' . esc_html( isset( $row['ip'] ) ? (string) $row['ip'] : '' ) . '</span></td>';
			echo '</tr>';
		}
		echo '</tbody></table></div>';

		$this->render_pagination( $total, $per_page );
	}

	/**
	 * Distinct event names for the filter.
	 *
	 * @return string[]
	 */
	private function log_events() {
		$events = Admin::call( 'store', 'log_events', array(), null );
		if ( ! is_array( $events ) ) {
			global $wpdb;
			$table  = Store::table( 'log' );
			$events = $wpdb->get_col( "SELECT DISTINCT event FROM {$table} ORDER BY event ASC LIMIT 200" ); // phpcs:ignore WordPress.DB
		}
		$events = array_filter( array_map( 'sanitize_key', (array) $events ) );
		sort( $events );
		return array_values( array_unique( $events ) );
	}
}

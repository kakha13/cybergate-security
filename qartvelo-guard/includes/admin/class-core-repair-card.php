<?php
/**
 * "WordPress core looks damaged" card on the Dashboard and the Reports tabs.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity\Admin;

use WPCyberSecurity\Core_Repair;
use WPCyberSecurity\Network;

defined( 'ABSPATH' ) || exit;

/**
 * Shows the core damage found by the last scan with the two ways to replace
 * core (one click when this server allows it, by hand always), a running or
 * finished reinstall, and the kept backups with "Restore the previous core".
 * Behaviour lives in assets/js/core-repair.js.
 */
class Core_Repair_Card {

	/**
	 * Prints the card when there is something to show.
	 *
	 * @param string $context dashboard | reports.
	 */
	public static function render( $context = 'dashboard' ) {
		$repair = function_exists( 'wpcybersec' ) ? wpcybersec()->core_repair : null;
		if ( ! $repair instanceof Core_Repair ) {
			return;
		}
		try {
			$repair->recover();
			$state   = $repair->state();
			$damage  = $repair->damage();
			$backups = 'dashboard' === $context ? $repair->backups() : array();
			$step    = isset( $state['step'] ) ? (string) $state['step'] : '';
			if ( ! $damage['show'] && '' === $step && ! $backups ) {
				return;
			}
			if ( '' !== $step ) {
				self::render_job( $state );
			}
			if ( $damage['show'] && ! in_array( $step, array( 'swap', 'finish' ), true ) ) {
				self::render_damage( $repair, $damage, $state );
			}
			foreach ( $backups as $backup ) {
				self::render_backup( $backup );
			}
		} catch ( \Throwable $e ) {
			return; // Never break the page over this card.
		}
	}

	/**
	 * Running, finished or failed reinstall.
	 *
	 * @param array $state Job state.
	 */
	private static function render_job( array $state ) {
		$public = Core_Repair::public_state( $state );
		$step   = $public['step'];
		if ( 'done' === $step ) {
			echo '<div class="wpcs-notice wpcs-notice--ok wpcs-dash-alert wpcs-core-result" data-wpcs-core-result><span class="dashicons dashicons-yes-alt" aria-hidden="true"></span><div><p><strong>'
				. esc_html__( 'WordPress core was reinstalled.', 'qartvelo-guard' ) . '</strong></p><p>' . esc_html( $public['message'] ) . '</p>';
			if ( ! empty( $state['result']['configs'] ) ) {
				echo '<p>' . esc_html(
					sprintf(
						/* translators: %s: list of files */
						__( 'These server configuration files from wp-admin or wp-includes are now only in the backup; put them back by hand if you added them on purpose: %s', 'qartvelo-guard' ),
						implode( ', ', array_map( 'strval', (array) $state['result']['configs'] ) )
					)
				) . '</p>';
			}
			echo '<p>' . esc_html( Core_Repair::after_steps()[0]['text'] ) . ' <code>wp config shuffle-salts</code></p>';
			echo '</div><button type="button" class="button wpcs-dash-alert__btn" data-wpcs-core-dismiss>' . esc_html__( 'Dismiss', 'qartvelo-guard' ) . '</button></div>';
			return;
		}
		if ( 'failed' === $step ) {
			echo '<div class="wpcs-notice wpcs-notice--bad wpcs-dash-alert wpcs-core-result" data-wpcs-core-result><span class="dashicons dashicons-warning" aria-hidden="true"></span><div><p><strong>'
				. esc_html__( 'The core reinstall did not complete.', 'qartvelo-guard' ) . '</strong></p><p>' . esc_html( $public['message'] ) . '</p></div>'
				. '<button type="button" class="button wpcs-dash-alert__btn" data-wpcs-core-dismiss>' . esc_html__( 'Dismiss', 'qartvelo-guard' ) . '</button></div>';
			return;
		}
		// Between start and the end of the swap: the script picks it up again.
		echo '<div class="wpcs-card wpcs-card--warn wpcs-core-card" data-wpcs-core data-wpcs-core-resume="1">';
		echo '<h2 class="wpcs-card__title"><span class="dashicons dashicons-update" aria-hidden="true"></span>' . esc_html(
			/* translators: %s: WordPress version */
			sprintf( __( 'Reinstalling WordPress %s core', 'qartvelo-guard' ), $public['version'] )
		) . '</h2>';
		self::progress( $public['percent'], $public['label'], false );
		echo '<p class="wpcs-core-card__actions"><button type="button" class="button" data-wpcs-core-cancel>' . esc_html__( 'Cancel', 'qartvelo-guard' ) . '</button></p>';
		echo '</div>';
	}

	/**
	 * The damage card with both options.
	 *
	 * @param Core_Repair $repair Service.
	 * @param array       $damage damage().
	 * @param array       $state  Job state.
	 */
	private static function render_damage( Core_Repair $repair, array $damage, array $state ) {
		$auto    = $repair->auto_status();
		$running = $repair->is_active( $state );
		echo '<div class="wpcs-card wpcs-card--bad wpcs-core-card" data-wpcs-core id="wpcs-core-card">';
		echo '<h2 class="wpcs-card__title"><span class="dashicons dashicons-wordpress" aria-hidden="true"></span>' . esc_html(
			sprintf(
				/* translators: %s: number of files */
				_n( 'WordPress core looks damaged: %s core file affected', 'WordPress core looks damaged: %s core files affected', $damage['total'], 'qartvelo-guard' ),
				number_format_i18n( $damage['total'] )
			)
		) . '</h2>';

		$lines = array();
		if ( $damage['modified'] ) {
			/* translators: %s: number of files */
			$lines[] = sprintf( _n( '%s core file differs from the official WordPress file', '%s core files differ from the official WordPress files', $damage['modified'], 'qartvelo-guard' ), number_format_i18n( $damage['modified'] ) );
		}
		if ( $damage['threats'] ) {
			/* translators: %s: number of files */
			$lines[] = sprintf( _n( '%s threat in a core file', '%s threats in core files', $damage['threats'], 'qartvelo-guard' ), number_format_i18n( $damage['threats'] ) );
		}
		if ( $damage['unknown'] ) {
			$lines[] = sprintf(
				/* translators: 1: number of files, 2: number of them that can run code */
				_n( '%1$s file in wp-admin or wp-includes that is not part of WordPress (%2$s can run code)', '%1$s files in wp-admin or wp-includes that are not part of WordPress (%2$s can run code)', $damage['unknown'], 'qartvelo-guard' ),
				number_format_i18n( $damage['unknown'] ),
				number_format_i18n( $damage['unknown_exec'] )
			);
		}
		if ( $damage['missing'] ) {
			/* translators: %s: number of files */
			$lines[] = sprintf( _n( '%s core file is missing', '%s core files are missing', $damage['missing'], 'qartvelo-guard' ), number_format_i18n( $damage['missing'] ) );
		}
		echo '<ul class="wpcs-core-card__counts">';
		foreach ( $lines as $line ) {
			echo '<li><span class="dashicons dashicons-arrow-right-alt2" aria-hidden="true"></span>' . esc_html( $line ) . '</li>';
		}
		echo '</ul>';
		if ( $damage['unknown_exec'] ) {
			echo '<p class="wpcs-core-card__warn"><strong>' . esc_html__( 'wp-admin and wp-includes should only ever contain WordPress files. An extra PHP file there is a classic backdoor.', 'qartvelo-guard' ) . '</strong></p>';
		}
		echo '<p>' . esc_html(
			sprintf(
				/* translators: %s: WordPress version */
				__( 'Replacing the whole WordPress core with a clean copy of version %s is faster and safer than reviewing these files one by one: wp-admin, wp-includes and the core files in the WordPress folder are swapped for the official ones. wp-config.php, wp-content (plugins, themes, uploads, languages), .htaccess and the other files you added stay as they are.', 'qartvelo-guard' ),
				$damage['version']
			)
		) . '</p>';

		echo '<div class="wpcs-core-card__options">';
		echo '<div class="wpcs-core-option">';
		echo '<h3>' . esc_html__( 'Reinstall clean core for me', 'qartvelo-guard' ) . '</h3>';
		if ( $auto['ok'] ) {
			echo '<p class="wpcs-sub">' . esc_html__( 'Downloads the official package of this version, checks every file against the wordpress.org checksums, then swaps core in a few seconds with maintenance mode on. If the site does not answer afterwards, the old core is put back by itself. The old core is kept for 7 days.', 'qartvelo-guard' ) . '</p>';
			echo '<p class="wpcs-core-card__actions"><button type="button" class="button button-primary" data-wpcs-core-start' . ( $running ? ' disabled' : '' ) . '><span class="dashicons dashicons-update" aria-hidden="true"></span> ' . esc_html__( 'Reinstall clean core for me', 'qartvelo-guard' ) . '</button></p>';
			self::progress( 0, '', true );
		} else {
			echo '<p class="wpcs-sub">' . esc_html__( 'Not available on this site:', 'qartvelo-guard' ) . ' ' . esc_html( $auto['reason'] ) . '</p>';
		}
		echo '</div>';

		echo '<details class="wpcs-core-option wpcs-core-manual"' . ( $auto['ok'] ? '' : ' open' ) . '>';
		echo '<summary>' . esc_html__( 'Do it by hand, step by step', 'qartvelo-guard' ) . '</summary>';
		$hosting = wpcybersec()->hosting;
		if ( $hosting ) {
			$info = $hosting->current();
			echo '<p class="wpcs-sub"><span class="dashicons dashicons-admin-site-alt3" aria-hidden="true"></span> ' . esc_html( $hosting->label( $info ) ) . ' <a href="' . esc_url( \WPCyberSecurity\Hosting::change_url() ) . '">' . esc_html__( 'Not your hosting?', 'qartvelo-guard' ) . '</a></p>';
		}
		Settings_Page::render_steps( $repair->manual_steps() );
		if ( 'composer' !== Core_Repair::layout() ) {
			echo '<p class="wpcs-core-card__actions">';
			echo '<a class="button" href="' . esc_url( Core_Repair::package_url( $damage['version'] ) ) . '"><span class="dashicons dashicons-download" aria-hidden="true"></span> ' . esc_html__( 'Download the package', 'qartvelo-guard' ) . '</a> ';
			echo '<button type="button" class="button" data-wpcs-core-maint>' . esc_html__( 'Turn on maintenance mode', 'qartvelo-guard' ) . '</button> ';
			echo '<a class="button" href="' . esc_url( \WPCyberSecurity\Developer_Instructions::download_url() ) . '">' . esc_html__( 'Download these steps (.txt)', 'qartvelo-guard' ) . '</a>';
			echo '</p>';
		}
		echo '</details>';
		echo '</div></div>';
	}

	/**
	 * A kept backup of a replaced core.
	 *
	 * @param array $backup Entry of Core_Repair::backups().
	 */
	private static function render_backup( array $backup ) {
		$format = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );
		$at     = (int) $backup['at'];
		$until  = $at + Core_Repair::KEEP_DAYS * DAY_IN_SECONDS;
		echo '<div class="wpcs-notice wpcs-dash-alert wpcs-core-backup"><span class="dashicons dashicons-backup" aria-hidden="true"></span><div><p><strong>'
			. esc_html(
				sprintf(
					/* translators: 1: date, 2: WordPress version */
					__( 'The WordPress core replaced on %1$s (version %2$s) is kept as a backup.', 'qartvelo-guard' ),
					wp_date( $format, $at ),
					(string) $backup['version']
				)
			) . '</strong></p><p>'
			. esc_html(
				sprintf(
					/* translators: %s: date */
					__( 'It is deleted on %s. Restore it only if something stopped working after the reinstall: it holds the old, possibly infected files, and they are reported again.', 'qartvelo-guard' ),
					wp_date( $format, $until )
				)
			) . '</p></div>'
			. '<button type="button" class="button wpcs-dash-alert__btn" data-wpcs-core-restore data-id="' . esc_attr( (string) $backup['id'] ) . '">' . esc_html__( 'Restore the previous core', 'qartvelo-guard' ) . '</button></div>';
	}

	/**
	 * Progress block (same markup as the scan progress).
	 *
	 * @param int    $percent Percent.
	 * @param string $label   Text.
	 * @param bool   $hidden  Hidden until a job runs.
	 */
	private static function progress( $percent, $label, $hidden ) {
		echo '<div class="wpcs-progress' . ( $hidden ? ' wpcs-hidden' : '' ) . '" data-wpcs-core-progress>';
		echo '<div class="wpcs-progress__track"><div class="wpcs-progress__bar" style="width:' . (int) $percent . '%"></div></div>';
		echo '<div class="wpcs-progress__label"><span class="wpcs-progress__text">' . esc_html( $label ) . '</span><span class="wpcs-progress__current"></span></div>';
		echo '</div>';
	}

	/**
	 * Strings for core-repair.js.
	 *
	 * @return array
	 */
	public static function i18n() {
		return array(
			'starting'     => __( 'Checking the server and downloading the official package', 'qartvelo-guard' ),
			'swapping'     => __( 'Replacing core (a few seconds)', 'qartvelo-guard' ),
			'cancelled'    => __( 'Cancelled. Nothing was changed.', 'qartvelo-guard' ),
			'restoreTitle' => __( 'Restore the previous WordPress core?', 'qartvelo-guard' ),
			'restoreText'  => __( 'The core from before the reinstall goes back in place, with every file that was in it (also the ones that were reported). The clean core is deleted and a quick scan reports the old files again.', 'qartvelo-guard' ),
			'restore'      => __( 'Restore the previous core', 'qartvelo-guard' ),
			'maintTitle'   => __( 'Turn on maintenance mode now?', 'qartvelo-guard' ),
			'maintText'    => __( 'Visitors and this admin see "Briefly unavailable for scheduled maintenance" until the .maintenance file is deleted or 10 minutes have passed. Do it right before you delete the core files, and keep this page open for the steps.', 'qartvelo-guard' ),
			'maintOn'      => __( 'Turn on maintenance mode', 'qartvelo-guard' ),
			'network'      => Network::active() ? __( 'All sites of the network share this core.', 'qartvelo-guard' ) : '',
		);
	}
}

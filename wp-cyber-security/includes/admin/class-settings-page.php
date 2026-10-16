<?php
/**
 * Settings page: General (site owners) and Advanced (system administrators).
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity\Admin;

use WPCyberSecurity\Settings;
use WPCyberSecurity\Sysadmin_Tools;

defined( 'ABSPATH' ) || exit;

/**
 * Renders the settings tabs. Each tab is one form posting to admin-post
 * "wpcybersec_save_settings" (handled by Sysadmin_Tools). Also holds small
 * static UI helpers shared with the setup wizard.
 */
class Settings_Page {

	/** @var bool Whether a card section is open (for error recovery). */
	private $card_is_open = false;

	/* ------------------------------------------------------------------ */
	/* Shared UI helpers                                                   */
	/* ------------------------------------------------------------------ */

	/**
	 * Page header through Admin::header() when the admin module provides it,
	 * otherwise an equivalent fallback.
	 *
	 * @param string $title        Title.
	 * @param string $subtitle     Subtitle.
	 * @param string $actions_html Buttons (already escaped HTML).
	 */
	public static function page_header( $title, $subtitle = '', $actions_html = '' ) {
		$class = __NAMESPACE__ . '\\Admin';
		if ( class_exists( $class ) && method_exists( $class, 'header' ) ) {
			$returned = null;
			$failed   = false;
			ob_start();
			try {
				$method = new \ReflectionMethod( $class, 'header' );
				if ( $method->isStatic() ) {
					$returned = call_user_func( array( $class, 'header' ), $title, $subtitle, $actions_html );
				} else {
					$admin = Sysadmin_Tools::service( 'admin' );
					if ( $admin instanceof $class ) {
						$returned = $admin->header( $title, $subtitle, $actions_html );
					}
				}
			} catch ( \Throwable $e ) {
				$failed = true;
			}
			$out = (string) ob_get_clean();
			if ( $failed ) {
				// Never print half a header.
				$out      = '';
				$returned = null;
			}
			if ( '' === trim( $out ) && is_string( $returned ) ) {
				$out = $returned;
			}
			if ( '' !== trim( $out ) ) {
				echo $out; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- rendered and escaped by Admin::header().
				return;
			}
		}
		?>
		<div class="wpcs-header">
			<div class="wpcs-header__icon"><span class="dashicons dashicons-shield" aria-hidden="true"></span></div>
			<div class="wpcs-header__text">
				<h1><?php echo esc_html( $title ); ?></h1>
				<?php if ( $subtitle ) : ?>
					<p><?php echo esc_html( $subtitle ); ?></p>
				<?php endif; ?>
			</div>
			<?php if ( $actions_html ) : ?>
				<div class="wpcs-header__actions"><?php echo wp_kses_post( $actions_html ); ?></div>
			<?php endif; ?>
		</div>
		<hr class="wp-header-end">
		<?php
	}

	/**
	 * Inline notice that WordPress does not move around.
	 *
	 * @param string $message Plain text.
	 * @param string $type    ok | warn | bad | info.
	 */
	public static function notice( $message, $type = 'info' ) {
		$icons = array(
			'ok'   => 'yes-alt',
			'warn' => 'warning',
			'bad'  => 'dismiss',
			'info' => 'info',
		);
		$type  = isset( $icons[ $type ] ) ? $type : 'info';
		$class = 'info' === $type ? 'wpcs-notice' : 'wpcs-notice wpcs-notice--' . $type;
		$role  = 'bad' === $type ? 'alert' : 'status';
		echo '<div class="' . esc_attr( $class ) . '" role="' . esc_attr( $role ) . '"><span class="dashicons dashicons-' . esc_attr( $icons[ $type ] ) . '" aria-hidden="true"></span><p>' . esc_html( $message ) . '</p></div>';
	}

	/**
	 * Prints the one-time notices queued by the admin-post handlers.
	 */
	public static function render_flash() {
		foreach ( Sysadmin_Tools::take_flash() as $notice ) {
			self::notice( $notice['message'], $notice['type'] );
		}
	}

	/**
	 * Copyable code block.
	 *
	 * @param string $code  Code.
	 * @param string $label Optional label above the block.
	 * @param string $help  Optional help below the block.
	 * @return string HTML.
	 */
	public static function code( $code, $label = '', $help = '' ) {
		$html = '<div class="wpcs-code">';
		if ( '' !== $label ) {
			$html .= '<span class="wpcs-code__label">' . esc_html( $label ) . '</span>';
		}
		$html .= '<pre>' . esc_html( $code ) . '</pre>';
		$html .= '<button type="button" class="button wpcs-copy" data-wpcs-copy>' . esc_html__( 'Copy', 'wp-cyber-security' ) . '</button>';
		if ( '' !== $help ) {
			$html .= '<span class="wpcs-field__help">' . esc_html( $help ) . '</span>';
		}
		return $html . '</div>';
	}

	/**
	 * @param array $attrs name => value.
	 * @return string
	 */
	private static function attrs( array $attrs ) {
		$out = '';
		foreach ( $attrs as $name => $value ) {
			$out .= ' ' . esc_attr( $name ) . '="' . esc_attr( $value ) . '"';
		}
		return $out;
	}

	/**
	 * Toggle switch with a hidden "off" value, so unchecked boxes are saved too.
	 *
	 * @param string $name      Field name.
	 * @param bool   $checked   State.
	 * @param string $label     Label.
	 * @param string $help      Help text.
	 * @param array  $attrs     Extra attributes for the checkbox.
	 * @param string $value     Value when on.
	 * @param string $off_value Value when off.
	 * @return string HTML.
	 */
	public static function toggle_row( $name, $checked, $label, $help = '', array $attrs = array(), $value = '1', $off_value = '0' ) {
		$id   = 'wpcs-' . sanitize_html_class( str_replace( '_', '-', $name ) );
		$html = '<div class="wpcs-toggle-row">';
		$html .= '<label class="wpcs-toggle" for="' . esc_attr( $id ) . '">';
		$html .= '<input type="hidden" name="' . esc_attr( $name ) . '" value="' . esc_attr( $off_value ) . '">';
		$html .= '<input type="checkbox" id="' . esc_attr( $id ) . '" name="' . esc_attr( $name ) . '" value="' . esc_attr( $value ) . '"' . ( $checked ? ' checked' : '' ) . self::attrs( $attrs ) . '>';
		$html .= '<span class="wpcs-toggle__track" aria-hidden="true"></span>';
		$html .= '<span class="wpcs-toggle__label">' . esc_html( $label ) . '</span>';
		$html .= '</label>';
		if ( '' !== $help ) {
			$html .= '<span class="wpcs-field__help">' . esc_html( $help ) . '</span>';
		}
		return $html . '</div>';
	}

	/**
	 * Radio list with a label and a description per choice.
	 *
	 * @param string $name    Field name.
	 * @param array  $choices value => array( label, description ).
	 * @param string $current Current value.
	 * @return string HTML.
	 */
	public static function radio_list( $name, array $choices, $current ) {
		$html = '<div class="wpcs-radio-list" role="radiogroup">';
		foreach ( $choices as $value => $choice ) {
			$html .= '<label><input type="radio" name="' . esc_attr( $name ) . '" value="' . esc_attr( $value ) . '"' . checked( (string) $current, (string) $value, false ) . '> ';
			$html .= '<strong>' . esc_html( $choice[0] ) . '</strong>';
			if ( ! empty( $choice[1] ) ) {
				$html .= '<span class="wpcs-sub">' . esc_html( $choice[1] ) . '</span>';
			}
			$html .= '</label>';
		}
		return $html . '</div>';
	}

	/**
	 * Alert delivery choices (wizard and settings).
	 *
	 * @param string $current Current mode.
	 * @return string HTML.
	 */
	public static function notify_mode_choices( $current ) {
		return self::radio_list(
			'notify_mode',
			array(
				'instant' => array( __( 'Instantly', 'wp-cyber-security' ), __( 'An email as soon as something is held or found. At most one email every 10 minutes; anything else is summarized in the next one.', 'wp-cyber-security' ) ),
				'digest'  => array( __( 'Daily digest', 'wp-cyber-security' ), __( 'One summary email per day.', 'wp-cyber-security' ) ),
				'off'     => array( __( 'Off', 'wp-cyber-security' ), __( 'No emails. Check the Reports page yourself.', 'wp-cyber-security' ) ),
			),
			$current
		);
	}

	/**
	 * Human labels for enum settings.
	 *
	 * @return array
	 */
	public static function labels() {
		return array(
			'protection_level' => array(
				'strict'   => __( 'Strict', 'wp-cyber-security' ),
				'balanced' => __( 'Balanced', 'wp-cyber-security' ),
				'relaxed'  => __( 'Relaxed', 'wp-cyber-security' ),
				'custom'   => __( 'Custom', 'wp-cyber-security' ),
			),
			'upload_mode'      => array(
				'hold_all'   => __( 'Every upload held for approval', 'wp-cyber-security' ),
				'hold_risky' => __( 'Risky uploads held for approval', 'wp-cyber-security' ),
				'scan_only'  => __( 'Scanned, only malware held', 'wp-cyber-security' ),
				'off'        => __( 'Not checked', 'wp-cyber-security' ),
			),
			'file_mode'        => array(
				'quarantine_exec' => __( 'Moved to quarantine', 'wp-cyber-security' ),
				'report'          => __( 'Reported for review', 'wp-cyber-security' ),
				'off'             => __( 'Not reported', 'wp-cyber-security' ),
			),
			'scan_schedule'    => array(
				'hourly'     => __( 'Every hour', 'wp-cyber-security' ),
				'twicedaily' => __( 'Twice a day', 'wp-cyber-security' ),
				'daily'      => __( 'Once a day', 'wp-cyber-security' ),
				'weekly'     => __( 'Once a week', 'wp-cyber-security' ),
				'off'        => __( 'Off (manual scans only)', 'wp-cyber-security' ),
			),
			'notify_mode'      => array(
				'instant' => __( 'Instant email', 'wp-cyber-security' ),
				'digest'  => __( 'Daily digest', 'wp-cyber-security' ),
				'off'     => __( 'Off', 'wp-cyber-security' ),
			),
		);
	}

	/**
	 * What a preset does, in plain words.
	 *
	 * @param array $preset Preset values.
	 * @return string[]
	 */
	public static function level_points( array $preset ) {
		$points  = array();
		$uploads = array(
			'hold_all'   => __( 'Every upload waits for approval', 'wp-cyber-security' ),
			'hold_risky' => __( 'Only risky uploads wait for approval', 'wp-cyber-security' ),
			'scan_only'  => __( 'Uploads are scanned, not held', 'wp-cyber-security' ),
			'off'        => __( 'Uploads are not checked', 'wp-cyber-security' ),
		);
		if ( isset( $preset['upload_mode'], $uploads[ $preset['upload_mode'] ] ) ) {
			$points[] = $uploads[ $preset['upload_mode'] ];
		}
		if ( isset( $preset['upload_bypass_roles'] ) ) {
			$points[] = in_array( 'administrator', (array) $preset['upload_bypass_roles'], true )
				? __( 'Administrators\' clean uploads pass', 'wp-cyber-security' )
				: __( 'Administrators\' uploads are held too', 'wp-cyber-security' );
		}
		if ( isset( $preset['install_mode'] ) ) {
			$points[] = 'hold' === $preset['install_mode']
				? __( 'New plugins and themes wait for approval', 'wp-cyber-security' )
				: __( 'Plugin and theme installs are not held', 'wp-cyber-security' );
		}
		if ( isset( $preset['file_mode'] ) ) {
			$points[] = 'quarantine_exec' === $preset['file_mode']
				? __( 'New unknown PHP files go to quarantine', 'wp-cyber-security' )
				: __( 'New unknown PHP files are reported', 'wp-cyber-security' );
		}
		if ( ! empty( $preset['auto_quarantine'] ) ) {
			$points[] = __( 'Critical malware is quarantined automatically', 'wp-cyber-security' );
		}
		$schedules = array(
			'hourly'     => __( 'Scans every hour', 'wp-cyber-security' ),
			'twicedaily' => __( 'Scans twice a day', 'wp-cyber-security' ),
			'daily'      => __( 'Scans once a day', 'wp-cyber-security' ),
			'weekly'     => __( 'Scans once a week', 'wp-cyber-security' ),
		);
		if ( isset( $preset['scan_schedule'], $schedules[ $preset['scan_schedule'] ] ) ) {
			$points[] = $schedules[ $preset['scan_schedule'] ];
		}
		if ( isset( $preset['notify_mode'] ) && 'off' !== $preset['notify_mode'] ) {
			$points[] = 'digest' === $preset['notify_mode'] ? __( 'Daily digest email', 'wp-cyber-security' ) : __( 'Instant email alerts', 'wp-cyber-security' );
		}
		return $points;
	}

	/**
	 * Protection level radio cards.
	 *
	 * @param string $name     Field name.
	 * @param string $selected Selected level (custom selects nothing).
	 * @return string HTML.
	 */
	public static function level_cards( $name, $selected ) {
		$meta = array(
			'strict'   => array( 'lock', __( 'Maximum control. Nothing new runs or appears without your approval, and suspicious files are moved away at once.', 'wp-cyber-security' ) ),
			'balanced' => array( 'shield', __( 'Holds every upload and new install, and reports unknown files without moving them. Best for most sites.', 'wp-cyber-security' ) ),
			'relaxed'  => array( 'unlock', __( 'Fewer approvals. Only risky uploads are held and administrators\' clean uploads pass.', 'wp-cyber-security' ) ),
		);
		$labels = self::labels();
		$html   = '<div class="wpcs-options wpcs-levels" role="radiogroup" aria-label="' . esc_attr__( 'Protection level', 'wp-cyber-security' ) . '">';
		foreach ( Settings::presets() as $level => $preset ) {
			$icon = isset( $meta[ $level ] ) ? $meta[ $level ][0] : 'shield';
			$desc = isset( $meta[ $level ] ) ? $meta[ $level ][1] : '';
			$is   = $selected === $level;
			$html .= '<label class="wpcs-option' . ( $is ? ' is-selected' : '' ) . '">';
			$html .= '<input type="radio" name="' . esc_attr( $name ) . '" value="' . esc_attr( $level ) . '"' . ( $is ? ' checked' : '' ) . ' data-wpcs-level>';
			if ( 'balanced' === $level ) {
				$html .= '<span class="wpcs-badge wpcs-badge--ok wpcs-option__tag">' . esc_html__( 'Recommended', 'wp-cyber-security' ) . '</span>';
			}
			$html .= '<span class="wpcs-option__title"><span class="dashicons dashicons-' . esc_attr( $icon ) . '" aria-hidden="true"></span>' . esc_html( isset( $labels['protection_level'][ $level ] ) ? $labels['protection_level'][ $level ] : ucfirst( $level ) ) . '</span>';
			$html .= '<span class="wpcs-option__desc">' . esc_html( $desc ) . '</span>';
			$html .= '<ul>';
			foreach ( self::level_points( $preset ) as $point ) {
				$html .= '<li>' . esc_html( $point ) . '</li>';
			}
			$html .= '</ul></label>';
		}
		return $html . '</div>';
	}

	/**
	 * Environment check list.
	 *
	 * @param array[] $checks       Checks from Sysadmin_Tools::diagnostics().
	 * @param bool    $with_actions Render quick action buttons (inside the wizard form).
	 */
	public static function render_checks( array $checks, $with_actions = false ) {
		$icons   = array(
			'pass' => 'yes-alt',
			'warn' => 'warning',
			'fail' => 'dismiss',
			'info' => 'info',
		);
		$badges  = array(
			'pass' => array( 'ok', __( 'OK', 'wp-cyber-security' ) ),
			'warn' => array( 'medium', __( 'Recommended', 'wp-cyber-security' ) ),
			'fail' => array( 'high', __( 'Problem', 'wp-cyber-security' ) ),
			'info' => array( 'info', __( 'Info', 'wp-cyber-security' ) ),
		);
		$actions = array(
			'write_htaccess' => __( 'Add the rule for me', 'wp-cyber-security' ),
			'probe'          => __( 'Run a live test', 'wp-cyber-security' ),
		);
		echo '<ul class="wpcs-checks wpcs-checks--detailed">';
		foreach ( $checks as $check ) {
			$status = isset( $icons[ $check['status'] ] ) ? $check['status'] : 'info';
			echo '<li class="is-' . esc_attr( $status ) . '" data-check="' . esc_attr( $check['id'] ) . '">';
			echo '<span class="dashicons dashicons-' . esc_attr( $icons[ $status ] ) . '" aria-hidden="true"></span>';
			echo '<div class="wpcs-check">';
			echo '<div class="wpcs-check__head"><strong>' . esc_html( $check['label'] ) . '</strong><span class="wpcs-badge wpcs-badge--' . esc_attr( $badges[ $status ][0] ) . '">' . esc_html( $badges[ $status ][1] ) . '</span></div>';
			if ( '' !== (string) $check['detail'] ) {
				echo '<span class="wpcs-sub">' . esc_html( $check['detail'] ) . '</span>';
			}
			$auto  = ! empty( $check['auto_fix'] ) && is_array( $check['auto_fix'] ) ? $check['auto_fix'] : null;
			$steps = ! empty( $check['manual_steps'] ) && is_array( $check['manual_steps'] ) ? $check['manual_steps'] : array();
			// The check's own snippet (for example the nginx rule) when the steps do not show it.
			$extra = ( $auto || $steps ) ? self::extra_code( $check, $steps ) : '';

			if ( $auto ) {
				// One click for the signed-in administrator; by-hand steps folded away.
				echo '<div class="wpcs-autofix">';
				if ( ! empty( $auto['link'] ) ) {
					echo '<a class="button button-primary" href="' . esc_url( $auto['link'] ) . '">' . esc_html( $auto['label'] ) . '</a>';
				} else {
					echo '<button type="button" class="button button-primary" data-wpcs-fix="' . esc_attr( $auto['id'] ) . '"><span class="dashicons dashicons-admin-tools" aria-hidden="true"></span>' . esc_html( $auto['label'] ) . '</button>';
				}
				if ( ! empty( $auto['description'] ) ) {
					echo '<span class="wpcs-sub">' . esc_html( $auto['description'] ) . '</span>';
				}
				echo '</div>';
				if ( $steps || '' !== $extra ) {
					echo '<details class="wpcs-manual" data-wpcs-manual="' . esc_attr( $auto['id'] ) . '"><summary>' . esc_html__( 'Do it by hand instead', 'wp-cyber-security' ) . '</summary>';
					if ( $steps ) {
						self::render_steps( $steps );
					}
					self::render_extra_code( $check, $extra );
					echo '</details>';
				}
			} elseif ( $steps ) {
				// No automatic fix on this server: easy numbered steps, open by default.
				echo '<div class="wpcs-manual wpcs-manual--open" data-wpcs-manual="' . esc_attr( $check['id'] ) . '">';
				echo '<span class="wpcs-sub wpcs-check__fix">' . esc_html__( 'How to fix it:', 'wp-cyber-security' ) . '</span>';
				self::render_steps( $steps );
				self::render_extra_code( $check, $extra );
				echo '</div>';
			} else {
				if ( '' !== (string) $check['fix'] ) {
					echo '<span class="wpcs-sub wpcs-check__fix">' . esc_html( $check['fix'] ) . '</span>';
				}
				if ( '' !== (string) $check['code'] ) {
					echo self::code( $check['code'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in code().
				}
			}
			if ( $with_actions && ! empty( $check['actions'] ) ) {
				echo '<div class="wpcs-check__actions">';
				foreach ( (array) $check['actions'] as $action ) {
					if ( $auto && 'write_htaccess' === $action ) {
						continue; // The one-click fix above does the same.
					}
					if ( isset( $actions[ $action ] ) ) {
						echo '<button type="submit" name="wpcs_do" value="' . esc_attr( $action ) . '" class="button button-small">' . esc_html( $actions[ $action ] ) . '</button>';
					}
				}
				echo '</div>';
			}
			echo '</div></li>';
		}
		echo '</ul>';
	}

	/**
	 * The check's own code snippet when the by-hand steps do not already show
	 * it (the same text, or a define() of the same wp-config.php constant).
	 *
	 * @param array   $check Check.
	 * @param array[] $steps By-hand steps.
	 * @return string Code, or ''.
	 */
	private static function extra_code( array $check, array $steps ) {
		$code = isset( $check['code'] ) ? trim( (string) $check['code'] ) : '';
		if ( '' === $code ) {
			return '';
		}
		$constant = preg_match( '/^define\(\s*[\'"]([A-Za-z0-9_]+)[\'"]/', $code, $m ) ? $m[1] : '';
		foreach ( $steps as $step ) {
			$step_code = isset( $step['code'] ) ? trim( (string) $step['code'] ) : '';
			if ( '' === $step_code ) {
				continue;
			}
			if ( false !== strpos( $step_code, $code ) ) {
				return '';
			}
			if ( '' !== $constant && preg_match( '/define\(\s*[\'"]' . preg_quote( $constant, '/' ) . '[\'"]/', $step_code ) ) {
				return '';
			}
		}
		return $code;
	}

	/**
	 * Prints the check's own snippet below the by-hand steps.
	 *
	 * @param array  $check Check.
	 * @param string $code  From extra_code().
	 */
	private static function render_extra_code( array $check, $code ) {
		if ( '' === $code ) {
			return;
		}
		$fix = isset( $check['fix'] ) ? trim( (string) $check['fix'] ) : '';
		echo '<span class="wpcs-sub wpcs-check__fix">' . esc_html( '' !== $fix ? $fix : __( 'Or use this:', 'wp-cyber-security' ) ) . '</span>';
		echo self::code( $code ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in code().
	}

	/**
	 * Numbered by-hand steps.
	 *
	 * @param array[] $steps Each { text, code (optional) }.
	 */
	public static function render_steps( array $steps ) {
		echo '<ol class="wpcs-howto">';
		foreach ( $steps as $step ) {
			echo '<li>' . esc_html( isset( $step['text'] ) ? (string) $step['text'] : '' );
			if ( ! empty( $step['code'] ) ) {
				echo self::code( (string) $step['code'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in code().
			}
			echo '</li>';
		}
		echo '</ol>';
	}

	/**
	 * Ids of checks that "Fix all" repairs here: only fixes it really runs
	 * (Hardening::AUTO). The early guard and the cron switch keep their own
	 * buttons, so the count next to "Fix them all" matches what happens.
	 *
	 * @param array[] $checks Checks.
	 * @return string[]
	 */
	public static function auto_fix_ids( array $checks ) {
		$runs = class_exists( '\WPCyberSecurity\Hardening' ) ? \WPCyberSecurity\Hardening::AUTO : array();
		$ids  = array();
		foreach ( $checks as $check ) {
			if ( ! empty( $check['auto_fix']['id'] ) && empty( $check['auto_fix']['link'] ) && in_array( (string) $check['auto_fix']['id'], $runs, true ) ) {
				$ids[] = (string) $check['auto_fix']['id'];
			}
		}
		return array_values( array_unique( $ids ) );
	}

	/* ------------------------------------------------------------------ */
	/* Page                                                                */
	/* ------------------------------------------------------------------ */

	/**
	 * @return array Current settings.
	 */
	private function settings() {
		$settings = Sysadmin_Tools::service( 'settings' );
		return $settings ? $settings->all() : Settings::defaults();
	}

	/**
	 * @return Sysadmin_Tools
	 */
	private function tools() {
		$tools = Sysadmin_Tools::service( 'sysadmin' );
		return $tools instanceof Sysadmin_Tools ? $tools : new Sysadmin_Tools();
	}

	/**
	 * Renders the settings page.
	 */
	public function render() {
		if ( ! Admin::can() ) {
			wp_die( esc_html__( 'You are not allowed to access this page.', 'wp-cyber-security' ) );
		}
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- navigation and display only.
		$tab     = ( isset( $_GET['tab'] ) && 'advanced' === sanitize_key( wp_unslash( $_GET['tab'] ) ) ) ? 'advanced' : 'general';
		$updated = ! empty( $_GET['settings-updated'] );
		// phpcs:enable

		$actions = '<a class="button" href="' . esc_url( Sysadmin_Tools::wizard_url() ) . '">' . esc_html__( 'Run setup wizard', 'wp-cyber-security' ) . '</a>';
		?>
		<div class="wrap wpcs-wrap wpcs-settings">
			<?php
			self::page_header( __( 'Settings', 'wp-cyber-security' ), __( 'Protection rules, alerts and tools for system administrators.', 'wp-cyber-security' ), $actions );
			if ( $updated ) {
				self::notice( __( 'Settings saved.', 'wp-cyber-security' ), 'ok' );
			}
			self::render_flash();
			?>
			<nav class="nav-tab-wrapper wpcs-tabs" aria-label="<?php esc_attr_e( 'Settings sections', 'wp-cyber-security' ); ?>">
				<a href="<?php echo esc_url( Sysadmin_Tools::settings_url( 'general' ) ); ?>" class="nav-tab<?php echo 'general' === $tab ? ' nav-tab-active' : ''; ?>"<?php echo 'general' === $tab ? ' aria-current="page"' : ''; ?>>
					<span class="dashicons dashicons-admin-generic" aria-hidden="true"></span><?php esc_html_e( 'General', 'wp-cyber-security' ); ?>
				</a>
				<a href="<?php echo esc_url( Sysadmin_Tools::settings_url( 'advanced' ) ); ?>" class="nav-tab<?php echo 'advanced' === $tab ? ' nav-tab-active' : ''; ?>"<?php echo 'advanced' === $tab ? ' aria-current="page"' : ''; ?>>
					<span class="dashicons dashicons-admin-tools" aria-hidden="true"></span><?php esc_html_e( 'Advanced', 'wp-cyber-security' ); ?>
					<span class="wpcs-badge wpcs-badge--muted"><?php esc_html_e( 'System administrators', 'wp-cyber-security' ); ?></span>
				</a>
			</nav>
			<?php
			try {
				if ( 'advanced' === $tab ) {
					$this->render_advanced();
				} else {
					$this->render_general();
				}
			} catch ( \Throwable $e ) {
				/* translators: %s: error message */
				self::notice( sprintf( __( 'Part of this page could not be shown: %s', 'wp-cyber-security' ), $e->getMessage() ), 'bad' );
			}
			?>
		</div>
		<?php
	}

	/**
	 * Opens the settings form of a tab.
	 *
	 * @param string $tab Tab.
	 */
	private function form_open( $tab ) {
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="wpcs-settings-form" data-wpcs-level-form="settings">
			<input type="hidden" name="action" value="wpcybersec_save_settings">
			<input type="hidden" name="tab" value="<?php echo esc_attr( $tab ); ?>">
			<?php wp_nonce_field( 'wpcybersec_save_settings' ); ?>
			<button type="submit" class="wpcs-default-submit" tabindex="-1" aria-hidden="true"><?php esc_html_e( 'Save changes', 'wp-cyber-security' ); ?></button>
		<?php
	}

	/**
	 * Sticky save bar and end of the form.
	 *
	 * @param string $note Text next to the button.
	 */
	private function form_close( $note ) {
		?>
			<div class="wpcs-savebar">
				<span class="wpcs-savebar__note"><?php echo esc_html( $note ); ?></span>
				<button type="submit" class="button button-primary button-large"><?php esc_html_e( 'Save changes', 'wp-cyber-security' ); ?></button>
			</div>
		</form>
		<?php
	}

	/**
	 * @param string $id    Anchor id.
	 * @param string $icon  Dashicon.
	 * @param string $title Title.
	 * @param string $desc  Description.
	 */
	private function card_open( $id, $icon, $title, $desc = '' ) {
		$this->card_is_open = true;
		echo '<section class="wpcs-card wpcs-settings-card" id="' . esc_attr( $id ) . '">';
		echo '<h2 class="wpcs-card__title"><span class="dashicons dashicons-' . esc_attr( $icon ) . '" aria-hidden="true"></span>' . esc_html( $title ) . '</h2>';
		if ( '' !== $desc ) {
			echo '<p class="wpcs-card__desc">' . esc_html( $desc ) . '</p>';
		}
	}

	/**
	 * Closes a card.
	 */
	private function card_close() {
		$this->card_is_open = false;
		echo '</section>';
	}

	/**
	 * One labelled row.
	 *
	 * @param string $label   Label.
	 * @param string $content Escaped HTML.
	 * @param string $help    Help text.
	 * @param string $for     Input id for the label.
	 */
	private function field( $label, $content, $help = '', $for = '' ) {
		echo '<div class="wpcs-field">';
		if ( $for ) {
			echo '<label class="wpcs-field__label" for="' . esc_attr( $for ) . '">' . esc_html( $label ) . '</label>';
		} else {
			echo '<div class="wpcs-field__label">' . esc_html( $label ) . '</div>';
		}
		echo '<div class="wpcs-field__control">' . $content; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built from escaped parts.
		if ( '' !== $help ) {
			echo '<span class="wpcs-field__help">' . esc_html( $help ) . '</span>';
		}
		echo '</div></div>';
	}

	/**
	 * @param string $name  Field name.
	 * @param int    $value Value.
	 * @param int    $min   Min.
	 * @param int    $max   Max.
	 * @param string $unit  Unit label.
	 * @return string HTML.
	 */
	private function number( $name, $value, $min, $max, $unit ) {
		$id = 'wpcs-' . str_replace( '_', '-', $name );
		return '<input type="number" class="small-text" id="' . esc_attr( $id ) . '" name="' . esc_attr( $name ) . '" value="' . esc_attr( (string) (int) $value ) . '" min="' . esc_attr( (string) $min ) . '" max="' . esc_attr( (string) $max ) . '" step="1"> <span class="wpcs-field__unit">' . esc_html( $unit ) . '</span>';
	}

	/**
	 * @param string $name    Field name.
	 * @param array  $choices value => label.
	 * @param string $current Current value.
	 * @return string HTML.
	 */
	private function select( $name, array $choices, $current ) {
		$id   = 'wpcs-' . str_replace( '_', '-', $name );
		$html = '<select id="' . esc_attr( $id ) . '" name="' . esc_attr( $name ) . '">';
		foreach ( $choices as $value => $label ) {
			$html .= '<option value="' . esc_attr( $value ) . '"' . selected( (string) $current, (string) $value, false ) . '>' . esc_html( $label ) . '</option>';
		}
		return $html . '</select>';
	}

	/**
	 * @param string $name  Field name.
	 * @param array  $lines Lines.
	 * @param int    $rows  Rows.
	 * @return string HTML.
	 */
	private function textarea( $name, array $lines, $rows = 5 ) {
		$id = 'wpcs-' . str_replace( '_', '-', $name );
		return '<textarea id="' . esc_attr( $id ) . '" name="' . esc_attr( $name ) . '" rows="' . (int) $rows . '" spellcheck="false">' . esc_textarea( implode( "\n", $lines ) ) . '</textarea>';
	}

	/**
	 * @param string $text Text.
	 * @param string $type ok | medium | high | info | muted | critical | pending.
	 * @return string HTML.
	 */
	private function badge( $text, $type ) {
		return '<span class="wpcs-badge wpcs-badge--' . esc_attr( $type ) . '">' . esc_html( $text ) . '</span>';
	}

	/**
	 * GET link to an admin-post action, protected by a nonce.
	 *
	 * @param string $action Action without the wpcybersec_ prefix.
	 * @param array  $args   Extra args.
	 * @return string
	 */
	private function action_url( $action, array $args = array() ) {
		$url = add_query_arg( array_merge( array( 'action' => 'wpcybersec_' . $action ), $args ), admin_url( 'admin-post.php' ) );
		return wp_nonce_url( $url, 'wpcybersec_' . $action );
	}

	/* ------------------------------------------------------------------ */
	/* General tab                                                         */
	/* ------------------------------------------------------------------ */

	/**
	 * Site owner settings.
	 */
	private function render_general() {
		$s      = $this->settings();
		$labels = self::labels();

		$this->form_open( 'general' );

		$this->card_open( 'wpcs-level', 'shield', __( 'Protection level', 'wp-cyber-security' ), __( 'Pick a starting point. The settings below follow the level you pick; changing one of them makes the level Custom.', 'wp-cyber-security' ) );
		if ( 'custom' === $s['protection_level'] ) {
			self::notice( __( 'Custom: your settings do not match a preset. Pick a level to reset the settings below to its values.', 'wp-cyber-security' ), 'info' );
		}
		echo self::level_cards( 'protection_level', $s['protection_level'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in level_cards().
		echo '<input type="hidden" name="wpcs_level_synced" value="0" data-wpcs-level-synced>';
		echo '<p class="wpcs-custom-hint wpcs-hidden" data-wpcs-custom-hint></p>';
		$this->card_close();

		// Uploads.
		$this->card_open( 'wpcs-uploads', 'upload', __( 'Uploads', 'wp-cyber-security' ), __( 'Files added through the Media Library, the block editor, the REST API and plugins that use the WordPress upload functions.', 'wp-cyber-security' ) );
		$this->field(
			__( 'When a file is uploaded', 'wp-cyber-security' ),
			self::radio_list(
				'upload_mode',
				array(
					'hold_all'   => array( __( 'Hold every upload', 'wp-cyber-security' ), __( 'Every new file waits for approval, unless the same file was approved before. Safest.', 'wp-cyber-security' ) ),
					'hold_risky' => array( __( 'Hold risky uploads', 'wp-cyber-security' ), __( 'Holds scripts, archives, SVG and HTML files, files whose content does not match the extension, and anything that looks malicious. Ordinary images and documents pass.', 'wp-cyber-security' ) ),
					'scan_only'  => array( __( 'Scan only', 'wp-cyber-security' ), __( 'Uploads pass unless they contain known malware.', 'wp-cyber-security' ) ),
					'off'        => array( __( 'Off', 'wp-cyber-security' ), __( 'Uploads are not checked.', 'wp-cyber-security' ) ),
				),
				$s['upload_mode']
			)
		);
		$roles_html = '<div class="wpcs-check-grid">';
		$roles      = function_exists( 'wp_roles' ) ? wp_roles()->get_names() : array( 'administrator' => 'Administrator' );
		foreach ( $roles as $role => $name ) {
			$roles_html .= '<label class="wpcs-check-inline"><input type="checkbox" name="upload_bypass_roles[]" value="' . esc_attr( $role ) . '"' . checked( in_array( $role, (array) $s['upload_bypass_roles'], true ), true, false ) . '> ' . esc_html( translate_user_role( $name ) ) . '</label>';
		}
		$roles_html .= '</div>';
		$this->field(
			__( 'Clean uploads pass for', 'wp-cyber-security' ),
			$roles_html,
			__( 'Uploads from these roles are still scanned. Anything that looks malicious is always held.', 'wp-cyber-security' )
		);
		$this->field(
			__( 'Files downloaded by WordPress', 'wp-cyber-security' ),
			self::toggle_row( 'gate_sideloads', ! empty( $s['gate_sideloads'] ), __( 'Also hold files that WordPress downloads from other sites', 'wp-cyber-security' ), __( 'For example images fetched by importers or by plugins that call media_sideload_image().', 'wp-cyber-security' ) )
		);
		$this->card_close();

		// Installs.
		$this->card_open( 'wpcs-installs', 'admin-plugins', __( 'Plugin and theme installs', 'wp-cyber-security' ) );
		$this->field(
			__( 'New plugins and themes', 'wp-cyber-security' ),
			self::toggle_row( 'install_mode', 'hold' === $s['install_mode'], __( 'Hold new plugin and theme installs until approved', 'wp-cyber-security' ), __( 'Approved installs are remembered, so reinstalling the same plugin or theme is not held again.', 'wp-cyber-security' ), array(), 'hold', 'off' )
		);
		$this->field(
			__( 'Updates', 'wp-cyber-security' ),
			self::toggle_row( 'hold_updates', ! empty( $s['hold_updates'] ), __( 'Also hold updates of installed plugins and themes', 'wp-cyber-security' ), __( 'Turn this on only if you want to approve every update by hand. Updated files are checked against the official checksums either way.', 'wp-cyber-security' ) )
		);
		$this->card_close();

		// File monitor.
		$this->card_open( 'wpcs-monitor', 'media-code', __( 'File monitor', 'wp-cyber-security' ), __( 'What happens with files that appear or change on the server outside of WordPress, for example through FTP or a hacked plugin.', 'wp-cyber-security' ) );
		$this->field(
			__( 'New unknown code files', 'wp-cyber-security' ),
			self::radio_list(
				'file_mode',
				array(
					'quarantine_exec' => array( __( 'Move to quarantine', 'wp-cyber-security' ), __( 'New PHP and other executable files are moved away until you approve them. Not for development sites where you edit code.', 'wp-cyber-security' ) ),
					'report'          => array( __( 'Report only', 'wp-cyber-security' ), __( 'New files stay in place and appear on the Reports page for review.', 'wp-cyber-security' ) ),
					'off'             => array( __( 'Off', 'wp-cyber-security' ), __( 'New files are not reported. Malware is still detected.', 'wp-cyber-security' ) ),
				),
				$s['file_mode']
			)
		);
		$this->field(
			__( 'Changed code files', 'wp-cyber-security' ),
			self::radio_list(
				'modified_action',
				array(
					'report'     => array( __( 'Report', 'wp-cyber-security' ), __( 'Changed files stay in place and are listed for review.', 'wp-cyber-security' ) ),
					'quarantine' => array( __( 'Move to quarantine', 'wp-cyber-security' ), __( 'Changed files are moved away until you approve them. The site may break until you do.', 'wp-cyber-security' ) ),
				),
				$s['modified_action']
			)
		);
		$this->field(
			__( 'Critical malware', 'wp-cyber-security' ),
			self::toggle_row( 'auto_quarantine', ! empty( $s['auto_quarantine'] ), __( 'Move files with critical malware to quarantine automatically', 'wp-cyber-security' ), __( 'Only for hits rated critical, such as known web shells. You can restore a file from the Reports page.', 'wp-cyber-security' ) )
		);
		$this->card_close();

		// Scanning.
		$this->card_open( 'wpcs-scanning', 'search', __( 'Scanning', 'wp-cyber-security' ) );
		$this->field(
			__( 'Scheduled scans', 'wp-cyber-security' ),
			$this->select( 'scan_schedule', $labels['scan_schedule'], $s['scan_schedule'] ),
			__( 'Scheduled scans only check new and changed files, so they are quick. Use a real cron job for exact timing (Advanced tab).', 'wp-cyber-security' ),
			'wpcs-scan-schedule'
		);
		$this->field(
			__( 'Malware check', 'wp-cyber-security' ),
			self::toggle_row( 'scan_malware', ! empty( $s['scan_malware'] ), __( 'Check new and changed files for malware during scheduled scans', 'wp-cyber-security' ) )
		);
		$this->field(
			__( 'Report findings from', 'wp-cyber-security' ),
			$this->select(
				'min_severity',
				array(
					'1' => __( 'Medium severity and above', 'wp-cyber-security' ),
					'2' => __( 'High severity and above', 'wp-cyber-security' ),
					'3' => __( 'Critical only', 'wp-cyber-security' ),
				),
				(string) $s['min_severity']
			),
			__( 'Medium findings include suspicious but sometimes legitimate code, such as obfuscation in commercial plugins.', 'wp-cyber-security' ),
			'wpcs-min-severity'
		);
		$this->field(
			__( 'Official checksums', 'wp-cyber-security' ),
			self::toggle_row( 'use_checksums', ! empty( $s['use_checksums'] ), __( 'Verify WordPress core and wordpress.org plugins against their official checksums', 'wp-cyber-security' ), __( 'Files that match the official release are trusted automatically, for example after updates.', 'wp-cyber-security' ) )
		);
		$this->field(
			__( 'Show what changed', 'wp-cyber-security' ),
			self::toggle_row( 'snapshots', ! empty( $s['snapshots'] ), __( 'Keep copies of PHP and config files so you can see exactly what changed', 'wp-cyber-security' ), __( 'A compressed copy of each trusted version is kept in the private data folder, so a modified file can be compared line by line. Passwords and keys are hidden when shown. Files that match an official WordPress.org checksum are not copied: the original is downloaded when needed.', 'wp-cyber-security' ) )
		);
		$this->field(
			__( 'Largest file to copy', 'wp-cyber-security' ),
			$this->number( 'snapshot_max_kb', $s['snapshot_max_kb'], 16, 4096, __( 'KB', 'wp-cyber-security' ) ),
			__( 'Bigger files are still checked, but no copy is kept, so their changes cannot be shown line by line.', 'wp-cyber-security' ),
			'wpcs-snapshot-max-kb'
		);
		$this->card_close();

		// Notifications.
		$emails = $s['notify_emails'] ? (array) $s['notify_emails'] : array();
		$this->card_open( 'wpcs-notifications', 'email-alt', __( 'Notifications', 'wp-cyber-security' ) );
		$this->field( __( 'Send alerts', 'wp-cyber-security' ), self::notify_mode_choices( $s['notify_mode'] ) );
		$emails_html  = '<textarea id="wpcs-notify-emails" name="notify_emails" rows="3" class="wpcs-textarea-sm" spellcheck="false" placeholder="' . esc_attr( get_option( 'admin_email' ) ) . '">' . esc_textarea( implode( "\n", $emails ) ) . '</textarea>';
		$emails_html .= '<span class="wpcs-field__help">' . esc_html(
			/* translators: %s: email address */
			sprintf( __( 'One address per line. Empty means the site admin email (%s).', 'wp-cyber-security' ), get_option( 'admin_email' ) )
		) . '</span>';
		$emails_html .= '<p class="wpcs-inline-actions"><button type="submit" name="wpcs_send_test" value="1" class="button" data-wpcs-test-email data-source="#wpcs-notify-emails"><span class="dashicons dashicons-email-alt" aria-hidden="true"></span>' . esc_html__( 'Send test email', 'wp-cyber-security' ) . '</button></p>';
		$this->field( __( 'Email recipients', 'wp-cyber-security' ), $emails_html, '', 'wpcs-notify-emails' );
		$this->field(
			__( 'Webhook URL', 'wp-cyber-security' ),
			'<input type="url" id="wpcs-webhook-url" name="webhook_url" value="' . esc_attr( $s['webhook_url'] ) . '" placeholder="https://hooks.slack.com/services/..." autocomplete="off">',
			__( 'Optional. Posts a short message to Slack, Discord, Microsoft Teams or any service that accepts incoming webhooks. Must start with https://.', 'wp-cyber-security' ),
			'wpcs-webhook-url'
		);
		$this->card_close();

		$this->form_close( __( 'Changes apply as soon as you save.', 'wp-cyber-security' ) );
	}

	/* ------------------------------------------------------------------ */
	/* Advanced tab                                                        */
	/* ------------------------------------------------------------------ */

	/**
	 * System administrator settings and tools.
	 */
	private function render_advanced() {
		$s     = $this->settings();
		$tools = $this->tools();

		$toc = array(
			'wpcs-health'       => __( 'Server health', 'wp-cyber-security' ),
			'wpcs-storage'      => __( 'Storage', 'wp-cyber-security' ),
			'wpcs-scan'         => __( 'Scan scope', 'wp-cyber-security' ),
			'wpcs-guard'        => __( 'Early guard', 'wp-cyber-security' ),
			'wpcs-cron'         => __( 'Real cron', 'wp-cyber-security' ),
			'wpcs-freeze'       => __( 'Freeze lock', 'wp-cyber-security' ),
			'wpcs-hardening'    => __( 'Web server', 'wp-cyber-security' ),
			'wpcs-integrations' => __( 'Integrations', 'wp-cyber-security' ),
			'wpcs-clamav'       => __( 'ClamAV', 'wp-cyber-security' ),
			'wpcs-tamper'       => __( 'Tamper check', 'wp-cyber-security' ),
			'wpcs-data'         => __( 'Data', 'wp-cyber-security' ),
			'wpcs-transfer'     => __( 'Import and export', 'wp-cyber-security' ),
		);
		echo '<nav class="wpcs-toc" aria-label="' . esc_attr__( 'Advanced sections', 'wp-cyber-security' ) . '">';
		foreach ( $toc as $id => $label ) {
			echo '<a href="#' . esc_attr( $id ) . '">' . esc_html( $label ) . '</a>';
		}
		echo '</nav>';

		// Server health: open recommendations with one-click fixes (outside the settings form).
		try {
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read only.
			$checks    = $tools->diagnostics( ! empty( $_GET['recheck'] ) );
			$attention = array_values(
				array_filter(
					$checks,
					static function ( $c ) {
						return in_array( $c['status'], array( 'warn', 'fail' ), true );
					}
				)
			);
			$this->card_open( 'wpcs-health', 'heart', __( 'Server health', 'wp-cyber-security' ), __( 'Recommendations for this server. Use the buttons to fix them here, or follow the steps to do it by hand.', 'wp-cyber-security' ) );
			if ( $attention ) {
				$fixable = self::auto_fix_ids( $attention );
				if ( $fixable ) {
					echo '<div class="wpcs-fixall"><div><strong>' . esc_html(
						/* translators: %d: number of items */
						sprintf( _n( '%d item can be fixed for you', '%d items can be fixed for you', count( $fixable ), 'wp-cyber-security' ), count( $fixable ) )
					) . '</strong></div><button type="button" class="button button-primary" data-wpcs-fix-all="' . esc_attr( implode( ',', $fixable ) ) . '">' . esc_html__( 'Fix them all', 'wp-cyber-security' ) . '</button></div>';
				}
				self::render_checks( $attention, false );
			} else {
				self::notice( __( 'No open recommendations. Everything important looks good.', 'wp-cyber-security' ), 'ok' );
			}
			$this->card_close();
		} catch ( \Throwable $e ) {
			if ( $this->card_is_open ) {
				$this->card_close();
			}
		}

		$this->form_open( 'advanced' );
		$sections = array( 'section_storage', 'section_scan', 'section_guard', 'section_cron', 'section_freeze', 'section_hardening', 'section_integrations', 'section_clamav', 'section_tamper', 'section_data' );
		foreach ( $sections as $section ) {
			try {
				$this->$section( $s, $tools );
			} catch ( \Throwable $e ) {
				/* translators: %s: error message */
				self::notice( sprintf( __( 'This section could not be shown: %s', 'wp-cyber-security' ), $e->getMessage() ), 'bad' );
				if ( $this->card_is_open ) {
					$this->card_close();
				}
			}
		}
		$this->form_close( __( 'Saves the fields on this tab. The buttons inside the cards act immediately.', 'wp-cyber-security' ) );

		$this->section_transfer();
	}

	/**
	 * @param array          $s     Settings.
	 * @param Sysadmin_Tools $tools Tools.
	 */
	private function section_storage( array $s, Sysadmin_Tools $tools ) {
		$storage = Sysadmin_Tools::service( 'storage' );
		$storage = $storage ? $storage : new \WPCyberSecurity\Storage();
		$dir     = $storage->data_dir();
		$in_root = $storage->is_in_webroot( $dir );

		$this->card_open( 'wpcs-storage', 'database', __( 'Storage', 'wp-cyber-security' ), __( 'Quarantined files, scan job files, the early guard configuration and its upload spool live in the data folder.', 'wp-cyber-security' ) );

		$badges  = is_dir( $dir ) && wp_is_writable( $dir ) ? $this->badge( __( 'Writable', 'wp-cyber-security' ), 'ok' ) : $this->badge( __( 'Not writable', 'wp-cyber-security' ), 'high' );
		$badges .= ' ' . ( $in_root ? $this->badge( __( 'Inside the web root', 'wp-cyber-security' ), 'medium' ) : $this->badge( __( 'Outside the web root', 'wp-cyber-security' ), 'ok' ) );
		if ( defined( 'WPCYBERSEC_DATA_DIR' ) && WPCYBERSEC_DATA_DIR ) {
			$badges .= ' ' . $this->badge( __( 'Set by WPCYBERSEC_DATA_DIR', 'wp-cyber-security' ), 'info' );
		}
		$this->field( __( 'Data folder', 'wp-cyber-security' ), '<code class="wpcs-path">' . esc_html( $dir ) . '</code><div class="wpcs-badges">' . $badges . '</div>' );

		$probe = $tools->probe_quarantine_web( false );
		switch ( $probe['result'] ) {
			case 'outside':
				$web = $this->badge( __( 'Not reachable', 'wp-cyber-security' ), 'ok' ) . ' ' . esc_html__( 'The folder is outside the web root.', 'wp-cyber-security' );
				break;
			case 'blocked':
				/* translators: %d: HTTP status code */
				$web = $this->badge( __( 'Blocked', 'wp-cyber-security' ), 'ok' ) . ' ' . esc_html( sprintf( __( 'A test file could not be downloaded (HTTP %d).', 'wp-cyber-security' ), $probe['code'] ) );
				break;
			case 'reachable':
				$web = $this->badge( __( 'Reachable', 'wp-cyber-security' ), 'high' ) . ' ' . esc_html__( 'A test file could be downloaded: the server ignores the .htaccess deny rules. Add the nginx rule from the Web server card or move the folder.', 'wp-cyber-security' );
				break;
			default:
				$web = $this->badge( __( 'Not tested', 'wp-cyber-security' ), 'muted' ) . ' ' . esc_html( $probe['message'] ? $probe['message'] : __( 'The site could not reach itself to test this.', 'wp-cyber-security' ) );
		}
		$this->field( __( 'Web access test', 'wp-cyber-security' ), '<div class="wpcs-inline-status">' . $web . '</div>' );

		if ( $in_root ) {
			$snippet = $tools->data_dir_snippet();
			$this->field(
				__( 'Move it outside the web root', 'wp-cyber-security' ),
				self::code( $snippet['shell'], __( 'Shell (as root)', 'wp-cyber-security' ) ) . self::code( $snippet['config'], 'wp-config.php' ),
				__( 'Run the commands, then add the line to wp-config.php above "That\'s all, stop editing!". The plugin switches to the new folder on the next page load.', 'wp-cyber-security' )
			);
		}
		$this->card_close();
	}

	/**
	 * @param array          $s     Settings.
	 * @param Sysadmin_Tools $tools Tools.
	 */
	private function section_scan( array $s, Sysadmin_Tools $tools ) {
		unset( $tools );
		$abspath = untrailingslashit( wp_normalize_path( ABSPATH ) );
		$parent  = dirname( $abspath );

		$this->card_open( 'wpcs-scan', 'search', __( 'Scan scope and performance', 'wp-cyber-security' ) );

		$root  = self::radio_list(
			'scan_root',
			array(
				'abspath' => array( __( 'WordPress folder', 'wp-cyber-security' ), $abspath ),
				/* translators: %s: folder path */
				'parent'  => array( __( 'Parent folder', 'wp-cyber-security' ), sprintf( __( '%s - also checks files next to WordPress, such as other apps or forgotten backups.', 'wp-cyber-security' ), $parent ) ),
				'custom'  => array( __( 'Custom folder', 'wp-cyber-security' ), __( 'Any folder that contains the site.', 'wp-cyber-security' ) ),
			),
			$s['scan_root']
		);
		$root .= '<div class="wpcs-indent' . ( 'custom' === $s['scan_root'] ? '' : ' wpcs-hidden' ) . '" data-wpcs-scan-root-custom><input type="text" name="scan_root_custom" value="' . esc_attr( $s['scan_root_custom'] ) . '" placeholder="' . esc_attr( $parent ) . '" class="wpcs-mono" aria-label="' . esc_attr__( 'Custom scan folder', 'wp-cyber-security' ) . '"></div>';
		$this->field( __( 'Scan folder', 'wp-cyber-security' ), $root, __( 'After changing the folder, rebuild the baseline from the Dashboard, otherwise every file is reported as new.', 'wp-cyber-security' ) );

		$this->field(
			__( 'Exclusions', 'wp-cyber-security' ),
			$this->textarea( 'exclusions', (array) $s['exclusions'], 6 ),
			__( 'One per line, relative to the scan folder. Folders end with /, and the wildcards * and ? work (for example *.log). The data folder is always excluded.', 'wp-cyber-security' ),
			'wpcs-exclusions'
		);
		$this->field(
			__( 'Largest file to check', 'wp-cyber-security' ),
			$this->number( 'max_file_mb', $s['max_file_mb'], 1, 512, __( 'MB', 'wp-cyber-security' ) ),
			__( 'Bigger files are fingerprinted but not searched for malware.', 'wp-cyber-security' ),
			'wpcs-max-file-mb'
		);
		$this->field(
			__( 'Work per scan step', 'wp-cyber-security' ),
			$this->number( 'tick_seconds', $s['tick_seconds'], 3, 25, __( 'seconds', 'wp-cyber-security' ) ),
			__( 'How long each step of a scan runs. Lower it if scans time out on shared hosting.', 'wp-cyber-security' ),
			'wpcs-tick-seconds'
		);
		$this->field(
			__( 'Executable extensions', 'wp-cyber-security' ),
			'<input type="text" id="wpcs-exec-extensions" name="exec_extensions" value="' . esc_attr( implode( ', ', (array) $s['exec_extensions'] ) ) . '" class="wpcs-mono">',
			__( 'Comma separated. Matched anywhere in the name, so shell.php.jpg counts too. php, phtml and phar are always included.', 'wp-cyber-security' ),
			'wpcs-exec-extensions'
		);
		$this->field(
			__( 'Executable file names', 'wp-cyber-security' ),
			'<input type="text" id="wpcs-exec-filenames" name="exec_filenames" value="' . esc_attr( implode( ', ', (array) $s['exec_filenames'] ) ) . '" class="wpcs-mono">',
			__( 'Comma separated. Server configuration files that change how code runs. .htaccess and .user.ini are always included.', 'wp-cyber-security' ),
			'wpcs-exec-filenames'
		);
		$this->card_close();
	}

	/**
	 * @param array          $s     Settings.
	 * @param Sysadmin_Tools $tools Tools.
	 */
	private function section_guard( array $s, Sysadmin_Tools $tools ) {
		unset( $tools );
		$manager = Sysadmin_Tools::service( 'guard_manager' );
		$this->card_open( 'wpcs-guard', 'shield-alt', __( 'Early upload guard', 'wp-cyber-security' ), __( 'Runs before any PHP code through auto_prepend_file and holds files uploaded to ANY PHP script on this site, not only WordPress. Held files appear on the Reports page like other uploads.', 'wp-cyber-security' ) );

		if ( ! $manager || ! method_exists( $manager, 'status' ) ) {
			self::notice( __( 'The early guard module is not available in this installation.', 'wp-cyber-security' ), 'bad' );
			$this->card_close();
			return;
		}
		$status = Sysadmin_Tools::call( 'guard_manager', 'status', array(), array() );
		$status = is_array( $status ) ? $status : array();
		$yes    = __( 'Yes', 'wp-cyber-security' );
		$no     = __( 'No', 'wp-cyber-security' );

		$rows = array(
			array( __( 'Installed', 'wp-cyber-security' ), ! empty( $status['installed'] ) ? $this->badge( $yes, 'ok' ) : $this->badge( $no, 'muted' ) ),
			array( __( 'Active in this request', 'wp-cyber-security' ), ! empty( $status['active'] ) ? $this->badge( $yes, 'ok' ) : $this->badge( $no, empty( $status['installed'] ) ? 'muted' : 'medium' ) ),
			array(
				__( 'Bootstrap file', 'wp-cyber-security' ),
				'<code class="wpcs-path">' . esc_html( isset( $status['bootstrap_path'] ) ? $status['bootstrap_path'] : '' ) . '</code> '
				. ( ! empty( $status['bootstrap_exists'] ) ? $this->badge( __( 'Exists', 'wp-cyber-security' ), 'ok' ) : $this->badge( __( 'Missing', 'wp-cyber-security' ), 'muted' ) ),
			),
			array( 'auto_prepend_file', ! empty( $status['prepend'] ) ? '<code class="wpcs-path">' . esc_html( $status['prepend'] ) . '</code>' : esc_html__( 'Not set', 'wp-cyber-security' ) ),
			array( __( 'Conflict', 'wp-cyber-security' ), ! empty( $status['conflict'] ) ? '<code class="wpcs-path">' . esc_html( $status['conflict'] ) . '</code>' : esc_html__( 'None', 'wp-cyber-security' ) ),
			array( __( 'PHP SAPI', 'wp-cyber-security' ), esc_html( isset( $status['sapi'] ) ? $status['sapi'] : PHP_SAPI ) ),
			array( __( 'Uploads waiting to be imported', 'wp-cyber-security' ), esc_html( number_format_i18n( isset( $status['pending_spool'] ) ? (int) $status['pending_spool'] : 0 ) ) ),
		);
		echo '<table class="wpcs-status-table"><tbody>';
		foreach ( $rows as $row ) {
			echo '<tr><th scope="row">' . esc_html( $row[0] ) . '</th><td>' . $row[1] . '</td></tr>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built from escaped parts.
		}
		echo '</tbody></table>';

		if ( ! empty( $status['conflict'] ) ) {
			$help = ! empty( $status['conflict_help'] ) ? (string) $status['conflict_help'] : __( 'Another file already uses auto_prepend_file. The guard bootstrap includes it so both keep working, but check the snippets below before you change the PHP configuration.', 'wp-cyber-security' );
			self::notice( $help, 'warn' );
			if ( ! empty( $status['conflict_snippet'] ) ) {
				echo self::code( (string) $status['conflict_snippet'], __( 'Add at the top of the other prepend file', 'wp-cyber-security' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in code().
			}
		} elseif ( ! empty( $status['installed'] ) && empty( $status['active'] ) ) {
			self::notice( __( 'Installed, but PHP does not load it yet. Set auto_prepend_file with the recommended snippet below (or the button that writes .user.ini), then reload this page.', 'wp-cyber-security' ), 'warn' );
		}

		echo '<div class="wpcs-row wpcs-card__actions">';
		if ( empty( $status['installed'] ) ) {
			echo '<a class="button button-primary" href="' . esc_url( $this->action_url( 'guard', array( 'op' => 'install' ) ) ) . '"><span class="dashicons dashicons-download" aria-hidden="true"></span>' . esc_html__( 'Install the early guard', 'wp-cyber-security' ) . '</a>';
		} else {
			echo '<a class="button" href="' . esc_url( $this->action_url( 'guard', array( 'op' => 'install' ) ) ) . '"><span class="dashicons dashicons-update" aria-hidden="true"></span>' . esc_html__( 'Reinstall', 'wp-cyber-security' ) . '</a>';
			echo '<a class="button wpcs-btn-danger" href="' . esc_url( $this->action_url( 'guard', array( 'op' => 'uninstall' ) ) ) . '" data-wpcs-confirm="' . esc_attr__( 'Switch the early guard off? Uploads to scripts outside WordPress will no longer be held.', 'wp-cyber-security' ) . '">' . esc_html__( 'Uninstall', 'wp-cyber-security' ) . '</a>';
		}
		if ( method_exists( $manager, 'write_user_ini' ) ) {
			echo '<a class="button" href="' . esc_url( $this->action_url( 'guard', array( 'op' => 'write_user_ini' ) ) ) . '"><span class="dashicons dashicons-media-text" aria-hidden="true"></span>' . esc_html__( 'Write .user.ini for me', 'wp-cyber-security' ) . '</a>';
		}
		echo '<span class="wpcs-muted wpcs-inline-help">' . esc_html__( '.user.ini works with PHP-FPM and CGI. For mod_php or a server-wide setting, use one of the snippets below.', 'wp-cyber-security' ) . '</span>';
		echo '</div>';

		$this->field(
			__( 'When an upload is held', 'wp-cyber-security' ),
			self::radio_list(
				'guard_action',
				array(
					'block' => array( __( 'Block the request', 'wp-cyber-security' ), __( 'The script answers HTTP 403 with a short message and never runs. Safest.', 'wp-cyber-security' ) ),
					'strip' => array( __( 'Remove the file and continue', 'wp-cyber-security' ), __( 'The script runs as if no file was sent. Use this if blocking breaks a form you need.', 'wp-cyber-security' ) ),
				),
				$s['guard_action']
			)
		);
		$this->field(
			__( 'Not checked by the guard', 'wp-cyber-security' ),
			$this->textarea( 'guard_exempt', (array) $s['guard_exempt'], 5 ),
			__( 'Requests whose path or query contains one of these lines are skipped. WordPress media uploads are already checked by the plugin itself, so they are listed here by default.', 'wp-cyber-security' ),
			'wpcs-guard-exempt'
		);

		$snippets = Sysadmin_Tools::call( 'guard_manager', 'snippets', array(), array() );
		if ( is_array( $snippets ) && $snippets ) {
			$recommended = array();
			$others      = array();
			foreach ( $snippets as $snippet ) {
				if ( ! is_array( $snippet ) || empty( $snippet['code'] ) ) {
					continue;
				}
				if ( ! empty( $snippet['recommended'] ) && ! $recommended ) {
					$recommended[] = $snippet;
				} else {
					$others[] = $snippet;
				}
			}
			if ( $recommended && empty( $status['active'] ) ) {
				echo '<h3 class="wpcs-subhead">' . esc_html__( 'Recommended for this server', 'wp-cyber-security' ) . ' ' . $this->badge( isset( $status['sapi'] ) ? (string) $status['sapi'] : PHP_SAPI, 'info' ) . '</h3>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- badge is escaped.
				$this->render_snippet( $recommended[0] );
			} else {
				$others = array_merge( $recommended, $others );
			}
			if ( $others ) {
				echo '<details class="wpcs-disclosure"><summary>' . esc_html__( 'Other ways to set auto_prepend_file (.user.ini, Apache, PHP-FPM, nginx, php.ini)', 'wp-cyber-security' ) . '</summary>';
				foreach ( $others as $snippet ) {
					$this->render_snippet( $snippet );
				}
				echo '</details>';
			}
		}
		$this->card_close();
	}

	/**
	 * One guard configuration snippet.
	 *
	 * @param array $snippet { label, file, code, help }.
	 */
	private function render_snippet( array $snippet ) {
		$label = isset( $snippet['label'] ) ? (string) $snippet['label'] : '';
		if ( ! empty( $snippet['file'] ) ) {
			$label .= ( '' !== $label ? ' - ' : '' ) . $snippet['file'];
		}
		echo self::code( (string) $snippet['code'], $label, isset( $snippet['help'] ) ? (string) $snippet['help'] : '' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in code().
	}

	/**
	 * @param array          $s     Settings.
	 * @param Sysadmin_Tools $tools Tools.
	 */
	private function section_cron( array $s, Sysadmin_Tools $tools ) {
		$this->card_open( 'wpcs-cron', 'clock', __( 'Real cron', 'wp-cyber-security' ), __( 'WordPress runs scheduled tasks only when someone visits the site. A cron job on the server makes scans run on time and lets long scans finish without a browser.', 'wp-cyber-security' ) );
		$disabled = defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON;
		$next     = wp_next_scheduled( 'wpcybersec_scheduled_scan' );
		$state    = $disabled ? $this->badge( __( 'WP-Cron on page visits is off', 'wp-cyber-security' ), 'ok' ) : $this->badge( __( 'WP-Cron runs on page visits', 'wp-cyber-security' ), 'muted' );
		if ( $next ) {
			$state .= ' <span class="wpcs-muted">' . esc_html(
				/* translators: %s: date and time */
				sprintf( __( 'Next scheduled scan: %s', 'wp-cyber-security' ), wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $next ) )
			) . '</span>';
		} elseif ( 'off' !== $s['scan_schedule'] ) {
			$state .= ' <span class="wpcs-muted">' . esc_html__( 'No scan is scheduled yet.', 'wp-cyber-security' ) . '</span>';
		}
		echo '<div class="wpcs-inline-status wpcs-card__lead">' . $state . '</div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built from escaped parts.
		foreach ( $tools->cron_snippets() as $snippet ) {
			echo self::code( $snippet['code'], $snippet['label'] . ' - ' . $snippet['file'], $snippet['help'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in code().
		}
		$this->card_close();
	}

	/**
	 * @param array          $s     Settings.
	 * @param Sysadmin_Tools $tools Tools.
	 */
	private function section_freeze( array $s, Sysadmin_Tools $tools ) {
		unset( $tools );
		$gate = Sysadmin_Tools::service( 'install_gate' );
		$this->card_open( 'wpcs-freeze', 'lock', __( 'Freeze lock', 'wp-cyber-security' ), __( 'While frozen, nobody can install, update, delete or edit plugins, themes or WordPress core from the dashboard, even with a stolen administrator login.', 'wp-cyber-security' ) );
		$this->field(
			__( 'Freeze mode', 'wp-cyber-security' ),
			self::toggle_row( 'freeze_mods', ! empty( $s['freeze_mods'] ), __( 'Freeze plugins, themes and core', 'wp-cyber-security' ), __( 'Unlock for a few minutes when you want to update. Updates through WP-CLI or SFTP are not affected.', 'wp-cyber-security' ) )
		);
		$this->field(
			__( 'Unlock for', 'wp-cyber-security' ),
			$this->number( 'unlock_minutes', $s['unlock_minutes'], 1, 240, __( 'minutes', 'wp-cyber-security' ) ),
			'',
			'wpcs-unlock-minutes'
		);
		$this->field(
			__( 'Code editor', 'wp-cyber-security' ),
			self::toggle_row( 'disable_file_editor', ! empty( $s['disable_file_editor'] ), __( 'Turn off the theme and plugin file editor', 'wp-cyber-security' ), __( 'Same as DISALLOW_FILE_EDIT in wp-config.php. When wp-config.php already sets that constant, it wins.', 'wp-cyber-security' ) )
		);

		if ( ! $gate || ! method_exists( $gate, 'unlocked_until' ) ) {
			$this->field( __( 'Current state', 'wp-cyber-security' ), '<span class="wpcs-muted">' . esc_html__( 'The install gate module is not available.', 'wp-cyber-security' ) . '</span>' );
		} else {
			$until = (int) Sysadmin_Tools::call( 'install_gate', 'unlocked_until', array(), 0 );
			if ( $until > time() ) {
				/* translators: %s: time */
				$text = sprintf( __( 'Unlocked until %s', 'wp-cyber-security' ), wp_date( get_option( 'time_format' ), $until ) );
				$type = 'medium';
			} else {
				$text = __( 'Locked', 'wp-cyber-security' );
				$type = 'ok';
			}
			$html  = '<div class="wpcs-row">';
			$html .= '<span class="wpcs-badge wpcs-badge--' . esc_attr( $type ) . '" data-wpcs-lock-state>' . esc_html( $text ) . '</span>';
			$html .= '<button type="button" class="button" data-wpcs-unlock data-minutes-input="#wpcs-unlock-minutes"><span class="dashicons dashicons-unlock" aria-hidden="true"></span>' . esc_html__( 'Unlock now', 'wp-cyber-security' ) . '</button>';
			$html .= '<button type="button" class="button" data-wpcs-lock><span class="dashicons dashicons-lock" aria-hidden="true"></span>' . esc_html__( 'Lock now', 'wp-cyber-security' ) . '</button>';
			$html .= '</div>';
			$help = empty( $s['freeze_mods'] ) ? __( 'Freeze mode is off, so changes are allowed anyway. Turn it on and save to use the lock.', 'wp-cyber-security' ) : '';
			$this->field( __( 'Current state', 'wp-cyber-security' ), $html, $help );
		}
		$this->card_close();
	}

	/**
	 * @param array          $s     Settings.
	 * @param Sysadmin_Tools $tools Tools.
	 */
	private function section_hardening( array $s, Sysadmin_Tools $tools ) {
		unset( $s );
		$status = $tools->uploads_htaccess_status();
		$server = Sysadmin_Tools::server_type();
		$this->card_open( 'wpcs-hardening', 'admin-site-alt3', __( 'Web server hardening', 'wp-cyber-security' ), __( 'Stop PHP from running where it never should, and keep private folders private.', 'wp-cyber-security' ) );

		$labels = array(
			'ours'  => $this->badge( __( 'WP Cyber Security rules present', 'wp-cyber-security' ), 'ok' ),
			'other' => $this->badge( __( 'Blocking rules present', 'wp-cyber-security' ), 'ok' ),
			'none'  => $this->badge( __( 'No blocking rule', 'wp-cyber-security' ), 'medium' ),
		);
		echo '<h3 class="wpcs-subhead">' . esc_html__( 'Apache and LiteSpeed', 'wp-cyber-security' ) . ' ' . $labels[ $status ] . '</h3>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- badge is escaped.
		echo '<div class="wpcs-row wpcs-card__actions">';
		echo '<a class="button" href="' . esc_url( $this->action_url( 'write_htaccess' ) ) . '"><span class="dashicons dashicons-media-text" aria-hidden="true"></span>' . esc_html( 'ours' === $status ? __( 'Refresh uploads/.htaccess rules', 'wp-cyber-security' ) : __( 'Write uploads/.htaccess for me', 'wp-cyber-security' ) ) . '</a>';
		echo '<span class="wpcs-muted wpcs-inline-help">' . esc_html__( 'Adds the block between markers and keeps everything else. If the server answers with an error afterwards, the change is undone.', 'wp-cyber-security' ) . '</span>';
		echo '</div>';
		echo self::code( $tools->apache_uploads_rules(), 'wp-content/uploads/.htaccess' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in code().

		echo '<h3 class="wpcs-subhead">nginx' . ( 'nginx' === $server ? ' ' . $this->badge( __( 'This server', 'wp-cyber-security' ), 'info' ) : '' ) . '</h3>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- badge is escaped.
		echo self::code( $tools->nginx_rules(), __( 'Server block', 'wp-cyber-security' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in code().

		echo '<h3 class="wpcs-subhead">' . esc_html__( 'File permissions', 'wp-cyber-security' ) . '</h3>';
		echo self::code( $tools->permission_commands(), __( 'Shell', 'wp-cyber-security' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in code().
		echo '<p class="wpcs-muted">';
		printf(
			/* translators: %s: link to the environment check */
			esc_html__( 'To test whether PHP really is blocked in uploads, run the live test in the %s.', 'wp-cyber-security' ),
			'<a href="' . esc_url( Sysadmin_Tools::wizard_url( 'environment' ) ) . '">' . esc_html__( 'environment check', 'wp-cyber-security' ) . '</a>'
		);
		echo '</p>';
		$this->card_close();
	}

	/**
	 * @param array          $s     Settings.
	 * @param Sysadmin_Tools $tools Tools.
	 */
	private function section_integrations( array $s, Sysadmin_Tools $tools ) {
		unset( $s );
		$this->card_open( 'wpcs-integrations', 'networking', __( 'Server-level integrations', 'wp-cyber-security' ), __( 'Use the plugin\'s file fingerprints with tools that run outside PHP, so protection holds even if WordPress itself is compromised.', 'wp-cyber-security' ) );

		echo '<h3 class="wpcs-subhead">' . esc_html__( 'fapolicyd (RHEL, Rocky, Alma, Fedora)', 'wp-cyber-security' ) . '</h3>';
		echo '<p>' . esc_html__( 'Let PHP open only the PHP files you trust. The trust list contains every trusted file with its size and SHA-256, taken from the last baseline and approvals.', 'wp-cyber-security' ) . '</p>';
		echo '<div class="wpcs-row wpcs-card__actions"><a class="button" href="' . esc_url( $this->action_url( 'export', array( 'type' => 'fapolicyd' ) ) ) . '"><span class="dashicons dashicons-download" aria-hidden="true"></span>' . esc_html__( 'Download trust list', 'wp-cyber-security' ) . '</a></div>';
		echo self::code( $tools->fapolicyd_rules(), __( 'Rules', 'wp-cyber-security' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in code().

		echo '<h3 class="wpcs-subhead">' . esc_html__( 'inotify watcher', 'wp-cyber-security' ) . '</h3>';
		echo '<p>' . esc_html__( 'Starts a scan seconds after files change on disk, instead of waiting for the next scheduled scan.', 'wp-cyber-security' ) . '</p>';
		echo self::code( $tools->inotify_script(), '/usr/local/bin/wpcybersec-watch.sh' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in code().

		echo '<h3 class="wpcs-subhead">' . esc_html__( 'Linux Malware Detect (maldet)', 'wp-cyber-security' ) . '</h3>';
		echo self::code( $tools->maldet_snippet(), __( 'Shell (as root)', 'wp-cyber-security' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in code().
		$this->card_close();
	}

	/**
	 * @param array          $s     Settings.
	 * @param Sysadmin_Tools $tools Tools.
	 */
	private function section_clamav( array $s, Sysadmin_Tools $tools ) {
		$detected = $tools->clamav_detect();
		$exec     = Sysadmin_Tools::function_available( 'exec' ) || Sysadmin_Tools::function_available( 'proc_open' );
		$ready    = Sysadmin_Tools::call( 'scanner', 'clamav_available', array(), null );

		$this->card_open( 'wpcs-clamav', 'sos', __( 'ClamAV', 'wp-cyber-security' ), __( 'A second opinion on uploads from the open source ClamAV engine, next to the plugin\'s own signatures.', 'wp-cyber-security' ) );
		$this->field(
			__( 'ClamAV scanning', 'wp-cyber-security' ),
			self::toggle_row( 'clamav_enabled', ! empty( $s['clamav_enabled'] ), __( 'Also scan uploads with ClamAV', 'wp-cyber-security' ), __( 'Uploads take a little longer. clamdscan is much faster than clamscan when the clamd service runs.', 'wp-cyber-security' ) )
		);
		$this->field(
			__( 'Binary', 'wp-cyber-security' ),
			'<input type="text" id="wpcs-clamav-binary" name="clamav_binary" value="' . esc_attr( $s['clamav_binary'] ) . '" placeholder="' . esc_attr( $detected ? $detected : '/usr/bin/clamdscan' ) . '" class="wpcs-mono">',
			__( 'Leave empty to detect it automatically. Only clamscan or clamdscan binaries are accepted.', 'wp-cyber-security' ),
			'wpcs-clamav-binary'
		);
		$badges  = $exec ? $this->badge( __( 'Command execution available', 'wp-cyber-security' ), 'ok' ) : $this->badge( __( 'exec() and proc_open() disabled', 'wp-cyber-security' ), 'high' );
		/* translators: %s: binary path */
		$badges .= ' ' . ( $detected ? $this->badge( sprintf( __( 'Found: %s', 'wp-cyber-security' ), $detected ), 'ok' ) : $this->badge( __( 'ClamAV not found', 'wp-cyber-security' ), 'muted' ) );
		if ( null !== $ready ) {
			$badges .= ' ' . ( $ready ? $this->badge( __( 'Ready to scan', 'wp-cyber-security' ), 'ok' ) : $this->badge( __( 'Not in use', 'wp-cyber-security' ), 'muted' ) );
		}
		$this->field( __( 'Status', 'wp-cyber-security' ), '<div class="wpcs-badges">' . $badges . '</div>' );
		$this->card_close();
	}

	/**
	 * @param array          $s     Settings.
	 * @param Sysadmin_Tools $tools Tools.
	 */
	private function section_tamper( array $s, Sysadmin_Tools $tools ) {
		unset( $s );
		$this->card_open( 'wpcs-tamper', 'privacy', __( 'Tamper check', 'wp-cyber-security' ), __( 'Detects allowlist entries that were added directly in the database instead of through an approval. Code running as the web server user can still read the key, so this raises the bar; it is not a guarantee.', 'wp-cyber-security' ) );
		$state = Sysadmin_Tools::call( 'allowlist', 'verify_integrity', array(), null );
		if ( true === $state ) {
			self::notice( __( 'On. The allowlist matches its checksum.', 'wp-cyber-security' ), 'ok' );
		} elseif ( false === $state ) {
			self::notice( __( 'The allowlist was changed outside the plugin. Review Reports > Allowlist and remove entries you did not add.', 'wp-cyber-security' ), 'bad' );
		} else {
			self::notice( __( 'Off. Add a secret key to wp-config.php to turn it on.', 'wp-cyber-security' ), 'info' );
			echo self::code( $tools->hmac_snippet(), 'wp-config.php', __( 'This key was generated just now. Keep it only in wp-config.php.', 'wp-cyber-security' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in code().
		}
		$this->card_close();
	}

	/**
	 * @param array          $s     Settings.
	 * @param Sysadmin_Tools $tools Tools.
	 */
	private function section_data( array $s, Sysadmin_Tools $tools ) {
		unset( $tools );
		$this->card_open( 'wpcs-data', 'database', __( 'Data and housekeeping', 'wp-cyber-security' ) );
		$this->field(
			__( 'Keep the activity log for', 'wp-cyber-security' ),
			$this->number( 'log_retention_days', $s['log_retention_days'], 0, 3650, __( 'days', 'wp-cyber-security' ) ),
			__( '0 keeps it forever.', 'wp-cyber-security' ),
			'wpcs-log-retention-days'
		);
		$snapshots = Sysadmin_Tools::service( 'snapshots' );
		if ( $snapshots && method_exists( $snapshots, 'stats' ) ) {
			$stats  = $snapshots->stats();
			$copies = $stats['files']
				? sprintf(
					/* translators: 1: number of copies, 2: size such as 12 MB */
					_n( '%1$s stored copy, %2$s', '%1$s stored copies, %2$s', $stats['files'], 'wp-cyber-security' ),
					number_format_i18n( $stats['files'] ),
					size_format( $stats['bytes'], 1 )
				)
				: __( 'No stored copies', 'wp-cyber-security' );
			$copies_html = '<div class="wpcs-inline-status">' . $this->badge( $copies, $stats['files'] ? 'info' : 'muted' ) . '</div>';
			if ( $stats['files'] ) {
				$copies_html .= '<p class="wpcs-inline-actions"><a class="button wpcs-btn-danger" href="' . esc_url( $this->action_url( 'snapshots_clear' ) ) . '" data-wpcs-confirm="' . esc_attr__( 'Delete every stored file copy? Reports can then no longer show what changed in files found so far. While copies are switched on, the next scan copies the trusted files again.', 'wp-cyber-security' ) . '"><span class="dashicons dashicons-trash" aria-hidden="true"></span>' . esc_html__( 'Delete stored copies', 'wp-cyber-security' ) . '</a></p>';
			}
			$this->field(
				__( 'Copies of changed files', 'wp-cyber-security' ),
				$copies_html,
				__( 'Used to show what changed in a file. Copies nobody needs any more are deleted every day.', 'wp-cyber-security' )
			);
		}
		$html  = self::toggle_row( 'delete_data_on_uninstall', ! empty( $s['delete_data_on_uninstall'] ), __( 'Delete all plugin data when the plugin is deleted', 'wp-cyber-security' ) );
		$html .= '<div class="wpcs-notice wpcs-notice--warn wpcs-notice--compact"><span class="dashicons dashicons-warning" aria-hidden="true"></span><p>' . esc_html__( 'This removes the allowlist, the reports, the activity log and every held file. Files you approved would be held again after a reinstall. Deactivating the plugin never deletes data.', 'wp-cyber-security' ) . '</p></div>';
		$this->field( __( 'On uninstall', 'wp-cyber-security' ), $html );
		$this->field(
			__( 'Setup wizard', 'wp-cyber-security' ),
			'<a class="button" href="' . esc_url( Sysadmin_Tools::wizard_url() ) . '"><span class="dashicons dashicons-controls-repeat" aria-hidden="true"></span>' . esc_html__( 'Run the setup wizard again', 'wp-cyber-security' ) . '</a>'
		);
		$this->card_close();
	}

	/**
	 * Import and export (separate forms, outside the settings form).
	 */
	private function section_transfer() {
		$this->card_open( 'wpcs-transfer', 'database-export', __( 'Import and export settings', 'wp-cyber-security' ), __( 'Copy your settings to another site. The allowlist, reports and held files are not included.', 'wp-cyber-security' ) );
		?>
		<div class="wpcs-grid wpcs-grid--2 wpcs-transfer">
			<div>
				<h3 class="wpcs-subhead"><?php esc_html_e( 'Export', 'wp-cyber-security' ); ?></h3>
				<p class="wpcs-muted"><?php esc_html_e( 'Downloads every setting as a JSON file. It includes the webhook URL, so store it safely.', 'wp-cyber-security' ); ?></p>
				<a class="button" href="<?php echo esc_url( $this->action_url( 'export', array( 'type' => 'settings' ) ) ); ?>"><span class="dashicons dashicons-download" aria-hidden="true"></span><?php esc_html_e( 'Download settings', 'wp-cyber-security' ); ?></a>
			</div>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" enctype="multipart/form-data" class="wpcs-import">
				<input type="hidden" name="action" value="wpcybersec_import">
				<?php wp_nonce_field( 'wpcybersec_import' ); ?>
				<h3 class="wpcs-subhead"><?php esc_html_e( 'Import', 'wp-cyber-security' ); ?></h3>
				<p><input type="file" name="wpcs_import_file" accept=".json,application/json" aria-label="<?php esc_attr_e( 'Settings file', 'wp-cyber-security' ); ?>"></p>
				<p class="wpcs-muted"><?php esc_html_e( 'Or paste the file content (use this when the early guard holds the upload):', 'wp-cyber-security' ); ?></p>
				<textarea name="wpcs_import_json" rows="4" class="wpcs-mono wpcs-import__json" spellcheck="false" aria-label="<?php esc_attr_e( 'Settings JSON', 'wp-cyber-security' ); ?>"></textarea>
				<p><button type="submit" class="button" data-wpcs-confirm="<?php esc_attr_e( 'Replace the current settings with the imported ones?', 'wp-cyber-security' ); ?>"><span class="dashicons dashicons-upload" aria-hidden="true"></span><?php esc_html_e( 'Import settings', 'wp-cyber-security' ); ?></button></p>
			</form>
		</div>
		<?php
		$this->card_close();
	}
}

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

	/** @var string Open section of the Advanced tab. */
	private $section = 'health';

	/**
	 * Sections of the Advanced tab with fields that the Save button saves; the
	 * others only hold buttons that act at once.
	 */
	const SECTIONS_WITH_FIELDS = array( 'antivirus', 'scan', 'guard', 'freeze', 'data' );

	/** Old section anchors that now live elsewhere. */
	const SECTION_ALIASES = array( 'clamav' => 'antivirus' );

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
		$html .= '<button type="button" class="button wpcs-copy" data-wpcs-copy>' . esc_html__( 'Copy', 'cybergate-security' ) . '</button>';
		if ( '' !== $help ) {
			$html .= '<span class="wpcs-field__help">' . esc_html( $help ) . '</span>';
		}
		return $html . '</div>';
	}

	/**
	 * A long command snippet folded under "Show commands", so a card shows its
	 * explanation first. Copy keeps working inside (it copies the <pre>).
	 *
	 * @param string $code  Code.
	 * @param string $label What it is or where it goes (shown in the summary).
	 * @param string $help  Optional help below the block.
	 * @param bool   $open  Open by default (the related check fails, or it is the only content).
	 * @return string HTML.
	 */
	public static function commands( $code, $label = '', $help = '', $open = false ) {
		$html  = '<details class="wpcs-cmds"' . ( $open ? ' open' : '' ) . '>';
		$html .= '<summary><span class="dashicons dashicons-editor-code" aria-hidden="true"></span><span class="wpcs-cmds__show">' . esc_html__( 'Show commands', 'cybergate-security' ) . '</span>';
		if ( '' !== $label ) {
			$html .= '<span class="wpcs-cmds__label">' . esc_html( $label ) . '</span>';
		}
		$html .= '</summary>' . self::code( $code, '', $help ) . '</details>';
		return $html;
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
	 * Prints toggle_row().
	 *
	 * @param string $name      Field name.
	 * @param bool   $checked   State.
	 * @param string $label     Label.
	 * @param string $help      Help text.
	 * @param array  $attrs     Extra attributes for the checkbox.
	 * @param string $value     Value when on.
	 * @param string $off_value Value when off.
	 */
	public static function render_toggle_row( $name, $checked, $label, $help = '', array $attrs = array(), $value = '1', $off_value = '0' ) {
		echo self::toggle_row( $name, $checked, $label, $help, $attrs, $value, $off_value ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- every part is escaped in toggle_row().
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
				'instant' => array( __( 'Instantly', 'cybergate-security' ), __( 'An email as soon as something is held or found. At most one email every 10 minutes; anything else is summarized in the next one.', 'cybergate-security' ) ),
				'digest'  => array( __( 'Daily digest', 'cybergate-security' ), __( 'One summary email per day.', 'cybergate-security' ) ),
				'off'     => array( __( 'Off', 'cybergate-security' ), __( 'No emails. Check the Reports page yourself.', 'cybergate-security' ) ),
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
				'strict'   => __( 'Strict', 'cybergate-security' ),
				'balanced' => __( 'Balanced', 'cybergate-security' ),
				'relaxed'  => __( 'Relaxed', 'cybergate-security' ),
				'custom'   => __( 'Custom', 'cybergate-security' ),
			),
			'upload_mode'      => array(
				'hold_all'   => __( 'Every upload held for approval', 'cybergate-security' ),
				'hold_risky' => __( 'Risky uploads held for approval', 'cybergate-security' ),
				'scan_only'  => __( 'Scanned, only malware held', 'cybergate-security' ),
				'off'        => __( 'Not checked', 'cybergate-security' ),
			),
			'file_mode'        => array(
				'quarantine_exec' => __( 'Moved to quarantine', 'cybergate-security' ),
				'report'          => __( 'Reported for review', 'cybergate-security' ),
				'off'             => __( 'Not reported', 'cybergate-security' ),
			),
			'scan_schedule'    => array(
				'hourly'     => __( 'Every hour', 'cybergate-security' ),
				'twicedaily' => __( 'Twice a day', 'cybergate-security' ),
				'daily'      => __( 'Once a day', 'cybergate-security' ),
				'weekly'     => __( 'Once a week', 'cybergate-security' ),
				'off'        => __( 'Off (manual scans only)', 'cybergate-security' ),
			),
			'notify_mode'      => array(
				'instant' => __( 'Instant email', 'cybergate-security' ),
				'digest'  => __( 'Daily digest', 'cybergate-security' ),
				'off'     => __( 'Off', 'cybergate-security' ),
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
			'hold_all'   => __( 'Every upload waits for approval', 'cybergate-security' ),
			'hold_risky' => __( 'Only risky uploads wait for approval', 'cybergate-security' ),
			'scan_only'  => __( 'Uploads are scanned, not held', 'cybergate-security' ),
			'off'        => __( 'Uploads are not checked', 'cybergate-security' ),
		);
		if ( isset( $preset['upload_mode'], $uploads[ $preset['upload_mode'] ] ) ) {
			$points[] = $uploads[ $preset['upload_mode'] ];
		}
		if ( isset( $preset['upload_bypass_roles'] ) ) {
			$points[] = in_array( 'administrator', (array) $preset['upload_bypass_roles'], true )
				? __( 'Administrators\' clean uploads pass', 'cybergate-security' )
				: __( 'Administrators\' uploads are held too', 'cybergate-security' );
		}
		if ( isset( $preset['install_mode'] ) ) {
			$points[] = 'hold' === $preset['install_mode']
				? __( 'New plugins and themes wait for approval', 'cybergate-security' )
				: __( 'Plugin and theme installs are not held', 'cybergate-security' );
		}
		if ( isset( $preset['file_mode'] ) ) {
			$points[] = 'quarantine_exec' === $preset['file_mode']
				? __( 'New unknown PHP files go to quarantine', 'cybergate-security' )
				: __( 'New unknown PHP files are reported', 'cybergate-security' );
		}
		if ( ! empty( $preset['auto_quarantine'] ) ) {
			$points[] = __( 'Critical malware is quarantined automatically', 'cybergate-security' );
		}
		$schedules = array(
			'hourly'     => __( 'Scans every hour', 'cybergate-security' ),
			'twicedaily' => __( 'Scans twice a day', 'cybergate-security' ),
			'daily'      => __( 'Scans once a day', 'cybergate-security' ),
			'weekly'     => __( 'Scans once a week', 'cybergate-security' ),
		);
		if ( isset( $preset['scan_schedule'], $schedules[ $preset['scan_schedule'] ] ) ) {
			$points[] = $schedules[ $preset['scan_schedule'] ];
		}
		if ( isset( $preset['notify_mode'] ) && 'off' !== $preset['notify_mode'] ) {
			$points[] = 'digest' === $preset['notify_mode'] ? __( 'Daily digest email', 'cybergate-security' ) : __( 'Instant email alerts', 'cybergate-security' );
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
			'strict'   => array( 'lock', __( 'Maximum control. Nothing new runs or appears without your approval, and suspicious files are moved away at once.', 'cybergate-security' ) ),
			'balanced' => array( 'shield', __( 'Holds every upload and new install, and reports unknown files without moving them. Best for most sites.', 'cybergate-security' ) ),
			'relaxed'  => array( 'unlock', __( 'Fewer approvals. Only risky uploads are held and administrators\' clean uploads pass.', 'cybergate-security' ) ),
		);
		$labels = self::labels();
		$html   = '<div class="wpcs-options wpcs-levels" role="radiogroup" aria-label="' . esc_attr__( 'Protection level', 'cybergate-security' ) . '">';
		foreach ( Settings::presets() as $level => $preset ) {
			$icon = isset( $meta[ $level ] ) ? $meta[ $level ][0] : 'shield';
			$desc = isset( $meta[ $level ] ) ? $meta[ $level ][1] : '';
			$is   = $selected === $level;
			$html .= '<label class="wpcs-option' . ( $is ? ' is-selected' : '' ) . '">';
			$html .= '<input type="radio" name="' . esc_attr( $name ) . '" value="' . esc_attr( $level ) . '"' . ( $is ? ' checked' : '' ) . ' data-wpcs-level>';
			if ( 'balanced' === $level ) {
				$html .= '<span class="wpcs-badge wpcs-badge--ok wpcs-option__tag">' . esc_html__( 'Recommended', 'cybergate-security' ) . '</span>';
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
			'pass' => array( 'ok', __( 'OK', 'cybergate-security' ) ),
			'warn' => array( 'medium', __( 'Recommended', 'cybergate-security' ) ),
			'fail' => array( 'high', __( 'Problem', 'cybergate-security' ) ),
			'info' => array( 'info', __( 'Info', 'cybergate-security' ) ),
		);
		$actions = array(
			'write_htaccess' => __( 'Add the rule for me', 'cybergate-security' ),
			'probe'          => __( 'Run a live test', 'cybergate-security' ),
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
					echo '<details class="wpcs-manual" data-wpcs-manual="' . esc_attr( $auto['id'] ) . '"><summary>' . esc_html__( 'Do it by hand instead', 'cybergate-security' ) . '</summary>';
					if ( $steps ) {
						self::render_steps( $steps );
					}
					self::render_extra_code( $check, $extra );
					echo '</details>';
				}
			} elseif ( $steps ) {
				// No automatic fix on this server: easy numbered steps, open by default.
				echo '<div class="wpcs-manual wpcs-manual--open" data-wpcs-manual="' . esc_attr( $check['id'] ) . '">';
				echo '<span class="wpcs-sub wpcs-check__fix">' . esc_html__( 'How to fix it:', 'cybergate-security' ) . '</span>';
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
		echo '<span class="wpcs-sub wpcs-check__fix">' . esc_html( '' !== $fix ? $fix : __( 'Or use this:', 'cybergate-security' ) ) . '</span>';
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
			wp_die( esc_html__( 'You are not allowed to access this page.', 'cybergate-security' ) );
		}
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- navigation and display only.
		$tab     = ( isset( $_GET['tab'] ) && 'advanced' === sanitize_key( wp_unslash( $_GET['tab'] ) ) ) ? 'advanced' : 'general';
		$updated = ! empty( $_GET['settings-updated'] );
		// phpcs:enable

		$actions = '<a class="button" href="' . esc_url( Sysadmin_Tools::wizard_url() ) . '">' . esc_html__( 'Run setup wizard', 'cybergate-security' ) . '</a>';
		?>
		<div class="wrap wpcs-wrap wpcs-settings">
			<?php
			self::page_header( __( 'Settings', 'cybergate-security' ), __( 'Protection rules, alerts and tools for system administrators.', 'cybergate-security' ), $actions );
			if ( $updated ) {
				self::notice( __( 'Settings saved.', 'cybergate-security' ), 'ok' );
			}
			self::render_flash();
			?>
			<nav class="nav-tab-wrapper wpcs-tabs" aria-label="<?php esc_attr_e( 'Settings sections', 'cybergate-security' ); ?>">
				<a href="<?php echo esc_url( Sysadmin_Tools::settings_url( 'general' ) ); ?>" class="nav-tab<?php echo 'general' === $tab ? ' nav-tab-active' : ''; ?>"<?php echo 'general' === $tab ? ' aria-current="page"' : ''; ?>>
					<span class="dashicons dashicons-admin-generic" aria-hidden="true"></span><?php esc_html_e( 'General', 'cybergate-security' ); ?>
				</a>
				<a href="<?php echo esc_url( Sysadmin_Tools::settings_url( 'advanced' ) ); ?>" class="nav-tab<?php echo 'advanced' === $tab ? ' nav-tab-active' : ''; ?>"<?php echo 'advanced' === $tab ? ' aria-current="page"' : ''; ?>>
					<span class="dashicons dashicons-admin-tools" aria-hidden="true"></span><?php esc_html_e( 'Advanced', 'cybergate-security' ); ?>
					<span class="wpcs-badge wpcs-badge--muted"><?php esc_html_e( 'System administrators', 'cybergate-security' ); ?></span>
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
				self::notice( sprintf( __( 'Part of this page could not be shown: %s', 'cybergate-security' ), $e->getMessage() ), 'bad' );
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
			<?php if ( 'advanced' === $tab ) : ?>
				<input type="hidden" name="section" value="<?php echo esc_attr( $this->section ); ?>" data-wpcs-section-input>
			<?php endif; ?>
			<?php wp_nonce_field( 'wpcybersec_save_settings' ); ?>
			<button type="submit" class="wpcs-default-submit" tabindex="-1" aria-hidden="true"><?php esc_html_e( 'Save changes', 'cybergate-security' ); ?></button>
		<?php
	}

	/**
	 * Sticky save bar and end of the form.
	 *
	 * @param string $note Text next to the button.
	 * @param bool   $idle Hidden while the open section has no fields (with scripts only).
	 */
	private function form_close( $note, $idle = false ) {
		?>
			<div class="wpcs-savebar<?php echo $idle ? ' is-idle' : ''; ?>" data-wpcs-savebar>
				<span class="wpcs-savebar__note"><?php echo esc_html( $note ); ?></span>
				<button type="submit" class="button button-primary button-large"><?php esc_html_e( 'Save changes', 'cybergate-security' ); ?></button>
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

		$this->card_open( 'wpcs-level', 'shield', __( 'Protection level', 'cybergate-security' ), __( 'Pick a starting point. The settings below follow the level you pick; changing one of them makes the level Custom.', 'cybergate-security' ) );
		if ( 'custom' === $s['protection_level'] ) {
			self::notice( __( 'Custom: your settings do not match a preset. Pick a level to reset the settings below to its values.', 'cybergate-security' ), 'info' );
		}
		echo self::level_cards( 'protection_level', $s['protection_level'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in level_cards().
		echo '<input type="hidden" name="wpcs_level_synced" value="0" data-wpcs-level-synced>';
		echo '<p class="wpcs-custom-hint wpcs-hidden" data-wpcs-custom-hint></p>';
		$this->card_close();

		// Uploads.
		$this->card_open( 'wpcs-uploads', 'upload', __( 'Uploads', 'cybergate-security' ), __( 'Files added through the Media Library, the block editor, the REST API and plugins that use the WordPress upload functions.', 'cybergate-security' ) );
		$this->field(
			__( 'When a file is uploaded', 'cybergate-security' ),
			self::radio_list(
				'upload_mode',
				array(
					'hold_all'   => array( __( 'Hold every upload', 'cybergate-security' ), __( 'Every new file waits for approval, unless the same file was approved before. Safest.', 'cybergate-security' ) ),
					'hold_risky' => array( __( 'Hold risky uploads', 'cybergate-security' ), __( 'Holds scripts, archives, SVG and HTML files, files whose content does not match the extension, and anything that looks malicious. Ordinary images and documents pass.', 'cybergate-security' ) ),
					'scan_only'  => array( __( 'Scan only', 'cybergate-security' ), __( 'Uploads pass unless they contain known malware.', 'cybergate-security' ) ),
					'off'        => array( __( 'Off', 'cybergate-security' ), __( 'Uploads are not checked.', 'cybergate-security' ) ),
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
			__( 'Clean uploads pass for', 'cybergate-security' ),
			$roles_html,
			__( 'Uploads from these roles are still scanned. Anything that looks malicious is always held.', 'cybergate-security' )
		);
		$this->field(
			__( 'Files downloaded by WordPress', 'cybergate-security' ),
			self::toggle_row( 'gate_sideloads', ! empty( $s['gate_sideloads'] ), __( 'Also hold files that WordPress downloads from other sites', 'cybergate-security' ), __( 'For example images fetched by importers or by plugins that call media_sideload_image().', 'cybergate-security' ) )
		);
		$this->card_close();

		// Installs.
		$this->card_open( 'wpcs-installs', 'admin-plugins', __( 'Plugin and theme installs', 'cybergate-security' ) );
		$this->field(
			__( 'New plugins and themes', 'cybergate-security' ),
			self::toggle_row( 'install_mode', 'hold' === $s['install_mode'], __( 'Hold new plugin and theme installs until approved', 'cybergate-security' ), __( 'Approved installs are remembered, so reinstalling the same plugin or theme is not held again.', 'cybergate-security' ), array(), 'hold', 'off' )
		);
		$this->field(
			__( 'Updates', 'cybergate-security' ),
			self::toggle_row( 'hold_updates', ! empty( $s['hold_updates'] ), __( 'Also hold updates of installed plugins and themes', 'cybergate-security' ), __( 'Turn this on only if you want to approve every update by hand. Updated files are checked against the official checksums either way.', 'cybergate-security' ) )
		);
		$this->card_close();

		// File monitor.
		$this->card_open( 'wpcs-monitor', 'media-code', __( 'File monitor', 'cybergate-security' ), __( 'What happens with files that appear or change on the server outside of WordPress, for example through FTP or a hacked plugin.', 'cybergate-security' ) );
		$this->field(
			__( 'New unknown code files', 'cybergate-security' ),
			self::radio_list(
				'file_mode',
				array(
					'quarantine_exec' => array( __( 'Move to quarantine', 'cybergate-security' ), __( 'New PHP and other executable files are moved away until you approve them. Not for development sites where you edit code.', 'cybergate-security' ) ),
					'report'          => array( __( 'Report only', 'cybergate-security' ), __( 'New files stay in place and appear on the Reports page for review.', 'cybergate-security' ) ),
					'off'             => array( __( 'Off', 'cybergate-security' ), __( 'New files are not reported. Malware is still detected.', 'cybergate-security' ) ),
				),
				$s['file_mode']
			)
		);
		$this->field(
			__( 'Changed code files', 'cybergate-security' ),
			self::radio_list(
				'modified_action',
				array(
					'report'     => array( __( 'Report', 'cybergate-security' ), __( 'Changed files stay in place and are listed for review.', 'cybergate-security' ) ),
					'quarantine' => array( __( 'Move to quarantine', 'cybergate-security' ), __( 'Changed files are moved away until you approve them. The site may break until you do.', 'cybergate-security' ) ),
				),
				$s['modified_action']
			)
		);
		$this->field(
			__( 'Critical malware', 'cybergate-security' ),
			self::toggle_row( 'auto_quarantine', ! empty( $s['auto_quarantine'] ), __( 'Move files with critical malware to quarantine automatically', 'cybergate-security' ), __( 'Only for hits rated critical, such as known web shells. You can restore a file from the Reports page.', 'cybergate-security' ) )
		);
		$this->card_close();

		// Scanning.
		$this->card_open( 'wpcs-scanning', 'search', __( 'Scanning', 'cybergate-security' ) );
		$this->field(
			__( 'Scheduled scans', 'cybergate-security' ),
			$this->select( 'scan_schedule', $labels['scan_schedule'], $s['scan_schedule'] ),
			__( 'Scheduled scans only check new and changed files, so they are quick. Use a real cron job for exact timing (Advanced tab).', 'cybergate-security' ),
			'wpcs-scan-schedule'
		);
		$this->field(
			__( 'Malware check', 'cybergate-security' ),
			self::toggle_row( 'scan_malware', ! empty( $s['scan_malware'] ), __( 'Check new and changed files for malware during scheduled scans', 'cybergate-security' ) )
		);
		$this->field(
			__( 'Report findings from', 'cybergate-security' ),
			$this->select(
				'min_severity',
				array(
					'1' => __( 'Medium severity and above', 'cybergate-security' ),
					'2' => __( 'High severity and above', 'cybergate-security' ),
					'3' => __( 'Critical only', 'cybergate-security' ),
				),
				(string) $s['min_severity']
			),
			__( 'Medium findings include suspicious but sometimes legitimate code, such as obfuscation in commercial plugins.', 'cybergate-security' ),
			'wpcs-min-severity'
		);
		$this->field(
			__( 'Official checksums', 'cybergate-security' ),
			self::toggle_row( 'use_checksums', ! empty( $s['use_checksums'] ), __( 'Verify WordPress core and wordpress.org plugins against their official checksums', 'cybergate-security' ), __( 'Files that match the official release are trusted automatically, for example after updates.', 'cybergate-security' ) )
		);
		$this->field(
			__( 'Show what changed', 'cybergate-security' ),
			self::toggle_row( 'snapshots', ! empty( $s['snapshots'] ), __( 'Keep copies of PHP and config files so you can see exactly what changed', 'cybergate-security' ), __( 'A compressed copy of each trusted version is kept in the private data folder, so a modified file can be compared line by line. Passwords and keys are hidden when shown. Files that match an official WordPress.org checksum are not copied: the original is downloaded when needed.', 'cybergate-security' ) )
		);
		$this->field(
			__( 'Largest file to copy', 'cybergate-security' ),
			$this->number( 'snapshot_max_kb', $s['snapshot_max_kb'], 16, 4096, __( 'KB', 'cybergate-security' ) ),
			__( 'Bigger files are still checked, but no copy is kept, so their changes cannot be shown line by line.', 'cybergate-security' ),
			'wpcs-snapshot-max-kb'
		);
		$this->field(
			__( 'Most stored copies', 'cybergate-security' ),
			$this->number( 'snapshot_max_files', $s['snapshot_max_files'], 1000, 1000000, __( 'files', 'cybergate-security' ) ),
			__( 'Shared hosting often limits the number of files (inodes). When the limit is reached, the copies used least recently are deleted first.', 'cybergate-security' ),
			'wpcs-snapshot-max-files'
		);
		$this->field(
			__( 'Most disk space for copies', 'cybergate-security' ),
			$this->number( 'snapshot_max_mb', $s['snapshot_max_mb'], 10, 10240, __( 'MB', 'cybergate-security' ) ),
			__( 'Copies are compressed. When the space is used up, the copies used least recently are deleted first.', 'cybergate-security' ),
			'wpcs-snapshot-max-mb'
		);
		$this->card_close();

		// Notifications.
		$emails = $s['notify_emails'] ? (array) $s['notify_emails'] : array();
		$this->card_open( 'wpcs-notifications', 'email-alt', __( 'Notifications', 'cybergate-security' ) );
		$this->field( __( 'Send alerts', 'cybergate-security' ), self::notify_mode_choices( $s['notify_mode'] ) );
		$emails_html  = '<textarea id="wpcs-notify-emails" name="notify_emails" rows="3" class="wpcs-textarea-sm" spellcheck="false" placeholder="' . esc_attr( implode( "\n", \WPCyberSecurity\Network::default_recipients() ) ) . '">' . esc_textarea( implode( "\n", $emails ) ) . '</textarea>';
		$emails_html .= '<span class="wpcs-field__help">' . esc_html(
			is_multisite()
				/* translators: %s: email addresses */
				? sprintf( __( 'One address per line. Empty means the network admin email and the super admins (%s).', 'cybergate-security' ), implode( ', ', \WPCyberSecurity\Network::default_recipients() ) )
				/* translators: %s: email address */
				: sprintf( __( 'One address per line. Empty means the site admin email (%s).', 'cybergate-security' ), get_option( 'admin_email' ) )
		) . '</span>';
		$emails_html .= '<p class="wpcs-inline-actions"><button type="submit" name="wpcs_send_test" value="1" class="button" data-wpcs-test-email data-source="#wpcs-notify-emails"><span class="dashicons dashicons-email-alt" aria-hidden="true"></span>' . esc_html__( 'Send test email', 'cybergate-security' ) . '</button></p>';
		$this->field( __( 'Email recipients', 'cybergate-security' ), $emails_html, '', 'wpcs-notify-emails' );
		$this->field(
			__( 'Webhook URL', 'cybergate-security' ),
			'<input type="url" id="wpcs-webhook-url" name="webhook_url" value="' . esc_attr( $s['webhook_url'] ) . '" placeholder="https://hooks.slack.com/services/..." autocomplete="off">',
			__( 'Optional. Posts a short message to Slack, Discord, Microsoft Teams or any service that accepts incoming webhooks. Must start with https://.', 'cybergate-security' ),
			'wpcs-webhook-url'
		);
		$this->card_close();

		$this->form_close( __( 'Changes apply as soon as you save.', 'cybergate-security' ) );
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

		$sections = self::advanced_sections();
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- navigation only.
		$asked = isset( $_GET['section'] ) ? sanitize_key( wp_unslash( $_GET['section'] ) ) : '';
		$asked = isset( self::SECTION_ALIASES[ $asked ] ) ? self::SECTION_ALIASES[ $asked ] : $asked;
		$this->section = isset( $sections[ $asked ] ) ? $asked : 'health';

		// Computed once: Server health, the developer instructions and the command blocks use them.
		$checks = array();
		try {
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read only.
			$checks = $tools->diagnostics( ! empty( $_GET['recheck'] ) );
		} catch ( \Throwable $e ) {
			$checks = array();
		}
		$attention = array_values(
			array_filter(
				$checks,
				static function ( $c ) {
					return in_array( $c['status'], array( 'warn', 'fail' ), true );
				}
			)
		);
		$developer = Sysadmin_Tools::service( 'developer' );
		$dev_items = array();
		if ( $developer && method_exists( $developer, 'items' ) ) {
			try {
				$dev_items = $developer->items( $checks );
			} catch ( \Throwable $e ) {
				$dev_items = array();
			}
		}
		$counts = array(
			'health'    => count( $attention ),
			'developer' => count( $dev_items ),
		);

		// Section chips: plain links to the cards without scripts, tabs with them (setup.js).
		echo '<nav class="wpcs-toc" aria-label="' . esc_attr__( 'Advanced sections', 'cybergate-security' ) . '" data-wpcs-sections>';
		foreach ( $sections as $key => $label ) {
			$active = $key === $this->section;
			echo '<a href="#wpcs-' . esc_attr( $key ) . '" id="wpcs-tab-' . esc_attr( $key ) . '" class="wpcs-toc__chip' . ( $active ? ' is-active' : '' ) . '" data-wpcs-section="' . esc_attr( $key ) . '" aria-controls="wpcs-panel-' . esc_attr( $key ) . '">' . esc_html( $label );
			if ( ! empty( $counts[ $key ] ) ) {
				echo '<span class="wpcs-toc__count">' . esc_html( number_format_i18n( $counts[ $key ] ) ) . '</span>';
			}
			echo '</a>';
		}
		echo '</nav>';

		// One form for every section except Import and export (its own forms), so
		// fields of hidden sections are always saved with their current values.
		$this->form_open( 'advanced' );

		$this->panel_open( 'health' );
		try {
			$this->card_open( 'wpcs-health', 'heart', __( 'Server health', 'cybergate-security' ), __( 'Recommendations for this server. Use the buttons to fix them here, or follow the steps to do it by hand.', 'cybergate-security' ) );
			if ( $attention ) {
				$fixable = self::auto_fix_ids( $attention );
				if ( $fixable ) {
					echo '<div class="wpcs-fixall"><div><strong>' . esc_html(
						/* translators: %d: number of items */
						sprintf( _n( '%d item can be fixed for you', '%d items can be fixed for you', count( $fixable ), 'cybergate-security' ), count( $fixable ) )
					) . '</strong></div><button type="button" class="button button-primary" data-wpcs-fix-all="' . esc_attr( implode( ',', $fixable ) ) . '">' . esc_html__( 'Fix them all', 'cybergate-security' ) . '</button></div>';
				}
				self::render_checks( $attention, false );
			} else {
				self::notice( __( 'No open recommendations. Everything important looks good.', 'cybergate-security' ), 'ok' );
			}
			if ( $dev_items ) {
				echo '<p class="wpcs-card__foot-note"><span class="dashicons dashicons-clipboard" aria-hidden="true"></span><span>';
				printf(
					/* translators: %s: link to the developer instructions */
					esc_html__( 'Steps that need server access are collected in %s.', 'cybergate-security' ),
					'<a href="' . esc_url( Sysadmin_Tools::settings_url( 'advanced', array(), 'wpcs-developer' ) ) . '" data-wpcs-goto="developer">' . esc_html__( 'Developer instructions', 'cybergate-security' ) . '</a>'
				);
				echo '</span></p>';
			}
			$this->card_close();
		} catch ( \Throwable $e ) {
			if ( $this->card_is_open ) {
				$this->card_close();
			}
		}
		$this->panel_close();

		$by_id = array();
		foreach ( $checks as $check ) {
			$by_id[ (string) $check['id'] ] = $check;
		}
		$parts = array(
			'antivirus'    => array( 'section_antivirus', array( $s, $tools ) ),
			'developer'    => array( 'section_developer', array( $dev_items ) ),
			'storage'      => array( 'section_storage', array( $s, $tools ) ),
			'scan'         => array( 'section_scan', array( $s, $tools ) ),
			'guard'        => array( 'section_guard', array( $s, $tools ) ),
			'cron'         => array( 'section_cron', array( $s, $tools, $by_id ) ),
			'freeze'       => array( 'section_freeze', array( $s, $tools ) ),
			'hardening'    => array( 'section_hardening', array( $s, $tools, $by_id ) ),
			'integrations' => array( 'section_integrations', array( $s, $tools ) ),
			'tamper'       => array( 'section_tamper', array( $s, $tools ) ),
			'data'         => array( 'section_data', array( $s, $tools ) ),
		);
		foreach ( $parts as $key => $part ) {
			$this->panel_open( $key );
			try {
				call_user_func_array( array( $this, $part[0] ), $part[1] );
			} catch ( \Throwable $e ) {
				/* translators: %s: error message */
				self::notice( sprintf( __( 'This section could not be shown: %s', 'cybergate-security' ), $e->getMessage() ), 'bad' );
				if ( $this->card_is_open ) {
					$this->card_close();
				}
			}
			$this->panel_close();
		}
		$this->form_close(
			__( 'Saves the settings of every section. Buttons inside the cards act at once.', 'cybergate-security' ),
			! in_array( $this->section, self::SECTIONS_WITH_FIELDS, true )
		);

		$this->panel_open( 'transfer' );
		$this->section_transfer();
		$this->panel_close();
	}

	/**
	 * Sections of the Advanced tab, in order: key => chip label. The card of a
	 * section has the id "wpcs-<key>".
	 *
	 * @return array
	 */
	public static function advanced_sections() {
		return array(
			'health'       => __( 'Server health', 'cybergate-security' ),
			'antivirus'    => __( 'Antivirus engines', 'cybergate-security' ),
			'developer'    => __( 'Developer instructions', 'cybergate-security' ),
			'storage'      => __( 'Storage', 'cybergate-security' ),
			'scan'         => __( 'Scan scope', 'cybergate-security' ),
			'guard'        => __( 'Early guard', 'cybergate-security' ),
			'cron'         => __( 'Real cron', 'cybergate-security' ),
			'freeze'       => __( 'Freeze lock', 'cybergate-security' ),
			'hardening'    => __( 'Web server', 'cybergate-security' ),
			'integrations' => __( 'Integrations', 'cybergate-security' ),
			'tamper'       => __( 'Tamper check', 'cybergate-security' ),
			'data'         => __( 'Data', 'cybergate-security' ),
			'transfer'     => __( 'Import and export', 'cybergate-security' ),
		);
	}

	/**
	 * Opens the wrapper of one section. Without scripts every section shows;
	 * setup.js turns the chips into tabs and hides the others.
	 *
	 * @param string $key Section key.
	 */
	private function panel_open( $key ) {
		$fields = in_array( $key, self::SECTIONS_WITH_FIELDS, true );
		echo '<div class="wpcs-tabpanel' . ( $key === $this->section ? ' is-active' : '' ) . '" id="wpcs-panel-' . esc_attr( $key ) . '" data-wpcs-panel="' . esc_attr( $key ) . '" data-has-fields="' . ( $fields ? '1' : '0' ) . '">';
	}

	/**
	 * Closes a section wrapper.
	 */
	private function panel_close() {
		echo '</div>';
	}

	/**
	 * Check status by id ('' when the check did not run).
	 *
	 * @param array[] $by_id Checks by id.
	 * @param string  $id    Check id.
	 * @return string
	 */
	private static function check_status( array $by_id, $id ) {
		return isset( $by_id[ $id ]['status'] ) ? (string) $by_id[ $id ]['status'] : '';
	}

	/**
	 * @param string $status Check status.
	 * @return bool Whether it needs attention.
	 */
	private static function is_open( $status ) {
		return in_array( $status, array( 'warn', 'fail' ), true );
	}

	/**
	 * Antivirus engines: ClamAV and Linux Malware Detect.
	 *
	 * @param array          $s     Settings.
	 * @param Sysadmin_Tools $tools Tools.
	 */
	private function section_antivirus( array $s, Sysadmin_Tools $tools ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read only: "Check again" runs the ClamAV self-test now.
		if ( ! empty( $_GET['recheck'] ) ) {
			Sysadmin_Tools::call( 'scanner', 'clamav_selftest', array( true ), null );
		}
		$av     = $tools->antivirus_status();
		$clam   = $av['clamav'];
		$maldet = $av['maldet'];
		$yes    = __( 'Yes', 'cybergate-security' );
		$no     = __( 'No', 'cybergate-security' );

		$this->card_open( 'wpcs-antivirus', 'sos', __( 'Antivirus engines', 'cybergate-security' ), __( 'ClamAV and Linux Malware Detect know many more existing infections (web shells, phishing kits, infected uploads) and give a second opinion next to the plugin\'s own signatures. They find more, but they do not block attacks.', 'cybergate-security' ) );

		if ( 'ready_off' === $clam['state'] ) {
			echo '<div class="wpcs-callout">';
			echo '<span class="wpcs-callout__icon" aria-hidden="true"><span class="dashicons dashicons-sos"></span></span>';
			echo '<div class="wpcs-callout__text"><strong>' . esc_html__( 'ClamAV is installed and works, but is not in use', 'cybergate-security' ) . '</strong>';
			if ( ! empty( $clam['slow_only'] ) ) {
				$sub = __( 'Only the slow clamscan works here, so uploads are not scanned with it while someone waits (held uploads the early guard imports by cron are). Start clamd for fast scans of every upload.', 'cybergate-security' );
			} else {
				$sub = $clam['daemon'] ? __( 'Turn it on to check every upload with ClamAV too. Its background service runs, so whole-site scans use it as well.', 'cybergate-security' ) : __( 'Turn it on to check every upload with ClamAV too.', 'cybergate-security' );
			}
			echo '<span class="wpcs-sub">' . esc_html( $sub ) . '</span></div>';
			echo '<button type="button" class="button button-primary" data-wpcs-clamav-enable><span class="dashicons dashicons-yes" aria-hidden="true"></span>' . esc_html__( 'Turn on ClamAV for uploads', 'cybergate-security' ) . '</button>';
			echo '</div>';
			if ( '' !== $clam['hint_code'] ) {
				echo '<p class="wpcs-sub">' . esc_html( $clam['hint'] ) . '</p>';
				echo self::code( $clam['hint_code'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in code().
			}
		} elseif ( in_array( $clam['state'], array( 'broken', 'slow' ), true ) || ( '' !== $clam['hint'] && in_array( $clam['state'], array( 'uploads' ), true ) ) ) {
			self::notice( $clam['label'] . ( '' !== $clam['hint'] ? ' ' . $clam['hint'] : '' ), 'broken' === $clam['state'] ? 'bad' : 'warn' );
			if ( '' !== $clam['hint_code'] ) {
				echo self::code( $clam['hint_code'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in code().
			}
		}

		echo '<div class="wpcs-engines">';
		// ClamAV.
		$used = array(
			'missing'       => ! empty( $clam['hidden'] ) ? __( 'Nothing (not found)', 'cybergate-security' ) : __( 'Nothing (not installed)', 'cybergate-security' ),
			'blocked'       => __( 'Nothing (PHP cannot run it)', 'cybergate-security' ),
			'broken'        => __( 'Nothing (the self-test failed)', 'cybergate-security' ),
			'ready_off'     => __( 'Nothing yet', 'cybergate-security' ),
			'slow'          => __( 'Held uploads imported by cron (uploads skip it while someone waits)', 'cybergate-security' ),
			'uploads'       => __( 'Uploads', 'cybergate-security' ),
			'uploads_scans' => __( 'Uploads and whole-site scans', 'cybergate-security' ),
		);
		$service = $this->badge( __( 'Not running', 'cybergate-security' ), 'muted' );
		if ( 'missing' === $clam['state'] ) {
			$service = ! empty( $clam['hidden'] ) ? esc_html__( 'Unknown (hosting hides it)', 'cybergate-security' ) : esc_html__( 'Not installed', 'cybergate-security' );
		} elseif ( $clam['daemon'] ) {
			/* translators: %s: time per file */
			$service = $this->badge( null !== $clam['daemon_ms'] ? sprintf( __( 'Running, about %s per file', 'cybergate-security' ), Sysadmin_Tools::duration_ms( $clam['daemon_ms'] ) ) : __( 'Running', 'cybergate-security' ), 'ok' );
		} elseif ( 'socket' === $clam['kind'] ) {
			$service = $this->badge( __( 'Running, but PHP may not use its socket', 'cybergate-security' ), 'high' );
		}
		$rows = array(
			__( 'Program', 'cybergate-security' )            => '' !== $clam['binary'] ? '<code class="wpcs-path">' . esc_html( $clam['binary'] ) . '</code>' : esc_html__( 'Not found', 'cybergate-security' ),
			__( 'Background service (clamd)', 'cybergate-security' ) => $service,
			__( 'PHP may run it', 'cybergate-security' )     => $clam['exec'] ? $this->badge( $yes, 'ok' ) : $this->badge( __( 'No: exec() and proc_open() are disabled', 'cybergate-security' ), 'high' ),
			__( 'Used for', 'cybergate-security' )           => esc_html( isset( $used[ $clam['state'] ] ) ? $used[ $clam['state'] ] : $clam['label'] ),
		);
		if ( ! empty( $clam['bins'] ) ) {
			$lines = array();
			foreach ( $clam['bins'] as $bin => $row ) {
				$name = '<code class="wpcs-path">' . esc_html( basename( (string) $bin ) ) . '</code> ';
				if ( ! empty( $row['ok'] ) ) {
					/* translators: %s: duration */
					$lines[] = $name . $this->badge( sprintf( __( 'Works, %s', 'cybergate-security' ), Sysadmin_Tools::duration_ms( $row['ms'] ) ), (int) $row['ms'] > \WPCyberSecurity\Scanner::SLOW_MS ? 'medium' : 'ok' );
				} else {
					$lines[] = $name . $this->badge( __( 'Failed', 'cybergate-security' ), 'high' ) . ' <span class="wpcs-muted">' . esc_html( (string) $row['error'] ) . '</span>';
				}
			}
			/* translators: %s: time ago */
			$lines[] = '<span class="wpcs-muted">' . esc_html( sprintf( __( 'Tested %s with the EICAR test file.', 'cybergate-security' ), Admin::ago( $clam['tested_at'] ) ) ) . '</span>';
			$rows[ __( 'Self-test', 'cybergate-security' ) ] = implode( '<br>', $lines );
		}
		$this->engine( 'ClamAV', $clam['label'], $clam['tone'], $rows );

		// Linux Malware Detect.
		if ( null === $maldet['linked'] ) {
			$linked = esc_html__( 'Unknown', 'cybergate-security' );
		} else {
			$linked = $maldet['linked'] ? $this->badge( $yes, 'ok' ) : $this->badge( $no, 'medium' );
		}
		$rows = array(
			__( 'Program', 'cybergate-security' ) => '' !== $maldet['binary'] ? '<code class="wpcs-path">' . esc_html( $maldet['binary'] ) . '</code>' : ( ! empty( $maldet['hidden'] ) ? esc_html__( 'Unknown (hosting hides it)', 'cybergate-security' ) : esc_html__( 'Not found', 'cybergate-security' ) ),
		);
		if ( '' !== $maldet['binary'] ) {
			$rows[ __( 'Signature version', 'cybergate-security' ) ]       = '' !== $maldet['version'] ? '<code>' . esc_html( $maldet['version'] ) . '</code>' : esc_html__( 'Unknown', 'cybergate-security' );
			$rows[ __( 'Signatures linked into ClamAV', 'cybergate-security' ) ] = $linked;
			$rows[ __( 'Real-time monitor', 'cybergate-security' ) ]             = $maldet['monitor'] ? $this->badge( __( 'Available', 'cybergate-security' ), 'ok' ) : $this->badge( __( 'Unavailable: install inotify-tools', 'cybergate-security' ), 'medium' );
		} elseif ( ! $maldet['supported'] ) {
			$rows[ __( 'Note', 'cybergate-security' ) ] = esc_html__( 'maldet runs on Linux servers only.', 'cybergate-security' );
		} elseif ( ! empty( $maldet['hidden'] ) ) {
			$rows[ __( 'Note', 'cybergate-security' ) ] = esc_html__( 'PHP may not look into the folders maldet is installed in (open_basedir), so it cannot tell whether it is there. Ask your host, or run "maldet --help" in a shell.', 'cybergate-security' );
		} else {
			$rows[ __( 'Note', 'cybergate-security' ) ] = esc_html__( 'Optional. Adds signatures made for website malware such as PHP web shells.', 'cybergate-security' );
		}
		$this->engine( __( 'Linux Malware Detect (maldet)', 'cybergate-security' ), $maldet['label'], $maldet['tone'], $rows );
		echo '</div>';

		// Is it running on the server right now.
		$states = array(
			'ok'      => array( 'yes-alt', 'ok' ),
			'bad'     => array( 'dismiss', 'high' ),
			'unknown' => array( 'editor-help', 'muted' ),
			'na'      => array( 'minus', 'muted' ),
		);
		echo '<h3 class="wpcs-subhead">' . esc_html__( 'On the server now', 'cybergate-security' ) . '</h3>';
		echo '<ul class="wpcs-live">';
		foreach ( $tools->antivirus_live() as $row ) {
			$state = isset( $states[ $row['state'] ] ) ? $states[ $row['state'] ] : $states['unknown'];
			echo '<li class="wpcs-live__row is-' . esc_attr( $row['state'] ) . '"><span class="dashicons dashicons-' . esc_attr( $state[0] ) . '" aria-hidden="true"></span><span class="wpcs-live__label">' . esc_html( $row['label'] ) . '</span>' . $this->badge( $row['text'], $state[1] ) . '</li>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- badge is escaped.
		}
		echo '</ul>';

		$this->field(
			__( 'ClamAV scanning', 'cybergate-security' ),
			self::toggle_row( 'clamav_enabled', ! empty( $s['clamav_enabled'] ), __( 'Also scan uploads with ClamAV', 'cybergate-security' ), __( 'Uploads take a little longer. clamdscan is much faster than clamscan when the clamd service runs; with it, whole-site scans use ClamAV too.', 'cybergate-security' ) )
		);
		$has_scan = false;
		foreach ( array_keys( (array) $clam['bins'] ) as $bin ) {
			$has_scan = $has_scan || false === strpos( basename( (string) $bin ), 'clamdscan' );
		}
		if ( $has_scan || ! empty( $clam['forced'] ) ) {
			$this->field(
				__( 'Slow clamscan', 'cybergate-security' ),
				self::toggle_row(
					'clamav_slow_uploads',
					! empty( $clam['forced'] ),
					__( 'Also use the slow clamscan for uploads', 'cybergate-security' ),
					__( 'Without the background service, clamscan loads its whole database for every file, which takes seconds. By default a clamscan slower than 3 seconds is only used for held uploads that cron imports, so nobody waits for it. Turn this on to make every upload wait for it.', 'cybergate-security' )
				)
			);
		}
		$this->field(
			__( 'ClamAV program', 'cybergate-security' ),
			'<input type="text" id="wpcs-clamav-binary" name="clamav_binary" value="' . esc_attr( $s['clamav_binary'] ) . '" placeholder="' . esc_attr( '' !== $clam['binary'] ? $clam['binary'] : '/usr/bin/clamdscan' ) . '" class="wpcs-mono">',
			__( 'Leave empty to detect it automatically. Only clamscan or clamdscan binaries are accepted.', 'cybergate-security' ),
			'wpcs-clamav-binary'
		);

		// ClamAV install guide: open while ClamAV is missing, folded away once it works.
		$info  = Sysadmin_Tools::call( 'scanner', 'clamav_info', array(), array() );
		$ready = in_array( $clam['state'], array( 'ready_off', 'uploads', 'uploads_scans' ), true ) && ! empty( $info['daemon'] );
		if ( $ready ) {
			echo '<details class="wpcs-disclosure"><summary>' . esc_html__( 'ClamAV install guide', 'cybergate-security' ) . '</summary>';
		} else {
			echo '<h3 class="wpcs-guide-title">' . esc_html__( 'How to install ClamAV', 'cybergate-security' ) . '</h3>';
		}
		Clamav_Guide::render( (string) $tools->clamav_detect(), (bool) $clam['exec'], ! empty( $info['daemon'] ), $clam );
		if ( $ready ) {
			echo '</details>';
		}

		// One server script for both engines.
		$block = Sysadmin_Tools::cgav_install_block();
		if ( '' !== $block ) {
			echo '<h3 class="wpcs-subhead">' . esc_html__( 'Server script (cgav)', 'cybergate-security' ) . '</h3>';
			echo '<p class="wpcs-muted">' . esc_html__( 'One script for root that installs and checks ClamAV and Linux Malware Detect for this site. Every section prints the status before and after, and is safe to run again; nothing deletes or moves site files.', 'cybergate-security' ) . '</p>';
			echo '<p class="wpcs-row"><a class="button" href="' . esc_url( $this->action_url( 'cgav' ) ) . '"><span class="dashicons dashicons-download" aria-hidden="true"></span>' . esc_html__( 'Download server script (cgav)', 'cybergate-security' ) . '</a></p>';
			echo '<details class="wpcs-cmds"><summary><span class="dashicons dashicons-editor-code" aria-hidden="true"></span><span class="wpcs-cmds__show">' . esc_html__( 'Show commands', 'cybergate-security' ) . '</span><span class="wpcs-cmds__label">' . esc_html__( 'Install everything in one paste (as root)', 'cybergate-security' ) . '</span></summary><div class="wpcs-cmds__body">';
			echo '<p class="wpcs-sub">' . esc_html__( 'Paste the whole block into an SSH session as root. It saves the script, installs the cgav command for this site and shows the status.', 'cybergate-security' ) . '</p>';
			echo self::code( $block ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in code().
			echo '</div></details>';
			echo '<dl class="wpcs-cgav">';
			foreach ( Sysadmin_Tools::cgav_commands() as $command => $what ) {
				echo '<div><dt><code>' . esc_html( $command ) . '</code></dt><dd>' . esc_html( $what ) . '</dd></div>';
			}
			echo '</dl>';
		}

		// maldet by hand, moved here from Integrations.
		echo '<h3 class="wpcs-subhead">' . esc_html__( 'Linux Malware Detect step by step', 'cybergate-security' ) . '</h3>';
		if ( '' === $maldet['binary'] && $maldet['supported'] ) {
			$install = Clamav_Guide::maldet_install_steps();
			echo '<p class="wpcs-muted">' . esc_html( $install[0]['text'] ) . '</p>';
			echo self::commands( $install[0]['code'], __( 'Install (as root)', 'cybergate-security' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in commands().
		}
		$no_monitor = '' !== $maldet['binary'] && false === $maldet['monitor'];
		if ( $no_monitor ) {
			self::notice( __( 'maldet is installed, but its real-time monitor is unavailable: install inotify-tools (step 1 below).', 'cybergate-security' ), 'warn' );
		}
		echo '<p class="wpcs-muted">' . esc_html__( 'Watch this site in real time, start the monitor on every boot, and scan recently changed files in the background. Run as root.', 'cybergate-security' ) . '</p>';
		echo '<details class="wpcs-cmds"' . ( $no_monitor ? ' open' : '' ) . '><summary><span class="dashicons dashicons-editor-code" aria-hidden="true"></span><span class="wpcs-cmds__show">' . esc_html__( 'Show commands', 'cybergate-security' ) . '</span><span class="wpcs-cmds__label">' . esc_html__( 'Real-time monitor and scans', 'cybergate-security' ) . '</span></summary><div class="wpcs-cmds__body">';
		self::render_steps( $tools->maldet_steps() );
		echo '</div></details>';
		$this->card_close();
	}

	/**
	 * One engine block of the Antivirus card.
	 *
	 * @param string $name  Engine name.
	 * @param string $state State label.
	 * @param string $tone  Badge tone.
	 * @param array  $rows  label => escaped HTML.
	 */
	private function engine( $name, $state, $tone, array $rows ) {
		echo '<div class="wpcs-engine">';
		echo '<div class="wpcs-engine__head"><strong>' . esc_html( $name ) . '</strong>' . $this->badge( $state, $tone ) . '</div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- badge is escaped.
		echo '<dl class="wpcs-engine__rows">';
		foreach ( $rows as $label => $value ) {
			echo '<div><dt>' . esc_html( $label ) . '</dt><dd>' . $value . '</dd></div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built from escaped parts.
		}
		echo '</dl></div>';
	}

	/**
	 * Developer instructions: what needs someone with server access.
	 *
	 * @param array[] $items Developer_Instructions::items().
	 */
	private function section_developer( array $items ) {
		$this->card_open( 'wpcs-developer', 'clipboard', __( 'Developer instructions', 'cybergate-security' ), __( 'Steps this server did not let the plugin do from the admin panel, and setup that always needs server access. Send them to your developer or host: each one has the exact commands for this server.', 'cybergate-security' ) );
		if ( ! $items ) {
			self::notice( __( 'Nothing needs server access right now.', 'cybergate-security' ), 'ok' );
			$this->card_close();
			return;
		}
		echo '<div class="wpcs-devbar"><span class="wpcs-devbar__count">' . esc_html(
			/* translators: %d: number of items */
			sprintf( _n( '%d item needs server access', '%d items need server access', count( $items ), 'cybergate-security' ), count( $items ) )
		) . '</span>';
		echo '<button type="button" class="button" data-wpcs-copy="#wpcs-dev-text"><span class="dashicons dashicons-admin-page" aria-hidden="true"></span>' . esc_html__( 'Copy all', 'cybergate-security' ) . '</button>';
		echo '<a class="button" href="' . esc_url( \WPCyberSecurity\Developer_Instructions::download_url() ) . '"><span class="dashicons dashicons-download" aria-hidden="true"></span>' . esc_html__( 'Download as .txt', 'cybergate-security' ) . '</a>';
		echo '</div>';
		echo '<ol class="wpcs-devlist">';
		foreach ( $items as $item ) {
			echo '<li class="wpcs-devlist__item">';
			echo '<div class="wpcs-devlist__head"><strong>' . esc_html( $item['title'] ) . '</strong>';
			if ( '' !== $item['error'] ) {
				echo $this->badge( __( 'Failed from the admin panel', 'cybergate-security' ), 'high' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in badge().
			}
			if ( $item['optional'] ) {
				echo $this->badge( __( 'Optional', 'cybergate-security' ), 'muted' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in badge().
			}
			echo '</div>';
			if ( '' !== $item['why'] ) {
				echo '<p class="wpcs-sub">' . esc_html( $item['why'] ) . '</p>';
			}
			if ( '' !== $item['error'] ) {
				echo '<p class="wpcs-devlist__error"><span class="dashicons dashicons-warning" aria-hidden="true"></span>' . esc_html(
					sprintf(
						/* translators: 1: date and time, 2: error message */
						__( 'Tried %1$s: %2$s', 'cybergate-security' ),
						Admin::ago( (int) $item['at'] ),
						$item['error']
					)
				) . '</p>';
			}
			self::render_steps( $item['steps'] );
			echo '</li>';
		}
		echo '</ol>';
		echo '<textarea id="wpcs-dev-text" class="wpcs-offscreen" readonly tabindex="-1" aria-hidden="true">' . esc_textarea( \WPCyberSecurity\Developer_Instructions::as_text( $items ) ) . '</textarea>';
		$this->card_close();
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

		$this->card_open( 'wpcs-storage', 'database', __( 'Storage', 'cybergate-security' ), __( 'Quarantined files, scan job files, the early guard configuration and its upload spool live in the data folder.', 'cybergate-security' ) );

		$badges  = is_dir( $dir ) && wp_is_writable( $dir ) ? $this->badge( __( 'Writable', 'cybergate-security' ), 'ok' ) : $this->badge( __( 'Not writable', 'cybergate-security' ), 'high' );
		$badges .= ' ' . ( $in_root ? $this->badge( __( 'Inside the web root', 'cybergate-security' ), 'medium' ) : $this->badge( __( 'Outside the web root', 'cybergate-security' ), 'ok' ) );
		if ( defined( 'WPCYBERSEC_DATA_DIR' ) && WPCYBERSEC_DATA_DIR ) {
			$badges .= ' ' . $this->badge( __( 'Set by WPCYBERSEC_DATA_DIR', 'cybergate-security' ), 'info' );
		}
		$status  = method_exists( $storage, 'check' ) ? $storage->check() : array( 'state' => 'ok' );
		$problem = 'ok' !== $status['state'] ? $storage->problem( $status ) : null;
		if ( 'fallback' === $status['state'] ) {
			$badges .= ' ' . $this->badge( __( 'Fallback folder', 'cybergate-security' ), 'medium' );
		}
		$note = $problem ? '<p class="wpcs-sub">' . esc_html( $problem['text'] . ' ' . $problem['fix'] ) . '</p>' . ( '' !== $problem['code'] ? '<code class="wpcs-path">' . esc_html( $problem['code'] ) . '</code>' : '' ) : '';
		$this->field( __( 'Data folder', 'cybergate-security' ), '<code class="wpcs-path">' . esc_html( $dir ) . '</code><div class="wpcs-badges">' . $badges . '</div>' . $note );

		$probe = $tools->probe_quarantine_web( false );
		switch ( $probe['result'] ) {
			case 'outside':
				$web = $this->badge( __( 'Not reachable', 'cybergate-security' ), 'ok' ) . ' ' . esc_html__( 'The folder is outside the web root.', 'cybergate-security' );
				break;
			case 'blocked':
				/* translators: %d: HTTP status code */
				$web = $this->badge( __( 'Blocked', 'cybergate-security' ), 'ok' ) . ' ' . esc_html( sprintf( __( 'A test file could not be downloaded (HTTP %d).', 'cybergate-security' ), $probe['code'] ) );
				break;
			case 'reachable':
				$web = $this->badge( __( 'Reachable', 'cybergate-security' ), 'high' ) . ' ' . esc_html__( 'A test file could be downloaded: the server ignores the .htaccess deny rules. Add the nginx rule from the Web server card or move the folder.', 'cybergate-security' );
				break;
			default:
				$web = $this->badge( __( 'Not tested', 'cybergate-security' ), 'muted' ) . ' ' . esc_html( $probe['message'] ? $probe['message'] : __( 'The site could not reach itself to test this.', 'cybergate-security' ) );
		}
		$this->field( __( 'Web access test', 'cybergate-security' ), '<div class="wpcs-inline-status">' . $web . '</div>' );

		if ( $in_root ) {
			$snippet = $tools->data_dir_snippet();
			$this->field(
				__( 'Move it outside the web root', 'cybergate-security' ),
				self::commands( $snippet['shell'], __( 'Shell (as root)', 'cybergate-security' ), '', true ) . self::code( $snippet['config'], 'wp-config.php' ),
				__( 'Run the commands, then add the line to wp-config.php above "That\'s all, stop editing!". The plugin switches to the new folder on the next page load.', 'cybergate-security' )
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

		$this->card_open( 'wpcs-scan', 'search', __( 'Scan scope and performance', 'cybergate-security' ) );

		$root  = self::radio_list(
			'scan_root',
			array(
				'abspath' => array( __( 'WordPress folder', 'cybergate-security' ), $abspath ),
				/* translators: %s: folder path */
				'parent'  => array( __( 'Parent folder', 'cybergate-security' ), sprintf( __( '%s - also checks files next to WordPress, such as other apps or forgotten backups.', 'cybergate-security' ), $parent ) ),
				'custom'  => array( __( 'Custom folder', 'cybergate-security' ), __( 'Any folder that contains the site.', 'cybergate-security' ) ),
			),
			$s['scan_root']
		);
		$root .= '<div class="wpcs-indent' . ( 'custom' === $s['scan_root'] ? '' : ' wpcs-hidden' ) . '" data-wpcs-scan-root-custom><input type="text" name="scan_root_custom" value="' . esc_attr( $s['scan_root_custom'] ) . '" placeholder="' . esc_attr( $parent ) . '" class="wpcs-mono" aria-label="' . esc_attr__( 'Custom scan folder', 'cybergate-security' ) . '"></div>';
		$outside = method_exists( '\WPCyberSecurity\Paths', 'outside_root' ) ? \WPCyberSecurity\Paths::outside_root() : array();
		if ( $outside ) {
			// WordPress folders outside the scan folder (Bedrock, WordPress in a subfolder, linked uploads) are scanned too.
			$paths  = array();
			$loaded = 0;
			foreach ( $outside as $entry ) {
				if ( 'loaded' === $entry['kind'] ) {
					++$loaded; // Files wp-config.php loads (Composer's autoloader and so on): counted, not listed.
					continue;
				}
				$paths[] = '<code>' . esc_html( $entry['path'] ) . '</code>' . ( 'top' === $entry['depth'] ? ' ' . esc_html__( '(files at its top only)', 'cybergate-security' ) : '' );
			}
			if ( $loaded ) {
				/* translators: %d: number of files */
				$paths[] = esc_html( sprintf( _n( '%d more file that wp-config.php loads', '%d more files that wp-config.php loads', $loaded, 'cybergate-security' ), $loaded ) );
			}
			$root .= '<div class="wpcs-notice wpcs-notice--info wpcs-notice--compact"><span class="dashicons dashicons-info" aria-hidden="true"></span><p>' . esc_html__( 'Some WordPress folders lie outside the scan folder and are scanned as well:', 'cybergate-security' ) . ' ' . implode( ', ', $paths ) . '</p></div>';
		}
		$this->field( __( 'Scan folder', 'cybergate-security' ), $root, __( 'After changing the folder, rebuild the baseline from the Dashboard, otherwise every file is reported as new.', 'cybergate-security' ) );

		$this->field(
			__( 'Exclusions', 'cybergate-security' ),
			$this->textarea( 'exclusions', (array) $s['exclusions'], 6 ),
			__( 'One per line, relative to the scan folder. Folders end with /, and the wildcards * and ? work (for example *.log). The data folder is always excluded.', 'cybergate-security' ),
			'wpcs-exclusions'
		);
		$this->field(
			__( 'Largest file to check', 'cybergate-security' ),
			$this->number( 'max_file_mb', $s['max_file_mb'], 1, 512, __( 'MB', 'cybergate-security' ) ),
			__( 'Bigger files are fingerprinted but not searched for malware.', 'cybergate-security' ),
			'wpcs-max-file-mb'
		);
		$this->field(
			__( 'Work per scan step', 'cybergate-security' ),
			$this->number( 'tick_seconds', $s['tick_seconds'], 3, 25, __( 'seconds', 'cybergate-security' ) ),
			__( 'How long each step of a scan runs. Lower it if scans time out on shared hosting.', 'cybergate-security' ),
			'wpcs-tick-seconds'
		);
		$this->field(
			__( 'Executable extensions', 'cybergate-security' ),
			'<input type="text" id="wpcs-exec-extensions" name="exec_extensions" value="' . esc_attr( implode( ', ', (array) $s['exec_extensions'] ) ) . '" class="wpcs-mono">',
			__( 'Comma separated. Matched anywhere in the name, so shell.php.jpg counts too. php, phtml and phar are always included.', 'cybergate-security' ),
			'wpcs-exec-extensions'
		);
		$this->field(
			__( 'Executable file names', 'cybergate-security' ),
			'<input type="text" id="wpcs-exec-filenames" name="exec_filenames" value="' . esc_attr( implode( ', ', (array) $s['exec_filenames'] ) ) . '" class="wpcs-mono">',
			__( 'Comma separated. Server configuration files that change how code runs. .htaccess and .user.ini are always included.', 'cybergate-security' ),
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
		$this->card_open( 'wpcs-guard', 'shield-alt', __( 'Early upload guard', 'cybergate-security' ), __( 'Runs before any PHP code through auto_prepend_file and holds files uploaded to ANY PHP script on this site, not only WordPress. Held files appear on the Reports page like other uploads.', 'cybergate-security' ) );

		if ( ! $manager || ! method_exists( $manager, 'status' ) ) {
			self::notice( __( 'The early guard module is not available in this installation.', 'cybergate-security' ), 'bad' );
			$this->card_close();
			return;
		}
		$status = Sysadmin_Tools::call( 'guard_manager', 'status', array(), array() );
		$status = is_array( $status ) ? $status : array();
		$yes    = __( 'Yes', 'cybergate-security' );
		$no     = __( 'No', 'cybergate-security' );

		$manager_live = method_exists( $manager, 'live_state' ) ? $manager->live_state( $status ) : array( 'state' => ! empty( $status['active'] ) ? 'active' : ( ! empty( $status['installed'] ) ? 'installed' : 'off' ), 'label' => '', 'tone' => 'muted' );
		$ping         = isset( $status['ping'] ) && is_array( $status['ping'] ) ? $status['ping'] : null;
		$results      = array(
			'active'   => array( __( 'PHP loaded the guard', 'cybergate-security' ), 'ok' ),
			'inactive' => array( __( 'PHP did not load the guard', 'cybergate-security' ), 'medium' ),
			'down'     => array( __( 'The site did not answer', 'cybergate-security' ), 'high' ),
		);
		if ( $ping && isset( $results[ $ping['result'] ] ) && ! empty( $status['installed'] ) ) {
			/* translators: %s: time ago */
			$last = $this->badge( $results[ $ping['result'] ][0], $results[ $ping['result'] ][1] ) . ' <span class="wpcs-muted">' . esc_html( Admin::ago( $ping['at'] ) ) . '</span>';
		} else {
			$last = esc_html__( 'Not tested yet', 'cybergate-security' );
		}

		$rows = array(
			array( __( 'State', 'cybergate-security' ), '' !== (string) $manager_live['label'] ? $this->badge( $manager_live['label'], $manager_live['tone'] ) : '' ),
			array( __( 'Installed', 'cybergate-security' ), ! empty( $status['installed'] ) ? $this->badge( $yes, 'ok' ) : $this->badge( $no, 'muted' ) ),
			array(
				__( 'Active in this request', 'cybergate-security' ),
				! empty( $status['active'] )
					? $this->badge( $yes, 'ok' )
					: ( isset( $status['can_tell'] ) && ! $status['can_tell']
						? esc_html__( 'Cannot tell here (this request does not read .user.ini or .htaccess)', 'cybergate-security' )
						: $this->badge( $no, empty( $status['installed'] ) ? 'muted' : 'medium' ) ),
			),
			array( __( 'Last live test', 'cybergate-security' ), $last ),
			array(
				__( 'Bootstrap file', 'cybergate-security' ),
				'<code class="wpcs-path">' . esc_html( isset( $status['bootstrap_path'] ) ? $status['bootstrap_path'] : '' ) . '</code> '
				. ( ! empty( $status['bootstrap_exists'] ) ? $this->badge( __( 'Exists', 'cybergate-security' ), 'ok' ) : $this->badge( __( 'Missing', 'cybergate-security' ), 'muted' ) ),
			),
			array( 'auto_prepend_file', ! empty( $status['prepend'] ) ? '<code class="wpcs-path">' . esc_html( $status['prepend'] ) . '</code>' : esc_html__( 'Not set', 'cybergate-security' ) ),
			array( __( 'Conflict', 'cybergate-security' ), ! empty( $status['conflict'] ) ? '<code class="wpcs-path">' . esc_html( $status['conflict'] ) . '</code>' : esc_html__( 'None', 'cybergate-security' ) ),
			array( __( 'PHP SAPI', 'cybergate-security' ), esc_html( isset( $status['sapi'] ) ? $status['sapi'] : PHP_SAPI ) ),
			array( __( 'Uploads waiting to be imported', 'cybergate-security' ), esc_html( number_format_i18n( isset( $status['pending_spool'] ) ? (int) $status['pending_spool'] : 0 ) ) ),
		);
		echo '<table class="wpcs-status-table"><tbody>';
		foreach ( $rows as $row ) {
			echo '<tr><th scope="row">' . esc_html( $row[0] ) . '</th><td>' . $row[1] . '</td></tr>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built from escaped parts.
		}
		echo '</tbody></table>';

		$state = (string) $manager_live['state'];
		if ( ! empty( $status['conflict'] ) ) {
			$help = ! empty( $status['conflict_help'] ) ? (string) $status['conflict_help'] : __( 'Another file already uses auto_prepend_file. The guard bootstrap includes it so both keep working, but check the snippets below before you change the PHP configuration.', 'cybergate-security' );
			self::notice( $help, 'warn' );
			if ( ! empty( $status['conflict_snippet'] ) ) {
				echo self::code( (string) $status['conflict_snippet'], __( 'Add at the top of the other prepend file', 'cybergate-security' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in code().
			}
		} elseif ( 'confirmed' === $state ) {
			self::notice( __( 'The guard runs: the last live test request to the site was answered with the guard loaded. This request cannot tell by itself (PHP on the command line and the development server do not read .user.ini or .htaccess).', 'cybergate-security' ), 'ok' );
		} elseif ( 'installed' === $state ) {
			self::notice( __( 'Installed, but PHP does not load it yet. Use "Install and switch on the early guard" below, or set auto_prepend_file with the recommended snippet, then reload this page.', 'cybergate-security' ), 'warn' );
		}

		$hardening = Sysadmin_Tools::service( 'hardening' );
		$one_click = ! in_array( $state, array( 'active', 'confirmed' ), true ) && empty( $status['conflict'] ) && $hardening && method_exists( $hardening, 'descriptor' ) ? $hardening->descriptor( 'guard' ) : null;
		if ( $one_click ) {
			echo '<div class="wpcs-autofix wpcs-card__lead">';
			echo '<button type="button" class="button button-primary" data-wpcs-fix="guard"><span class="dashicons dashicons-shield-alt" aria-hidden="true"></span>' . esc_html( $one_click['label'] ) . '</button>';
			echo '<span class="wpcs-sub">' . esc_html( $one_click['description'] ) . '</span>';
			echo '</div>';
		}

		echo '<div class="wpcs-row wpcs-card__actions">';
		if ( $one_click ) {
			echo '<span class="wpcs-muted">' . esc_html__( 'Or step by step:', 'cybergate-security' ) . '</span>';
		}
		if ( empty( $status['installed'] ) ) {
			echo '<a class="button' . ( $one_click ? '' : ' button-primary' ) . '" href="' . esc_url( $this->action_url( 'guard', array( 'op' => 'install' ) ) ) . '"><span class="dashicons dashicons-download" aria-hidden="true"></span>' . esc_html( $one_click ? __( 'Only install the guard files', 'cybergate-security' ) : __( 'Install the guard files', 'cybergate-security' ) ) . '</a>';
		} else {
			if ( in_array( $state, array( 'active', 'confirmed', 'installed' ), true ) && $hardening && method_exists( $hardening, 'reping' ) ) {
				echo '<a class="button" href="' . esc_url( $this->action_url( 'guard', array( 'op' => 'ping' ) ) ) . '"><span class="dashicons dashicons-update" aria-hidden="true"></span>' . esc_html__( 'Test again', 'cybergate-security' ) . '</a>';
			}
			echo '<a class="button" href="' . esc_url( $this->action_url( 'guard', array( 'op' => 'install' ) ) ) . '"><span class="dashicons dashicons-update" aria-hidden="true"></span>' . esc_html__( 'Reinstall the files', 'cybergate-security' ) . '</a>';
			echo '<a class="button wpcs-btn-danger" href="' . esc_url( $this->action_url( 'guard', array( 'op' => 'uninstall' ) ) ) . '" data-wpcs-confirm="' . esc_attr__( 'Switch the early guard off? Uploads to scripts outside WordPress will no longer be held.', 'cybergate-security' ) . '">' . esc_html__( 'Uninstall', 'cybergate-security' ) . '</a>';
		}
		// Only with the bootstrap in place: a .user.ini line that points at a missing file stops every PHP request.
		if ( method_exists( $manager, 'write_user_ini' ) && ! empty( $status['installed'] ) && ! empty( $status['bootstrap_exists'] ) && ! in_array( $state, array( 'active', 'confirmed' ), true ) ) {
			echo '<a class="button" href="' . esc_url( $this->action_url( 'guard', array( 'op' => 'write_user_ini' ) ) ) . '"><span class="dashicons dashicons-media-text" aria-hidden="true"></span>' . esc_html__( 'Only write .user.ini', 'cybergate-security' ) . '</a>';
			echo '<span class="wpcs-muted wpcs-inline-help">' . esc_html__( '.user.ini works with PHP-FPM and CGI. For mod_php or a server-wide setting, use one of the snippets below.', 'cybergate-security' ) . '</span>';
		}
		echo '</div>';

		$this->field(
			__( 'When an upload is held', 'cybergate-security' ),
			self::radio_list(
				'guard_action',
				array(
					'block' => array( __( 'Block the request', 'cybergate-security' ), __( 'The script answers HTTP 403 with a short message and never runs. Safest.', 'cybergate-security' ) ),
					'strip' => array( __( 'Remove the file and continue', 'cybergate-security' ), __( 'The script runs as if no file was sent. Use this if blocking breaks a form you need.', 'cybergate-security' ) ),
				),
				$s['guard_action']
			)
		);
		$this->field(
			__( 'Not checked by the guard', 'cybergate-security' ),
			$this->textarea( 'guard_exempt', (array) $s['guard_exempt'], 5 ),
			__( 'Requests whose path or query contains one of these lines are skipped. WordPress media uploads are already checked by the plugin itself, so they are listed here by default.', 'cybergate-security' ),
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
				echo '<h3 class="wpcs-subhead">' . esc_html__( 'Recommended for this server', 'cybergate-security' ) . ' ' . $this->badge( isset( $status['sapi'] ) ? (string) $status['sapi'] : PHP_SAPI, 'info' ) . '</h3>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- badge is escaped.
				$this->render_snippet( $recommended[0] );
			} else {
				$others = array_merge( $recommended, $others );
			}
			if ( $others ) {
				echo '<details class="wpcs-disclosure"><summary>' . esc_html__( 'Other ways to set auto_prepend_file (.user.ini, Apache, PHP-FPM, nginx, php.ini)', 'cybergate-security' ) . '</summary>';
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
	private function section_cron( array $s, Sysadmin_Tools $tools, array $by_id = array() ) {
		$this->card_open( 'wpcs-cron', 'clock', __( 'Real cron', 'cybergate-security' ), __( 'WordPress runs scheduled tasks only when someone visits the site. A cron job on the server makes scans run on time and lets long scans finish without a browser.', 'cybergate-security' ) );
		$disabled = defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON;
		$next     = \WPCyberSecurity\Network::next_scheduled( 'wpcybersec_scheduled_scan' );
		$last_cli = (int) \WPCyberSecurity\Network::get_option( 'wpcybersec_cli_cron_at', 0 );
		$state    = $disabled ? $this->badge( __( 'WP-Cron on page visits is off', 'cybergate-security' ), 'ok' ) : $this->badge( __( 'WP-Cron runs on page visits', 'cybergate-security' ), 'muted' );
		if ( $last_cli ) {
			/* translators: %s: time ago */
			$state .= ' ' . $this->badge( sprintf( __( 'Real cron last ran %s', 'cybergate-security' ), Admin::ago( $last_cli ) ), $last_cli > time() - 2 * HOUR_IN_SECONDS ? 'ok' : 'medium' );
		}
		if ( $next ) {
			$state .= ' <span class="wpcs-muted">' . esc_html(
				/* translators: %s: date and time */
				sprintf( __( 'Next scheduled scan: %s', 'cybergate-security' ), wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $next ) )
			) . '</span>';
		} elseif ( 'off' !== $s['scan_schedule'] ) {
			$state .= ' <span class="wpcs-muted">' . esc_html__( 'No scan is scheduled yet.', 'cybergate-security' ) . '</span>';
		}
		echo '<div class="wpcs-inline-status wpcs-card__lead">' . $state . '</div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built from escaped parts.
		// The first variant opens when no real cron job runs yet, or scheduled tasks are late.
		$missing = $last_cli < time() - 2 * HOUR_IN_SECONDS || self::is_open( self::check_status( $by_id, 'wp_cron' ) );
		foreach ( $tools->cron_snippets() as $i => $snippet ) {
			echo '<div class="wpcs-cmd-block"><strong class="wpcs-cmd-block__title">' . esc_html( $snippet['label'] ) . '</strong>';
			echo self::commands( $snippet['code'], $snippet['file'], $snippet['help'], 0 === $i && $missing ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in commands().
			echo '</div>';
		}
		// The same switch-off step as the wizard: a button once real cron is seen running.
		$hardening = Sysadmin_Tools::service( 'hardening' );
		if ( ! $disabled && $hardening && method_exists( $hardening, 'descriptor' ) && $hardening->descriptor( 'disable_wp_cron' ) ) {
			$hardening->render_fix( 'disable_wp_cron' );
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
		$this->card_open( 'wpcs-freeze', 'lock', __( 'Freeze lock', 'cybergate-security' ), __( 'While frozen, nobody can install, update, delete or edit plugins, themes or WordPress core from the dashboard, even with a stolen administrator login.', 'cybergate-security' ) );
		$this->field(
			__( 'Freeze mode', 'cybergate-security' ),
			self::toggle_row( 'freeze_mods', ! empty( $s['freeze_mods'] ), __( 'Freeze plugins, themes and core', 'cybergate-security' ), __( 'Unlock for a few minutes when you want to update. Updates through WP-CLI or SFTP are not affected.', 'cybergate-security' ) )
		);
		$this->field(
			__( 'Unlock for', 'cybergate-security' ),
			$this->number( 'unlock_minutes', $s['unlock_minutes'], 1, 240, __( 'minutes', 'cybergate-security' ) ),
			'',
			'wpcs-unlock-minutes'
		);
		$this->field(
			__( 'Code editor', 'cybergate-security' ),
			self::toggle_row( 'disable_file_editor', ! empty( $s['disable_file_editor'] ), __( 'Turn off the theme and plugin file editor', 'cybergate-security' ), __( 'Same as DISALLOW_FILE_EDIT in wp-config.php. When wp-config.php already sets that constant, it wins.', 'cybergate-security' ) )
		);

		if ( ! $gate || ! method_exists( $gate, 'unlocked_until' ) ) {
			$this->field( __( 'Current state', 'cybergate-security' ), '<span class="wpcs-muted">' . esc_html__( 'The install gate module is not available.', 'cybergate-security' ) . '</span>' );
		} elseif ( \WPCyberSecurity\Install_Gate::mods_disallowed() ) {
			$html = '<div class="wpcs-row">' . $this->badge( __( 'Disabled by site config', 'cybergate-security' ), 'ok' ) . '</div>';
			$this->field( __( 'Current state', 'cybergate-security' ), $html, __( 'Installs and updates are disabled by the site config (DISALLOW_FILE_MODS in wp-config.php), so there is nothing to unlock here. Remove that line from wp-config.php to install or update from the dashboard again.', 'cybergate-security' ) );
		} elseif ( empty( $s['freeze_mods'] ) ) {
			$html = '<div class="wpcs-row">' . $this->badge( __( 'Off - changes allowed', 'cybergate-security' ), 'muted' ) . '</div>';
			$this->field( __( 'Current state', 'cybergate-security' ), $html, __( 'Plugins, themes and core can be changed as usual. Turn on Freeze mode and save to lock them.', 'cybergate-security' ) );
		} else {
			$until    = (int) Sysadmin_Tools::call( 'install_gate', 'unlocked_until', array(), 0 );
			$unlocked = $until > time();
			$minutes  = max( 1, (int) $s['unlock_minutes'] );
			/* translators: %s: time */
			$text  = $unlocked ? sprintf( __( 'Unlocked until %s', 'cybergate-security' ), wp_date( get_option( 'time_format' ), $until ) ) : __( 'Locked', 'cybergate-security' );
			$html  = '<div class="wpcs-row">';
			$html .= '<span class="wpcs-badge wpcs-badge--' . ( $unlocked ? 'medium' : 'ok' ) . '" data-wpcs-lock-state>' . esc_html( $text ) . '</span>';
			$html .= '<button type="button" class="button" data-wpcs-unlock data-minutes-input="#wpcs-unlock-minutes"' . ( $unlocked ? ' hidden' : '' ) . '><span class="dashicons dashicons-unlock" aria-hidden="true"></span><span data-wpcs-unlock-label>' . esc_html(
				/* translators: %s: number of minutes */
				sprintf( _n( 'Unlock for %s minute', 'Unlock for %s minutes', $minutes, 'cybergate-security' ), number_format_i18n( $minutes ) )
			) . '</span></button>';
			$html .= '<button type="button" class="button" data-wpcs-lock' . ( $unlocked ? '' : ' hidden' ) . '><span class="dashicons dashicons-lock" aria-hidden="true"></span>' . esc_html__( 'Lock now', 'cybergate-security' ) . '</button>';
			$html .= '</div>';
			$this->field( __( 'Current state', 'cybergate-security' ), $html );
		}
		$this->card_close();
	}

	/**
	 * @param array          $s     Settings.
	 * @param Sysadmin_Tools $tools Tools.
	 */
	private function section_hardening( array $s, Sysadmin_Tools $tools, array $by_id = array() ) {
		unset( $s );
		$status = $tools->uploads_htaccess_status();
		$server = Sysadmin_Tools::server_type();
		$this->card_open( 'wpcs-hardening', 'admin-site-alt3', __( 'Web server hardening', 'cybergate-security' ), __( 'Stop PHP from running where it never should, and keep private folders private.', 'cybergate-security' ) );

		$labels = array(
			'ours'  => $this->badge( __( 'CyberGate Security rules present', 'cybergate-security' ), 'ok' ),
			'other' => $this->badge( __( 'Blocking rules present', 'cybergate-security' ), 'ok' ),
			'none'  => $this->badge( __( 'No blocking rule', 'cybergate-security' ), 'medium' ),
		);
		echo '<h3 class="wpcs-subhead">' . esc_html__( 'Apache and LiteSpeed', 'cybergate-security' ) . ' ' . $labels[ $status ] . '</h3>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- badge is escaped.
		if ( 'nginx' === $server ) {
			// nginx never reads .htaccess: no button that would only look like a fix.
			echo '<p class="wpcs-muted">' . esc_html__( 'This server runs nginx, which ignores .htaccess files. Use the nginx rule below instead.', 'cybergate-security' ) . '</p>';
		} else {
			echo '<div class="wpcs-row wpcs-card__actions">';
			echo '<a class="button" href="' . esc_url( $this->action_url( 'write_htaccess' ) ) . '"><span class="dashicons dashicons-media-text" aria-hidden="true"></span>' . esc_html( 'ours' === $status ? __( 'Refresh uploads/.htaccess rules', 'cybergate-security' ) : __( 'Write uploads/.htaccess for me', 'cybergate-security' ) ) . '</a>';
			echo '<span class="wpcs-muted wpcs-inline-help">' . esc_html__( 'Adds the block between markers and keeps everything else, then tests that PHP no longer runs in uploads. If the server answers with an error, or PHP still runs, the change is undone.', 'cybergate-security' ) . '</span>';
			echo '</div>';
		}
		echo self::commands( $tools->apache_uploads_rules(), 'wp-content/uploads/.htaccess', '', 'none' === $status && 'nginx' !== $server ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in commands().

		echo '<h3 class="wpcs-subhead">nginx' . ( 'nginx' === $server ? ' ' . $this->badge( __( 'This server', 'cybergate-security' ), 'info' ) : '' ) . '</h3>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- badge is escaped.
		$nginx_open = 'nginx' === $server && ( self::is_open( self::check_status( $by_id, 'uploads_php' ) ) || self::is_open( self::check_status( $by_id, 'quarantine_web' ) ) );
		echo self::commands( $tools->nginx_rules(), __( 'Server block', 'cybergate-security' ), '', $nginx_open ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in commands().

		echo '<h3 class="wpcs-subhead">' . esc_html__( 'File permissions', 'cybergate-security' ) . '</h3>';
		$perms_open = self::is_open( self::check_status( $by_id, 'wp_config_perms' ) ) || 'fail' === self::check_status( $by_id, 'data_dir' );
		echo '<p class="wpcs-muted">' . esc_html__( 'Safe owners and permissions for the WordPress folder, wp-config.php and the data folder.', 'cybergate-security' ) . '</p>';
		echo self::commands( $tools->permission_commands(), __( 'Shell (as root)', 'cybergate-security' ), '', $perms_open ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in commands().
		echo '<p class="wpcs-muted">';
		printf(
			/* translators: %s: link to the environment check */
			esc_html__( 'To test whether PHP really is blocked in uploads, run the live test in the %s.', 'cybergate-security' ),
			'<a href="' . esc_url( Sysadmin_Tools::wizard_url( 'environment' ) ) . '">' . esc_html__( 'environment check', 'cybergate-security' ) . '</a>'
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
		$this->card_open( 'wpcs-integrations', 'networking', __( 'Server-level integrations', 'cybergate-security' ), __( 'Use the plugin\'s file fingerprints with tools that run outside PHP, so protection holds even if WordPress itself is compromised.', 'cybergate-security' ) );

		echo '<h3 class="wpcs-subhead">' . esc_html__( 'fapolicyd (RHEL, Rocky, Alma, Fedora)', 'cybergate-security' ) . '</h3>';
		echo '<p>' . esc_html__( 'Let PHP open only the PHP files you trust. The trust list contains every trusted file with its size and SHA-256, taken from the last baseline and approvals.', 'cybergate-security' ) . '</p>';
		echo '<div class="wpcs-row wpcs-card__actions"><a class="button" href="' . esc_url( $this->action_url( 'export', array( 'type' => 'fapolicyd' ) ) ) . '"><span class="dashicons dashicons-download" aria-hidden="true"></span>' . esc_html__( 'Download trust list', 'cybergate-security' ) . '</a></div>';
		echo self::commands( $tools->fapolicyd_rules(), __( 'Rules', 'cybergate-security' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in commands().

		echo '<h3 class="wpcs-subhead">' . esc_html__( 'inotify watcher', 'cybergate-security' ) . '</h3>';
		echo '<p>' . esc_html__( 'Starts a scan seconds after files change on disk, instead of waiting for the next scheduled scan.', 'cybergate-security' ) . '</p>';
		echo self::commands( $tools->inotify_script(), '/usr/local/bin/wpcybersec-watch.sh' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in commands().

		echo '<h3 class="wpcs-subhead">' . esc_html__( 'Linux Malware Detect (maldet)', 'cybergate-security' ) . '</h3>';
		echo '<p class="wpcs-muted">';
		printf(
			/* translators: %s: link to the Antivirus engines section */
			esc_html__( 'Its status and commands are in %s.', 'cybergate-security' ),
			'<a href="' . esc_url( Sysadmin_Tools::settings_url( 'advanced', array(), 'wpcs-antivirus' ) ) . '" data-wpcs-goto="antivirus">' . esc_html__( 'Antivirus engines', 'cybergate-security' ) . '</a>'
		);
		echo '</p>';
		$this->card_close();
	}

	/**
	 * @param array          $s     Settings.
	 * @param Sysadmin_Tools $tools Tools.
	 */
	private function section_tamper( array $s, Sysadmin_Tools $tools ) {
		unset( $s );
		$this->card_open( 'wpcs-tamper', 'privacy', __( 'Tamper check', 'cybergate-security' ), __( 'Detects allowlist entries that were added directly in the database instead of through an approval. Code running as the web server user can still read the key, so this raises the bar; it is not a guarantee.', 'cybergate-security' ) );
		$state = Sysadmin_Tools::call( 'allowlist', 'verify_integrity', array(), null );
		if ( true === $state ) {
			self::notice( __( 'On. The allowlist matches its checksum.', 'cybergate-security' ), 'ok' );
		} elseif ( false === $state ) {
			self::notice( __( 'The allowlist was changed outside the plugin. Review Reports > Allowlist and remove entries you did not add.', 'cybergate-security' ), 'bad' );
		} else {
			self::notice( __( 'Off. Add a secret key to wp-config.php to turn it on.', 'cybergate-security' ), 'info' );
			echo self::code( $tools->hmac_snippet(), 'wp-config.php', __( 'This key was generated just now. Keep it only in wp-config.php.', 'cybergate-security' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in code().
		}
		$this->card_close();
	}

	/**
	 * @param array          $s     Settings.
	 * @param Sysadmin_Tools $tools Tools.
	 */
	private function section_data( array $s, Sysadmin_Tools $tools ) {
		unset( $tools );
		$this->card_open( 'wpcs-data', 'database', __( 'Data and housekeeping', 'cybergate-security' ) );
		$this->field(
			__( 'Keep the activity log for', 'cybergate-security' ),
			$this->number( 'log_retention_days', $s['log_retention_days'], 0, 3650, __( 'days', 'cybergate-security' ) ),
			__( '0 keeps it forever.', 'cybergate-security' ),
			'wpcs-log-retention-days'
		);
		$snapshots = Sysadmin_Tools::service( 'snapshots' );
		if ( $snapshots && method_exists( $snapshots, 'stats' ) ) {
			$stats  = $snapshots->stats();
			$copies = $stats['files']
				? sprintf(
					/* translators: 1: number of copies, 2: size such as 12 MB */
					_n( '%1$s stored copy, %2$s', '%1$s stored copies, %2$s', $stats['files'], 'cybergate-security' ),
					number_format_i18n( $stats['files'] ),
					size_format( $stats['bytes'], 1 )
				)
				: __( 'No stored copies', 'cybergate-security' );
			$copies_html = '<div class="wpcs-inline-status">' . $this->badge( $copies, $stats['files'] ? 'info' : 'muted' ) . '</div>';
			if ( method_exists( $snapshots, 'usage' ) ) {
				$usage = $snapshots->usage();
				$line  = sprintf(
					/* translators: 1: percent used, 2: copy limit, 3: size limit */
					__( '%1$s%% of the limits used (%2$s copies, %3$s).', 'cybergate-security' ),
					number_format_i18n( $usage['percent'], 0 ),
					number_format_i18n( $usage['max_files'] ),
					size_format( $usage['max_bytes'] )
				);
				if ( $usage['full'] ) {
					$line .= ' ' . __( 'The store is full: new copies are skipped until the oldest are deleted after the next scan.', 'cybergate-security' );
				}
				if ( $usage['failures'] ) {
					/* translators: %s: number of copies */
					$line .= ' ' . sprintf( __( 'Copies that could not be written: %s (check free disk space and the data folder permissions).', 'cybergate-security' ), number_format_i18n( $usage['failures'] ) );
				}
				$copies_html .= '<p class="description">' . esc_html( $line ) . '</p>';
			}
			if ( $stats['files'] ) {
				$copies_html .= '<p class="wpcs-inline-actions"><a class="button wpcs-btn-danger" href="' . esc_url( $this->action_url( 'snapshots_clear' ) ) . '" data-wpcs-confirm="' . esc_attr__( 'Delete every stored file copy? Reports can then no longer show what changed in files found so far. While copies are switched on, the next scan copies the trusted files again.', 'cybergate-security' ) . '"><span class="dashicons dashicons-trash" aria-hidden="true"></span>' . esc_html__( 'Delete stored copies', 'cybergate-security' ) . '</a></p>';
			}
			$this->field(
				__( 'Copies of changed files', 'cybergate-security' ),
				$copies_html,
				__( 'Used to show what changed in a file. Copies nobody needs any more are deleted every day.', 'cybergate-security' )
			);
		}
		$html  = self::toggle_row( 'delete_data_on_uninstall', ! empty( $s['delete_data_on_uninstall'] ), __( 'Delete all plugin data when the plugin is deleted', 'cybergate-security' ) );
		$html .= '<div class="wpcs-notice wpcs-notice--warn wpcs-notice--compact"><span class="dashicons dashicons-warning" aria-hidden="true"></span><p>' . esc_html__( 'This removes the allowlist, the reports, the activity log and every held file. Files you approved would be held again after a reinstall. Deactivating the plugin never deletes data.', 'cybergate-security' ) . '</p></div>';
		$this->field( __( 'On uninstall', 'cybergate-security' ), $html );
		$this->field(
			__( 'Setup wizard', 'cybergate-security' ),
			'<a class="button" href="' . esc_url( Sysadmin_Tools::wizard_url() ) . '"><span class="dashicons dashicons-controls-repeat" aria-hidden="true"></span>' . esc_html__( 'Run the setup wizard again', 'cybergate-security' ) . '</a>'
		);
		$this->card_close();
	}

	/**
	 * Import and export (separate forms, outside the settings form).
	 */
	private function section_transfer() {
		$this->card_open( 'wpcs-transfer', 'database-export', __( 'Import and export settings', 'cybergate-security' ), __( 'Copy your settings to another site. The allowlist, reports and held files are not included.', 'cybergate-security' ) );
		?>
		<div class="wpcs-grid wpcs-grid--2 wpcs-transfer">
			<div>
				<h3 class="wpcs-subhead"><?php esc_html_e( 'Export', 'cybergate-security' ); ?></h3>
				<p class="wpcs-muted"><?php esc_html_e( 'Downloads every setting as a JSON file. It includes the webhook URL, so store it safely.', 'cybergate-security' ); ?></p>
				<a class="button" href="<?php echo esc_url( $this->action_url( 'export', array( 'type' => 'settings' ) ) ); ?>"><span class="dashicons dashicons-download" aria-hidden="true"></span><?php esc_html_e( 'Download settings', 'cybergate-security' ); ?></a>
			</div>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" enctype="multipart/form-data" class="wpcs-import">
				<input type="hidden" name="action" value="wpcybersec_import">
				<?php wp_nonce_field( 'wpcybersec_import' ); ?>
				<h3 class="wpcs-subhead"><?php esc_html_e( 'Import', 'cybergate-security' ); ?></h3>
				<p><input type="file" name="wpcs_import_file" accept=".json,application/json" aria-label="<?php esc_attr_e( 'Settings file', 'cybergate-security' ); ?>"></p>
				<p class="wpcs-muted"><?php esc_html_e( 'Or paste the file content (use this when the early guard holds the upload):', 'cybergate-security' ); ?></p>
				<textarea name="wpcs_import_json" rows="4" class="wpcs-mono wpcs-import__json" spellcheck="false" aria-label="<?php esc_attr_e( 'Settings JSON', 'cybergate-security' ); ?>"></textarea>
				<p><button type="submit" class="button" data-wpcs-confirm="<?php esc_attr_e( 'Replace the current settings with the imported ones?', 'cybergate-security' ); ?>"><span class="dashicons dashicons-upload" aria-hidden="true"></span><?php esc_html_e( 'Import settings', 'cybergate-security' ); ?></button></p>
			</form>
		</div>
		<?php
		$this->card_close();
	}
}

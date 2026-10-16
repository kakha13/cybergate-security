/**
 * WP Cyber Security - setup wizard and settings page.
 *
 * Uses window.WPCyberSec from core.js. Behaviour:
 *   - protection level cards sync the related fields to the preset values
 *   - "Custom" hint when the fields differ from the selected preset
 *   - wizard baseline scan runner with progress and result
 *   - test email button (AJAX, falls back to the form submit without JS)
 *   - freeze lock Unlock / Lock buttons
 *   - custom scan folder field toggle
 *   - unsaved changes warning on the settings form
 */
(function () {
	'use strict';

	var data = window.wpcybersecSetup || {};
	var i18n = data.i18n || {};
	var presets = data.presets || {};
	var levels = data.levels || {};

	/** Preset keys that do not decide the level (must match Sysadmin_Tools::LEVEL_IGNORE). */
	var LEVEL_IGNORE = ['notify_mode'];

	function api() {
		return window.WPCyberSec || null;
	}

	function fmt(text) {
		var S = api();
		var args = Array.prototype.slice.call(arguments);
		if (S && S.sprintf) {
			return S.sprintf.apply(null, args);
		}
		var rest = args.slice(1);
		var i = 0;
		return String(text).replace(/%(\d+)\$s|%s/g, function (m, n) {
			var v = n ? rest[parseInt(n, 10) - 1] : rest[i++];
			return v === undefined ? '' : String(v);
		});
	}

	function toast(message, isError) {
		var S = api();
		if (S && S.toast) {
			S.toast(message, isError);
		} else if (message) {
			window.alert(message);
		}
	}

	function each(list, fn) {
		Array.prototype.forEach.call(list || [], fn);
	}

	/* ------------------------------------------------------------------ */
	/* Protection level presets                                            */
	/* ------------------------------------------------------------------ */

	/**
	 * Wizard toggles and how they derive from a preset.
	 */
	var WIZARD_SYNC = {
		hold_admin_uploads: function (p) {
			return (p.upload_bypass_roles || []).indexOf('administrator') === -1;
		},
		hold_installs: function (p) {
			return p.install_mode === 'hold';
		},
		quarantine_php: function (p) {
			return p.file_mode === 'quarantine_exec';
		}
	};

	function selectedLevel(form) {
		var checked = form.querySelector('input[data-wpcs-level]:checked');
		return checked ? checked.value : '';
	}

	/**
	 * Current value of a named field, with PHP "last value wins" semantics
	 * (hidden "0" followed by a checkbox).
	 */
	function fieldValue(form, key) {
		var multi = form.querySelectorAll('input[name="' + key + '[]"]');
		if (multi.length) {
			var values = [];
			each(multi, function (el) {
				if (el.checked) {
					values.push(el.value);
				}
			});
			return values;
		}
		var els = form.querySelectorAll('[name="' + key + '"]');
		if (!els.length) {
			return undefined;
		}
		var value;
		each(els, function (el) {
			if (el.type === 'radio' || el.type === 'checkbox') {
				if (el.checked) {
					value = el.value;
				}
			} else {
				value = el.value;
			}
		});
		return value;
	}

	function sameValue(expected, actual) {
		if (actual === undefined) {
			return true;
		}
		if (Array.isArray(expected)) {
			var a = (actual || []).slice().sort();
			var b = expected.slice().sort();
			return a.length === b.length && a.every(function (v, i) {
				return v === b[i];
			});
		}
		if (typeof expected === 'boolean') {
			return (actual === '1') === expected;
		}
		return String(actual) === String(expected);
	}

	function applyPreset(form, preset) {
		Object.keys(preset).forEach(function (key) {
			var expected = preset[key];
			var multi = form.querySelectorAll('input[name="' + key + '[]"]');
			if (multi.length) {
				each(multi, function (el) {
					el.checked = Array.isArray(expected) && expected.indexOf(el.value) !== -1;
				});
				return;
			}
			each(form.querySelectorAll('[name="' + key + '"]'), function (el) {
				if (el.type === 'radio') {
					el.checked = el.value === String(expected);
				} else if (el.type === 'checkbox') {
					el.checked = typeof expected === 'boolean' ? expected : el.value === String(expected);
				} else if (el.tagName === 'SELECT') {
					el.value = String(expected);
				}
			});
		});
	}

	function differsFromPreset(form, preset, isWizard) {
		if (isWizard) {
			return Object.keys(WIZARD_SYNC).some(function (key) {
				var el = form.querySelector('[data-wpcs-sync="' + key + '"]');
				return el && el.checked !== WIZARD_SYNC[key](preset);
			});
		}
		return Object.keys(preset).some(function (key) {
			if (LEVEL_IGNORE.indexOf(key) !== -1) {
				return false;
			}
			return !sameValue(preset[key], fieldValue(form, key));
		});
	}

	function updateHint(form, isWizard) {
		var hint = form.querySelector('[data-wpcs-custom-hint]');
		if (!hint) {
			return;
		}
		var level = selectedLevel(form);
		var preset = presets[level];
		var differs = preset ? differsFromPreset(form, preset, isWizard) : false;
		hint.textContent = differs ? fmt(i18n.customHint || '%s', levels[level] || level) : '';
		hint.classList.toggle('wpcs-hidden', !differs);
	}

	function bindLevels() {
		each(document.querySelectorAll('form'), function (form) {
			if (!form.querySelector('input[data-wpcs-level]')) {
				return;
			}
			var isWizard = form.id === 'wpcs-wizard-form';

			form.addEventListener('change', function (e) {
				var target = e.target;
				if (target.matches('input[data-wpcs-level]')) {
					var preset = presets[target.value];
					if (!preset) {
						return;
					}
					if (isWizard) {
						Object.keys(WIZARD_SYNC).forEach(function (key) {
							var el = form.querySelector('[data-wpcs-sync="' + key + '"]');
							if (el) {
								el.checked = WIZARD_SYNC[key](preset);
							}
						});
					} else {
						applyPreset(form, preset);
						var synced = form.querySelector('[data-wpcs-level-synced]');
						if (synced) {
							synced.value = '1';
						}
					}
					updateHint(form, isWizard);
					return;
				}
				updateHint(form, isWizard);
			});

			// The page may load with fields that already differ from the stored level.
			var synced = form.querySelector('[data-wpcs-level-synced]');
			if (synced) {
				synced.value = '1';
			}
			updateHint(form, isWizard);
		});
	}

	/* ------------------------------------------------------------------ */
	/* Baseline scan (wizard)                                              */
	/* ------------------------------------------------------------------ */

	function notice(type, text, link) {
		var box = document.createElement('div');
		box.className = 'wpcs-notice' + (type ? ' wpcs-notice--' + type : '');
		var icon = document.createElement('span');
		var icons = { ok: 'yes-alt', warn: 'warning', bad: 'dismiss', '': 'info' };
		icon.className = 'dashicons dashicons-' + (icons[type] || 'info');
		icon.setAttribute('aria-hidden', 'true');
		var p = document.createElement('p');
		p.textContent = text;
		if (link) {
			p.appendChild(document.createTextNode(' '));
			var a = document.createElement('a');
			a.href = link.href;
			a.textContent = link.text;
			p.appendChild(a);
		}
		box.appendChild(icon);
		box.appendChild(p);
		return box;
	}

	function bindBaseline() {
		var box = document.querySelector('[data-wpcs-baseline-box]');
		var S = api();
		if (!box || !S) {
			return;
		}
		var button = box.querySelector('[data-wpcs-baseline]');
		var progress = box.querySelector('[data-wpcs-baseline-progress]');
		var result = box.querySelector('[data-wpcs-baseline-result]');
		var hint = box.querySelector('[data-wpcs-baseline-hint]');
		var form = box.closest('form');
		var next = form ? form.querySelector('[data-wpcs-continue]') : null;
		var running = false;

		if (box.getAttribute('data-has-baseline') !== '1' && next) {
			next.disabled = true;
		}

		function show(el) {
			result.innerHTML = '';
			result.appendChild(el);
			result.classList.remove('wpcs-hidden');
		}

		function onProgress(status) {
			S.renderProgress(progress, status);
			if (status && status.mode && status.mode !== 'baseline' && S.scan.isRunning(status)) {
				show(notice('', i18n.waitOther || ''));
			} else if (status && status.mode === 'baseline' && !result.classList.contains('wpcs-hidden') && S.scan.isRunning(status)) {
				result.classList.add('wpcs-hidden');
			}
		}

		function begin() {
			running = true;
			button.disabled = true;
			box.classList.add('is-running');
			result.classList.add('wpcs-hidden');
			progress.classList.remove('wpcs-hidden');
		}

		function end(status) {
			running = false;
			button.disabled = false;
			box.classList.remove('is-running');
			status = status || {};
			if (status.state === 'done') {
				S.renderProgress(progress, status);
				var files = parseInt(status.files_total, 10) || parseInt(status.files_done, 10) || 0;
				var threats = parseInt(status.threats, 10) || 0;
				var wrap = document.createElement('div');
				wrap.appendChild(notice('ok', fmt(i18n.fingerprinted || '%s', S.number(files)) + ' ' + (threats ? '' : i18n.noThreats || '')));
				if (threats) {
					wrap.appendChild(notice('bad', fmt(i18n.threatsFound || '%s', S.number(threats)), { href: data.threatsUrl, text: i18n.threatsLink || '' }));
				}
				show(wrap);
				box.setAttribute('data-has-baseline', '1');
				if (next) {
					next.disabled = false;
				}
				if (hint) {
					hint.hidden = true;
				}
			} else if (status.state === 'cancelled') {
				show(notice('warn', i18n.scanCancelled || ''));
			} else if (status.state === 'failed') {
				show(notice('bad', fmt(i18n.scanFailed || '%s', status.message || '')));
			}
		}

		function fail(err) {
			running = false;
			button.disabled = false;
			box.classList.remove('is-running');
			show(notice('bad', fmt(i18n.scanFailed || '%s', err && err.message ? err.message : '')));
		}

		function runBaseline(attempt) {
			// quiet: onProgress already shows its own "another scan is running" notice.
			return S.scan.run({ mode: 'baseline', malware: true, trigger: 'wizard', quiet: true }, onProgress).then(function (status) {
				// Another scan was running: it is finished now, so start the baseline.
				if (status && status.mode && status.mode !== 'baseline' && attempt < 2) {
					return runBaseline(attempt + 1);
				}
				return status;
			});
		}

		button.addEventListener('click', function (e) {
			e.preventDefault();
			if (running) {
				return;
			}
			begin();
			S.renderProgress(progress, { state: 'enumerating', files_total: 0, message: i18n.starting || '' });
			runBaseline(0).then(end).catch(fail);
		});

		window.addEventListener('beforeunload', function (e) {
			if (running) {
				e.preventDefault();
				e.returnValue = i18n.leaving || '';
				return i18n.leaving || '';
			}
		});

		// Re-attach to a baseline scan that is still running (page reload).
		S.ajax('scan_status')
			.then(function (status) {
				if (!S.scan.isRunning(status) || status.mode !== 'baseline') {
					return;
				}
				begin();
				onProgress(status);
				return S.scan.attach(onProgress).then(end);
			})
			.catch(function () {});
	}

	/* ------------------------------------------------------------------ */
	/* Test email                                                          */
	/* ------------------------------------------------------------------ */

	function bindTestEmail() {
		document.addEventListener('click', function (e) {
			var button = e.target.closest('[data-wpcs-test-email]');
			var S = api();
			if (!button || !S) {
				return;
			}
			e.preventDefault();
			if (button.disabled) {
				return;
			}
			var source = document.querySelector(button.getAttribute('data-source') || '');
			var original = button.innerHTML;
			button.disabled = true;
			button.textContent = i18n.sending || '...';
			S.ajax('test_email', { emails: source ? source.value : '' })
				.then(function (res) {
					toast(res && res.message ? res.message : '');
				})
				.catch(function (err) {
					toast(err.message, true);
				})
				.then(function () {
					button.disabled = false;
					button.innerHTML = original;
				});
		});
	}

	/* ------------------------------------------------------------------ */
	/* Freeze lock                                                         */
	/* ------------------------------------------------------------------ */

	function setLockState(until) {
		each(document.querySelectorAll('[data-wpcs-lock-state]'), function (el) {
			var unlocked = until && until * 1000 > Date.now();
			el.className = 'wpcs-badge wpcs-badge--' + (unlocked ? 'medium' : 'ok');
			el.textContent = unlocked
				? fmt(i18n.unlockedUntil || '%s', new Date(until * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }))
				: i18n.locked || '';
		});
	}

	function bindLock() {
		document.addEventListener('click', function (e) {
			var S = api();
			var unlock = e.target.closest('[data-wpcs-unlock]');
			var lock = e.target.closest('[data-wpcs-lock]');
			if ((!unlock && !lock) || !S) {
				return;
			}
			e.preventDefault();
			var button = unlock || lock;
			button.disabled = true;
			var request;
			if (unlock) {
				var input = document.querySelector(unlock.getAttribute('data-minutes-input') || '');
				request = S.ajax('unlock', { minutes: input ? input.value : '' });
			} else {
				request = S.ajax('lock');
			}
			request
				.then(function (res) {
					setLockState(res && res.unlocked_until ? parseInt(res.unlocked_until, 10) : 0);
					toast(unlock ? i18n.unlockedToast : i18n.lockedToast);
				})
				.catch(function (err) {
					toast(err.message, true);
				})
				.then(function () {
					button.disabled = false;
				});
		});
	}

	/* ------------------------------------------------------------------ */
	/* Misc                                                                */
	/* ------------------------------------------------------------------ */

	function bindScanRoot() {
		document.addEventListener('change', function (e) {
			if (!e.target.matches('input[name="scan_root"]')) {
				return;
			}
			var custom = document.querySelector('[data-wpcs-scan-root-custom]');
			if (!custom) {
				return;
			}
			var isCustom = e.target.value === 'custom' && e.target.checked;
			custom.classList.toggle('wpcs-hidden', !isCustom);
			if (isCustom) {
				var input = custom.querySelector('input');
				if (input) {
					input.focus();
				}
			}
		});
	}

	function bindDirtyForms() {
		var dirty = false;
		var forms = document.querySelectorAll('form.wpcs-settings-form');
		if (!forms.length) {
			return;
		}
		each(forms, function (form) {
			form.addEventListener('change', function () {
				dirty = true;
			});
			form.addEventListener('input', function () {
				dirty = true;
			});
			form.addEventListener('submit', function () {
				dirty = false;
			});
		});
		window.addEventListener('beforeunload', function (e) {
			if (dirty) {
				e.preventDefault();
				e.returnValue = '';
				return '';
			}
		});
	}

	function bindBusyForms() {
		document.addEventListener('submit', function (e) {
			var form = e.target;
			if (form.id === 'wpcs-wizard-form' || form.classList.contains('wpcs-settings-form')) {
				form.classList.add('is-submitting');
				form.setAttribute('aria-busy', 'true');
			}
		});
	}

	function init() {
		bindLevels();
		bindBaseline();
		bindTestEmail();
		bindLock();
		bindScanRoot();
		bindDirtyForms();
		bindBusyForms();
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', init);
	} else {
		init();
	}
})();

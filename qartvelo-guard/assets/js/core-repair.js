/**
 * Qartvelo Guard - "Reinstall clean core" card (Dashboard, Reports).
 *
 * Builds on window.WPCyberSec (core.js):
 *   [data-wpcs-core-start]    AJAX core_reinstall do=start, then do=tick until the package is
 *                             verified (step "ready"), confirmDialog() with the server's summary,
 *                             do=swap (the short request that replaces core), then the quick scan
 *                             the server started is followed and the page reloads.
 *   [data-wpcs-core-resume]   a job that is already running is continued on page load.
 *   [data-wpcs-core-cancel]   do=cancel (only before the swap).
 *   [data-wpcs-core-dismiss]  do=dismiss (hides a finished or failed job's message).
 *   [data-wpcs-core-restore]  AJAX core_restore id=<backup>, after a confirmation.
 *   [data-wpcs-core-maint]    AJAX core_maintenance (writes .maintenance for the steps by hand).
 */
(function () {
	'use strict';

	var api = window.WPCyberSec;
	if (!api) {
		return;
	}
	var i18n = (window.wpcybersecCore && window.wpcybersecCore.i18n) || {};
	var coreI18n = (window.wpcybersecData && window.wpcybersecData.i18n) || {};

	function t(key, fallback) {
		return i18n[key] || fallback;
	}

	function card(el) {
		return (el && el.closest('[data-wpcs-core]')) || document.querySelector('[data-wpcs-core]');
	}

	function setProgress(root, state) {
		var box = root && root.querySelector('[data-wpcs-core-progress]');
		if (!box) {
			return;
		}
		box.classList.remove('wpcs-hidden');
		var bar = box.querySelector('.wpcs-progress__bar');
		var text = box.querySelector('.wpcs-progress__text');
		if (bar) {
			bar.style.width = Math.max(0, Math.min(100, parseInt(state.percent, 10) || 0)) + '%';
		}
		if (text) {
			text.textContent = state.label || '';
		}
	}

	function fail(root, message, btn) {
		api.toast(message || coreI18n.error || 'Something went wrong.', true);
		if (btn) {
			btn.disabled = false;
		}
		window.setTimeout(function () {
			window.location.reload();
		}, 2500);
	}

	function call(params) {
		return api.ajax('core_reinstall', params);
	}

	/* Ticks until the package is verified, then asks, then swaps. */
	function drive(root, state, btn) {
		setProgress(root, state);
		if (state.step === 'download' || state.step === 'extract' || state.step === 'verify' || state.step === 'finish') {
			return call({ do: 'tick' }).then(function (next) {
				return drive(root, next, btn);
			});
		}
		if (state.step === 'ready') {
			var c = state.confirm || {};
			var text = c.text || '';
			if (i18n.network) {
				text += ' ' + i18n.network;
			}
			return api.confirmDialog({ title: c.title, verdict: c.verdict, text: text, confirm: c.confirm, tone: 'danger' }).then(function (ok) {
				if (!ok) {
					return call({ do: 'cancel' }).then(function () {
						api.toast(t('cancelled', 'Cancelled. Nothing was changed.'));
						window.setTimeout(function () {
							window.location.reload();
						}, 1200);
					});
				}
				setProgress(root, { percent: 90, label: t('swapping', 'Replacing core (a few seconds)') });
				return call({ do: 'swap' }).then(function (next) {
					return drive(root, next, btn);
				});
			});
		}
		if (state.step === 'done') {
			setProgress(root, state);
			api.toast(state.message || coreI18n.done || 'Done');
			if (state.scan && api.scan && typeof api.scan.attach === 'function' && [ 'enumerating', 'processing', 'finishing' ].indexOf(state.scan.state) !== -1) {
				var prog = root && root.querySelector('[data-wpcs-core-progress]');
				return api.scan.attach(function (status) {
					if (prog) {
						api.renderProgress(prog, status);
					}
				}).then(function () {
					window.location.reload();
				}, function () {
					window.location.reload();
				});
			}
			window.setTimeout(function () {
				window.location.reload();
			}, 1500);
			return null;
		}
		if (state.step === 'failed') {
			fail(root, state.message, btn);
			return null;
		}
		if (state.step === 'swap') {
			// Another request is swapping right now: look again in a moment.
			return new Promise(function (resolve) {
				window.setTimeout(resolve, 3000);
			}).then(function () {
				return call({ do: 'status' });
			}).then(function (next) {
				return drive(root, next, btn);
			});
		}
		window.location.reload();
		return null;
	}

	document.addEventListener('click', function (e) {
		var btn = e.target.closest('[data-wpcs-core-start]');
		if (btn) {
			e.preventDefault();
			var root = card(btn);
			btn.disabled = true;
			setProgress(root, { percent: 2, label: t('starting', 'Checking the server and downloading the official package') });
			call({ do: 'start' }).then(function (state) {
				return drive(root, state, btn);
			}).catch(function (err) {
				fail(root, err && err.message, btn);
			});
			return;
		}

		btn = e.target.closest('[data-wpcs-core-cancel]');
		if (btn) {
			e.preventDefault();
			btn.disabled = true;
			call({ do: 'cancel' }).then(function () {
				window.location.reload();
			}).catch(function (err) {
				fail(null, err && err.message, btn);
			});
			return;
		}

		btn = e.target.closest('[data-wpcs-core-dismiss]');
		if (btn) {
			e.preventDefault();
			btn.disabled = true;
			call({ do: 'dismiss' }).then(function () {
				var box = btn.closest('[data-wpcs-core-result]');
				if (box) {
					box.parentNode.removeChild(box);
				}
			}).catch(function (err) {
				fail(null, err && err.message, btn);
			});
			return;
		}

		btn = e.target.closest('[data-wpcs-core-restore]');
		if (btn) {
			e.preventDefault();
			api.confirmDialog({
				title: t('restoreTitle', 'Restore the previous WordPress core?'),
				text: t('restoreText', ''),
				confirm: t('restore', 'Restore the previous core'),
				tone: 'danger'
			}).then(function (ok) {
				if (!ok) {
					return;
				}
				btn.disabled = true;
				api.ajax('core_restore', { id: btn.getAttribute('data-id') }).then(function (res) {
					api.toast(res.message || coreI18n.done || 'Done');
					window.setTimeout(function () {
						window.location.reload();
					}, 1500);
				}).catch(function (err) {
					fail(null, err && err.message, btn);
				});
			});
			return;
		}

		btn = e.target.closest('[data-wpcs-core-maint]');
		if (btn) {
			e.preventDefault();
			api.confirmDialog({
				title: t('maintTitle', 'Turn on maintenance mode now?'),
				text: t('maintText', ''),
				confirm: t('maintOn', 'Turn on maintenance mode'),
				tone: 'danger'
			}).then(function (ok) {
				if (!ok) {
					return;
				}
				btn.disabled = true;
				api.ajax('core_maintenance', {}).then(function (res) {
					api.toast(res.message || '');
				}).catch(function (err) {
					api.toast((err && err.message) || coreI18n.error || 'Something went wrong.', true);
					btn.disabled = false;
				});
			});
		}
	});

	/* A job that was already running when the page loaded. */
	var resume = document.querySelector('[data-wpcs-core-resume]');
	if (resume) {
		call({ do: 'status' }).then(function (state) {
			return drive(resume, state, null);
		}).catch(function (err) {
			fail(resume, err && err.message, null);
		});
	}
})();

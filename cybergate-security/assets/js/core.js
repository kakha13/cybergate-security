/**
 * CyberGate Security - shared admin script.
 *
 * Exposes window.WPCyberSec:
 *   ajax(name, params)            POST to admin-ajax "wpcybersec_<name>", resolves with response.data
 *   toast(message, isError)       Small bottom-right message
 *   sprintf(fmt, a, b)            Replaces %s and %1$s style placeholders
 *   scan.start(opts)              opts: { mode: incremental|full|baseline, malware: bool, trigger }
 *   scan.run(opts, onProgress)    Starts (or attaches to a running scan) and ticks until finished.
 *                                 When a scan of another mode was already running, it toasts the
 *                                 server's notice (unless opts.quiet) and the final status gets
 *                                 otherScan: true and requested: <mode>.
 *   scan.attach(onProgress)       Keeps ticking a scan that is already running
 *   scan.cancel()
 *   renderProgress(el, status)    Fills a .wpcs-progress block
 *   itemAction(action, id)        Applies a decision, resolves with { item, available, counts, message }
 *   bulk(action, ids)             Bulk decision, resolves with { done, errors, counts }
 *
 * Declarative hooks (no extra JS needed):
 *   <button data-wpcs-scan data-mode="full" data-malware="1" data-target="#prog" data-reload="1">
 *   <div id="prog" class="wpcs-progress wpcs-hidden" data-wpcs-progress-auto> ...markup below... </div>
 *   <button data-wpcs-action="approve" data-id="12" [data-confirm="..."]>   inside a <tr data-item-id="12">
 *   <span data-wpcs-count="pending|threats|quarantined">3</span>
 *   <button class="wpcs-copy" data-wpcs-copy>                              inside .wpcs-code (copies its <pre>)
 *   <a data-wpcs-confirm="Message">                                        asks before following a link / submitting
 *
 * Progress markup:
 *   <div class="wpcs-progress">
 *     <div class="wpcs-progress__track"><div class="wpcs-progress__bar"></div></div>
 *     <div class="wpcs-progress__label"><span class="wpcs-progress__text"></span><span class="wpcs-progress__current"></span></div>
 *   </div>
 */
(function () {
	'use strict';

	var data = window.wpcybersecData || {};
	var i18n = data.i18n || {};
	var RUNNING = [ 'enumerating', 'processing', 'finishing' ];

	function sprintf(fmt) {
		var args = Array.prototype.slice.call(arguments, 1);
		var i = 0;
		return String(fmt).replace(/%(\d+)\$s|%s/g, function (m, n) {
			var v = n ? args[parseInt(n, 10) - 1] : args[i++];
			return v === undefined ? '' : String(v);
		});
	}

	function number(n) {
		n = parseInt(n, 10) || 0;
		try {
			return n.toLocaleString();
		} catch (e) {
			return String(n);
		}
	}

	function ajax(name, params) {
		var body = new FormData();
		body.append('action', 'wpcybersec_' + name);
		body.append('_ajax_nonce', data.nonce || '');
		Object.keys(params || {}).forEach(function (key) {
			var value = params[key];
			if (Array.isArray(value)) {
				value.forEach(function (v) {
					body.append(key + '[]', v);
				});
			} else if (typeof value === 'boolean') {
				body.append(key, value ? '1' : '0');
			} else if (value !== undefined && value !== null) {
				body.append(key, value);
			}
		});
		return fetch(data.ajaxUrl, { method: 'POST', credentials: 'same-origin', body: body })
			.then(function (r) {
				return r.json().catch(function () {
					throw new Error(i18n.error || 'Request failed');
				});
			})
			.then(function (res) {
				if (!res || !res.success) {
					throw new Error((res && res.data && res.data.message) || i18n.error || 'Request failed');
				}
				return res.data;
			});
	}

	var toastTimer = null;
	function toast(message, isError) {
		var el = document.querySelector('.wpcs-toast');
		if (!el) {
			el = document.createElement('div');
			el.className = 'wpcs-toast';
			el.setAttribute('role', 'status');
			el.setAttribute('aria-live', 'polite');
			document.body.appendChild(el);
		}
		el.textContent = message;
		el.classList.toggle('wpcs-toast--error', !!isError);
		el.classList.add('is-visible');
		clearTimeout(toastTimer);
		toastTimer = setTimeout(function () {
			el.classList.remove('is-visible');
		}, isError ? 6000 : 3000);
	}

	/* ---------------- Scans ---------------- */

	function isRunning(status) {
		return status && RUNNING.indexOf(status.state) !== -1;
	}

	function loop(onProgress) {
		return ajax('scan_tick').then(function (status) {
			if (onProgress) {
				onProgress(status);
			}
			if (isRunning(status)) {
				return loop(onProgress);
			}
			return status;
		});
	}

	var scan = {
		start: function (opts) {
			opts = opts || {};
			return ajax('scan_start', {
				mode: opts.mode || 'incremental',
				malware: opts.malware === undefined ? true : !!opts.malware,
				trigger: opts.trigger || 'manual'
			});
		},
		run: function (opts, onProgress) {
			opts = opts || {};
			var requested = opts.mode || 'incremental';
			return scan.start(opts).then(function (status) {
				// The server returned a scan that was already running instead of starting ours.
				var other = !!(status && status.attached && status.mode && status.mode !== requested);
				if (other && !opts.quiet && status.notice) {
					toast(status.notice);
				}
				if (onProgress) {
					onProgress(status);
				}
				var done = isRunning(status) ? loop(onProgress) : Promise.resolve(status);
				return done.then(function (final) {
					if (other && final) {
						final.otherScan = true;
						final.requested = requested;
						final.notice = status.notice || '';
					}
					return final;
				});
			});
		},
		attach: function (onProgress) {
			return ajax('scan_status').then(function (status) {
				if (onProgress) {
					onProgress(status);
				}
				return isRunning(status) ? loop(onProgress) : status;
			});
		},
		cancel: function () {
			return ajax('scan_cancel');
		},
		isRunning: isRunning
	};

	function renderProgress(el, status) {
		if (!el || !status) {
			return;
		}
		el.classList.remove('wpcs-hidden');
		var bar = el.querySelector('.wpcs-progress__bar');
		var text = el.querySelector('.wpcs-progress__text');
		var current = el.querySelector('.wpcs-progress__current');
		var state = status.state || 'idle';
		var indeterminate = state === 'enumerating';
		el.classList.toggle('is-indeterminate', indeterminate);

		var pct = Math.max(0, Math.min(100, parseFloat(status.percent) || 0));
		if (state === 'done') {
			pct = 100;
		}
		if (bar) {
			bar.style.width = indeterminate ? '' : pct + '%';
		}
		var label;
		if (state === 'enumerating') {
			label = (i18n.enumerating || 'Listing files') + ' - ' + sprintf(i18n.filesFound || '%s files found so far', number(status.files_total));
		} else if (state === 'processing') {
			label = (i18n.processing || 'Checking files') + ' - ' + sprintf(i18n.filesChecked || '%1$s of %2$s files checked', number(status.files_done), number(status.files_total));
		} else if (state === 'finishing') {
			label = i18n.finishing || 'Finishing';
		} else if (state === 'done') {
			label = (i18n.done || 'Scan complete') + (status.message ? ' - ' + status.message : '');
		} else if (state === 'failed') {
			label = (i18n.failed || 'Scan failed') + (status.message ? ': ' + status.message : '');
		} else if (state === 'cancelled') {
			label = i18n.cancelled || 'Scan cancelled';
		} else {
			label = status.message || '';
		}
		if (text) {
			text.textContent = label;
		}
		if (current) {
			current.textContent = isRunning(status) ? status.current || '' : '';
		}
	}

	function setScanButtons(disabled) {
		document.querySelectorAll('[data-wpcs-scan]').forEach(function (b) {
			b.disabled = disabled;
		});
	}

	function bindScanButtons() {
		document.addEventListener('click', function (e) {
			var btn = e.target.closest('[data-wpcs-scan]');
			if (!btn) {
				return;
			}
			e.preventDefault();
			if (btn.getAttribute('data-confirm') && !window.confirm(btn.getAttribute('data-confirm'))) {
				return;
			}
			var target = document.querySelector(btn.getAttribute('data-target') || '[data-wpcs-progress-auto]');
			var opts = {
				mode: btn.getAttribute('data-mode') || 'incremental',
				malware: btn.getAttribute('data-malware') !== '0',
				trigger: btn.getAttribute('data-trigger') || 'manual'
			};
			var onProgress = function (status) {
				renderProgress(target, status);
				document.dispatchEvent(new CustomEvent('wpcybersec:scan-progress', { detail: status }));
			};
			// Another scan was running and has finished: start the one that was asked for, once.
			var runRequested = function (attempt) {
				return scan.run(opts, onProgress).then(function (status) {
					if (status && status.otherScan && status.state === 'done' && attempt < 1) {
						return runRequested(attempt + 1);
					}
					if (status && status.otherScan && status.notice) {
						toast(status.notice, true);
					}
					return status;
				});
			};
			setScanButtons(true);
			runRequested(0)
				.then(function (status) {
					document.dispatchEvent(new CustomEvent('wpcybersec:scan-finished', { detail: status }));
					if (btn.getAttribute('data-reload') === '1') {
						setTimeout(function () {
							window.location.reload();
						}, 900);
					} else {
						setScanButtons(false);
					}
				})
				.catch(function (err) {
					toast(err.message, true);
					setScanButtons(false);
				});
		});
	}

	function autoAttach() {
		var target = document.querySelector('[data-wpcs-progress-auto]');
		if (!target) {
			return;
		}
		ajax('scan_status')
			.then(function (status) {
				if (!isRunning(status)) {
					return;
				}
				setScanButtons(true);
				renderProgress(target, status);
				return loop(function (s) {
					renderProgress(target, s);
				}).then(function (s) {
					document.dispatchEvent(new CustomEvent('wpcybersec:scan-finished', { detail: s }));
					setScanButtons(false);
				});
			})
			.catch(function () {});
	}

	/* ---------------- Item decisions ---------------- */

	function updateCounts(counts) {
		if (!counts) {
			return;
		}
		Object.keys(counts).forEach(function (key) {
			document.querySelectorAll('[data-wpcs-count="' + key + '"]').forEach(function (el) {
				el.textContent = number(counts[key]);
				el.classList.toggle('wpcs-count--zero', !counts[key]);
			});
		});
	}

	function itemAction(action, id) {
		return ajax('item_action', { do: action, id: id }).then(function (res) {
			updateCounts(res.counts);
			return res;
		});
	}

	function bulk(action, ids) {
		return ajax('bulk_action', { do: action, ids: ids }).then(function (res) {
			updateCounts(res.counts);
			return res;
		});
	}

	var STATUS_LABEL = {
		approved: { text: i18n.approved || 'Approved', cls: 'ok' },
		denied: { text: i18n.denied || 'Denied', cls: 'muted' },
		ignored: { text: i18n.ignored || 'Marked safe', cls: 'ok' },
		quarantined: { text: i18n.quarantined || 'Quarantined', cls: 'medium' },
		restored: { text: i18n.restored || 'Restored', cls: 'info' },
		deleted: { text: i18n.deleted || 'Deleted', cls: 'muted' }
	};

	function bindItemActions() {
		document.addEventListener('click', function (e) {
			var btn = e.target.closest('[data-wpcs-action]');
			if (!btn) {
				return;
			}
			e.preventDefault();
			var action = btn.getAttribute('data-wpcs-action');
			var id = btn.getAttribute('data-id');
			var confirmMsg = btn.getAttribute('data-confirm') || (action === 'delete' ? i18n.confirmDelete : '');
			if (confirmMsg && !window.confirm(confirmMsg)) {
				return;
			}
			var row = btn.closest('[data-item-id]');
			if (row) {
				row.classList.add('is-busy');
			}
			itemAction(action, id)
				.then(function (res) {
					var status = res.item ? res.item.status : action;
					var label = STATUS_LABEL[status] || { text: status, cls: 'muted' };
					if (row) {
						row.classList.remove('is-busy');
						row.classList.add('is-done');
						var statusCell = row.querySelector('[data-wpcs-status]');
						if (statusCell) {
							statusCell.innerHTML = '';
							var badge = document.createElement('span');
							badge.className = 'wpcs-badge wpcs-badge--' + label.cls;
							badge.textContent = label.text;
							statusCell.appendChild(badge);
						}
						var actions = row.querySelector('.wpcs-actions');
						if (actions) {
							actions.querySelectorAll('[data-wpcs-action]').forEach(function (b) {
								var allowed = (res.available || []).indexOf(b.getAttribute('data-wpcs-action')) !== -1;
								b.classList.toggle('wpcs-hidden', !allowed);
							});
						}
					}
					// Extra instructions from the server (for example "upload the ZIP again") win over the generic text.
					toast(res.message ? res.message : label.text + ': ' + (res.item ? res.item.path : '#' + id));
					document.dispatchEvent(new CustomEvent('wpcybersec:item-updated', { detail: res }));
				})
				.catch(function (err) {
					if (row) {
						row.classList.remove('is-busy');
					}
					toast(err.message, true);
				});
		});
	}

	/* ---------------- Misc ---------------- */

	function copyText(text) {
		if (navigator.clipboard && window.isSecureContext) {
			return navigator.clipboard.writeText(text);
		}
		var ta = document.createElement('textarea');
		ta.value = text;
		ta.style.position = 'fixed';
		ta.style.opacity = '0';
		document.body.appendChild(ta);
		ta.select();
		try {
			document.execCommand('copy');
		} finally {
			document.body.removeChild(ta);
		}
		return Promise.resolve();
	}

	function bindCopy() {
		document.addEventListener('click', function (e) {
			var btn = e.target.closest('[data-wpcs-copy]');
			if (!btn) {
				return;
			}
			e.preventDefault();
			var sel = btn.getAttribute('data-wpcs-copy');
			var src = sel ? document.querySelector(sel) : null;
			if (!src) {
				var box = btn.closest('.wpcs-code');
				src = box ? box.querySelector('pre') : null;
			}
			if (!src) {
				return;
			}
			copyText(src.value !== undefined && src.tagName === 'TEXTAREA' ? src.value : src.textContent).then(function () {
				var old = btn.textContent;
				btn.textContent = i18n.copied || 'Copied';
				setTimeout(function () {
					btn.textContent = old;
				}, 1500);
			});
		});
	}

	function bindConfirm() {
		document.addEventListener('click', function (e) {
			var el = e.target.closest('[data-wpcs-confirm]');
			if (el && !window.confirm(el.getAttribute('data-wpcs-confirm') || i18n.confirm || 'Are you sure?')) {
				e.preventDefault();
				e.stopImmediatePropagation();
			}
		}, true);
	}

	function bindOptionCards() {
		document.addEventListener('change', function (e) {
			if (!e.target.matches('.wpcs-option input[type="radio"]')) {
				return;
			}
			var name = e.target.name;
			document.querySelectorAll('.wpcs-option input[name="' + name + '"]').forEach(function (r) {
				r.closest('.wpcs-option').classList.toggle('is-selected', r.checked);
			});
		});
	}

	window.WPCyberSec = {
		ajax: ajax,
		toast: toast,
		sprintf: sprintf,
		number: number,
		scan: scan,
		renderProgress: renderProgress,
		itemAction: itemAction,
		bulk: bulk,
		updateCounts: updateCounts,
		copyText: copyText
	};

	function init() {
		bindConfirm();
		bindScanButtons();
		bindItemActions();
		bindCopy();
		bindOptionCards();
		autoAttach();
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', init);
	} else {
		init();
	}
})();

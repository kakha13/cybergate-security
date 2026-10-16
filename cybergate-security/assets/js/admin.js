/**
 * CyberGate Security - dashboard and reports behaviour.
 *
 * Builds on window.WPCyberSec (core.js), which already handles scan buttons,
 * single item decisions (data-wpcs-action), counts, copy and confirm links.
 * This file adds:
 *   - details rows toggle (.wpcs-details-toggle)
 *   - select all / shift-click range selection (.wpcs-cb-all, .wpcs-cb-item)
 *   - bulk decisions through WPCyberSec.bulk with row updates (#wpcs-bulk-form)
 *   - auto-submitting filter selects ([data-wpcs-autosubmit])
 *   - freeze lock unlock / lock buttons ([data-wpcs-freeze])
 *   - menu and admin bar count updates after decisions
 *   - dashboard refresh after a scan finishes ([data-wpcs-dashboard])
 *   - "+N -M lines" summary loaded when a details row opens ([data-wpcs-diff-summary])
 *   - changes view refresh after a decision ([data-wpcs-changes])
 */
(function () {
	'use strict';

	var api = window.WPCyberSec;
	if (!api) {
		return;
	}
	var i18n = (window.wpcybersecAdmin && window.wpcybersecAdmin.i18n) || {};
	var coreI18n = (window.wpcybersecData && window.wpcybersecData.i18n) || {};

	function t(key, fallback) {
		return i18n[key] || fallback;
	}

	/* Picks the "One" variant of a string for a count of 1. */
	function tn(key, count, fallback) {
		var text = count === 1 && i18n[key + 'One'] ? i18n[key + 'One'] : t(key, fallback);
		return api.sprintf(text, api.number(count));
	}

	function toArray(list) {
		return Array.prototype.slice.call(list || []);
	}

	/* ---------------- Details rows ---------------- */

	function setDetails(btn, open) {
		var row = document.getElementById(btn.getAttribute('aria-controls'));
		if (!row) {
			return;
		}
		if (open) {
			row.removeAttribute('hidden');
		} else {
			row.setAttribute('hidden', '');
		}
		btn.setAttribute('aria-expanded', open ? 'true' : 'false');
		var text = btn.querySelector('.wpcs-details-toggle__text');
		if (text) {
			text.textContent = open ? t('hideDetails', 'Hide details') : t('details', 'Details');
		}
		if (open) {
			loadDiffSummary(row);
		}
	}

	/* Fills "Changes: +N -M lines vs ..." once, when the details are first opened. */
	function loadDiffSummary(row) {
		var box = row.querySelector('[data-wpcs-diff-summary]');
		if (!box || box.getAttribute('data-loaded')) {
			return;
		}
		box.setAttribute('data-loaded', '1');
		var text = box.querySelector('.wpcs-diff-summary__text');
		if (!text) {
			return;
		}
		var before = text.textContent;
		text.textContent = t('comparing', 'Comparing...');
		api.ajax('diff_summary', { id: box.getAttribute('data-wpcs-diff-summary') })
			.then(function (res) {
				text.textContent = res && res.text ? res.text : before;
			})
			.catch(function () {
				text.textContent = before;
			});
	}

	function bindDetails() {
		document.addEventListener('click', function (e) {
			var btn = e.target.closest('.wpcs-details-toggle');
			if (!btn) {
				return;
			}
			e.preventDefault();
			setDetails(btn, btn.getAttribute('aria-expanded') !== 'true');
		});
	}

	/* ---------------- Selection ---------------- */

	function itemBoxes(scope) {
		return toArray((scope || document).querySelectorAll('.wpcs-cb-item')).filter(function (box) {
			return !box.disabled;
		});
	}

	function syncSelectAll(table) {
		if (!table) {
			return;
		}
		var all = table.querySelector('.wpcs-cb-all');
		if (!all) {
			return;
		}
		var boxes = itemBoxes(table);
		var checked = boxes.filter(function (b) {
			return b.checked;
		}).length;
		all.checked = boxes.length > 0 && checked === boxes.length;
		all.indeterminate = checked > 0 && checked < boxes.length;
		all.disabled = boxes.length === 0;
	}

	function bindSelection() {
		var last = null;

		document.addEventListener('click', function (e) {
			var box = e.target.closest('.wpcs-cb-item');
			if (!box) {
				return;
			}
			var table = box.closest('table');
			if (e.shiftKey && last && last !== box && table && table.contains(last)) {
				var boxes = itemBoxes(table);
				var a = boxes.indexOf(last);
				var b = boxes.indexOf(box);
				if (a !== -1 && b !== -1) {
					boxes.slice(Math.min(a, b), Math.max(a, b) + 1).forEach(function (x) {
						x.checked = box.checked;
					});
				}
			}
			last = box;
			syncSelectAll(table);
		});

		document.addEventListener('change', function (e) {
			if (!e.target.matches('.wpcs-cb-all')) {
				return;
			}
			var table = e.target.closest('table');
			itemBoxes(table).forEach(function (b) {
				b.checked = e.target.checked;
			});
			syncSelectAll(table);
		});
	}

	/* ---------------- Row updates ---------------- */

	var NEXT_STATUS = {
		approve: 'approved',
		deny: 'denied',
		ignore: 'ignored',
		quarantine: 'quarantined',
		restore: 'restored',
		'delete': 'deleted'
	};

	var STATUS_BADGE = {
		approved: 'ok',
		denied: 'muted',
		ignored: 'ok',
		quarantined: 'medium',
		restored: 'info',
		deleted: 'muted'
	};

	/* Mirrors Decisions::available() for statuses reached through a decision. */
	function availableAfter(status) {
		if (status === 'quarantined') {
			return [ 'approve', 'restore', 'delete' ];
		}
		if (status === 'restored') {
			return [ 'approve', 'quarantine' ];
		}
		return [];
	}

	/* Whether a downloadable held copy remains after a decision. */
	function heldAfter(action) {
		return action === 'quarantine';
	}

	function applyRowState(row, status, available, held) {
		row.classList.remove('is-busy');
		row.classList.add('is-done');
		row.setAttribute('data-held', held ? '1' : '0');

		var cell = row.querySelector('[data-wpcs-status]');
		if (cell && status) {
			cell.innerHTML = '';
			var badge = document.createElement('span');
			badge.className = 'wpcs-badge wpcs-badge--' + (STATUS_BADGE[status] || 'muted');
			badge.textContent = coreI18n[status] || status;
			cell.appendChild(badge);
		}

		toArray(row.querySelectorAll('.wpcs-actions [data-wpcs-action]')).forEach(function (b) {
			b.classList.toggle('wpcs-hidden', available.indexOf(b.getAttribute('data-wpcs-action')) === -1);
		});

		var download = row.querySelector('.wpcs-download');
		if (download) {
			download.classList.toggle('wpcs-hidden', !held);
		}

		var box = row.querySelector('.wpcs-cb-item');
		if (box) {
			box.checked = false;
			box.disabled = available.length === 0;
		}
	}

	/* ---------------- Counts in the admin menu and admin bar ---------------- */

	function updateMenuCounts(counts) {
		if (!counts) {
			return;
		}
		var total = (parseInt(counts.pending, 10) || 0) + (parseInt(counts.threats, 10) || 0);
		toArray(document.querySelectorAll('#adminmenu .wpcs-menu-count')).forEach(function (el) {
			el.className = el.className.replace(/\bcount-\d+\b/, 'count-' + total);
			var n = el.querySelector('.pending-count');
			if (n) {
				n.textContent = api.number(total);
			}
			var sr = el.querySelector('.screen-reader-text');
			if (sr) {
				sr.textContent = api.sprintf(t('menuCount', '%s items need your review'), api.number(total));
			}
			el.style.display = total ? '' : 'none';
		});
		toArray(document.querySelectorAll('#wp-admin-bar-wpcybersec .wpcs-ab-count')).forEach(function (el) {
			el.textContent = api.number(total);
		});
		var node = document.getElementById('wp-admin-bar-wpcybersec');
		if (node && !total) {
			node.style.display = 'none';
		}
	}

	function bindItemUpdates() {
		document.addEventListener('wpcybersec:item-updated', function (e) {
			var res = e.detail || {};
			updateMenuCounts(res.counts);
			var item = res.item;
			if (!item) {
				return;
			}
			var row = document.querySelector('[data-item-id="' + parseInt(item.id, 10) + '"]');
			if (!row) {
				return;
			}
			if (document.querySelector('[data-wpcs-changes]')) {
				// The file may have moved or changed: show the view again for its new state.
				setTimeout(function () {
					window.location.reload();
				}, 1200);
			}
			var held = !!item.quarantine_path && (item.status === 'pending' || item.status === 'quarantined');
			var available = res.available || [];
			row.setAttribute('data-held', held ? '1' : '0');
			var download = row.querySelector('.wpcs-download');
			if (download) {
				download.classList.toggle('wpcs-hidden', !held);
			}
			var box = row.querySelector('.wpcs-cb-item');
			if (box) {
				box.checked = false;
				box.disabled = available.length === 0;
			}
			syncSelectAll(row.closest('table'));
		});
	}

	/* ---------------- Bulk actions ---------------- */

	function bindBulk() {
		var form = document.getElementById('wpcs-bulk-form');
		if (!form) {
			return;
		}
		form.addEventListener('submit', function (e) {
			var submitter = e.submitter || null;
			if (submitter && submitter.name === 'wpcs_single') {
				return; // Plain form post (core.js normally handles these buttons).
			}
			e.preventDefault();

			var select = form.querySelector('select[name="bulk_action"]');
			var apply = form.querySelector('[name="wpcs_bulk_apply"]');
			var action = select ? select.value : '';
			if (!action) {
				api.toast(t('chooseAction', 'Choose a bulk action first.'), true);
				return;
			}
			var boxes = toArray(document.querySelectorAll('.wpcs-cb-item:checked')).filter(function (b) {
				return !b.disabled;
			});
			if (!boxes.length) {
				api.toast(t('chooseItems', 'Select at least one item.'), true);
				return;
			}
			var ids = boxes.map(function (b) {
				return b.value;
			});
			if (action === 'delete' && !window.confirm(tn('confirmDelete', ids.length, 'Delete %s items permanently?'))) {
				return;
			}
			if (action === 'deny' && !window.confirm(tn('confirmDeny', ids.length, 'Deny %s items?'))) {
				return;
			}

			var rows = ids
				.map(function (id) {
					return document.querySelector('tr[data-item-id="' + parseInt(id, 10) + '"]');
				})
				.filter(Boolean);
			rows.forEach(function (row) {
				row.classList.add('is-busy');
			});
			if (apply) {
				apply.disabled = true;
			}

			api.bulk(action, ids)
				.then(function (res) {
					var failed = {};
					(res.errors || []).forEach(function (msg) {
						var m = /^#(\d+):/.exec(String(msg));
						if (m) {
							failed[m[1]] = true;
						}
					});
					var status = NEXT_STATUS[action];
					rows.forEach(function (row) {
						var id = row.getAttribute('data-item-id');
						if (failed[id]) {
							row.classList.remove('is-busy');
							return;
						}
						var held = heldAfter(action);
						applyRowState(row, status, availableAfter(status), held);
					});
					toArray(document.querySelectorAll('.wpcs-items')).forEach(syncSelectAll);
					updateMenuCounts(res.counts);

					var done = parseInt(res.done, 10) || 0;
					var errors = res.errors || [];
					var msg = done ? tn('bulkDone', done, '%s items updated.') : '';
					if (errors.length) {
						msg += (msg ? ' ' : '') + tn('bulkFailed', errors.length, '%s items could not be changed:') + ' ' + errors.slice(0, 3).join(' ');
						api.toast(msg, true);
					} else {
						api.toast(msg);
					}
					if (select) {
						select.value = '';
					}
				})
				.catch(function (err) {
					rows.forEach(function (row) {
						row.classList.remove('is-busy');
					});
					api.toast(err.message, true);
				})
				.then(function () {
					if (apply) {
						apply.disabled = false;
					}
				});
		});
	}

	/* ---------------- Filters ---------------- */

	function bindAutosubmit() {
		document.addEventListener('change', function (e) {
			if (e.target.matches('[data-wpcs-autosubmit]') && e.target.form) {
				e.target.form.submit();
			}
		});
	}

	/* ---------------- Dashboard ---------------- */

	function bindFreeze() {
		document.addEventListener('click', function (e) {
			var btn = e.target.closest('[data-wpcs-freeze]');
			if (!btn) {
				return;
			}
			e.preventDefault();
			var mode = btn.getAttribute('data-wpcs-freeze');
			var params = {};
			var minutes = parseInt(btn.getAttribute('data-minutes'), 10);
			if (minutes > 0) {
				params.minutes = minutes;
			}
			btn.disabled = true;
			var label = btn.textContent;
			btn.textContent = t('working', 'Working...');
			api.ajax(mode === 'unlock' ? 'unlock' : 'lock', params)
				.then(function () {
					api.toast(mode === 'unlock' ? t('unlocked', 'Unlocked.') : t('locked', 'Locked.'));
					setTimeout(function () {
						window.location.reload();
					}, 900);
				})
				.catch(function (err) {
					btn.disabled = false;
					btn.textContent = label;
					api.toast(err.message, true);
				});
		});
	}

	function bindDashboardRefresh() {
		if (!document.querySelector('[data-wpcs-dashboard]')) {
			return;
		}
		document.addEventListener('wpcybersec:scan-finished', function (e) {
			var status = (e && e.detail) || {};
			var delay = 1400;
			if (status.otherScan && status.notice) {
				// The requested scan never got to run: leave time to read why.
				api.toast(status.notice, true);
				delay = 6000;
			} else {
				api.toast(t('refreshing', 'Scan finished. Refreshing the dashboard...'));
			}
			setTimeout(function () {
				window.location.reload();
			}, delay);
		});
	}

	/* ---------------- Init ---------------- */

	function init() {
		bindDetails();
		bindSelection();
		bindItemUpdates();
		bindBulk();
		bindAutosubmit();
		bindFreeze();
		bindDashboardRefresh();
		toArray(document.querySelectorAll('.wpcs-items')).forEach(syncSelectAll);
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', init);
	} else {
		init();
	}
})();

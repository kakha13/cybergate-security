# WP Cyber Security - architecture and module contracts

Plugin folder: `wp-cyber-security/` (slug `wp-cyber-security`, text domain `wp-cyber-security`).
Namespace `WPCyberSecurity\`, admin classes in `WPCyberSecurity\Admin\`. Prefix for options,
hooks, cron, AJAX, CSS classes: `wpcybersec_` / `wpcs-`. PHP 7.4+, WordPress 6.0+. No build step.

## What the plugin does

1. **Scans the whole site** (core, plugins, themes, uploads, web root, optionally the parent
   folder) for malware, webshells and backdoors, and verifies core and wordpress.org plugin
   files against official checksums.
2. **Holds every new upload** (media library, REST, sideloads, plugin/theme ZIPs) in quarantine
   until an administrator approves it on the Reports page. Optional early guard
   (`auto_prepend_file`) also holds uploads sent to ANY PHP script, not just WordPress.
3. **Holds new plugin/theme installs** until approved.
4. **Detects new and modified files** by comparing every file with a manifest (path -> sha256);
   unknown executable files can be quarantined automatically.
5. **Allow once, allowed always**: approving stores the file's SHA-256 (or the install slug) in
   a permanent allowlist. The same content is never held again.
6. **Setup wizard** for site owners and an **Advanced** settings tab for system administrators
   (data dir outside web root, early guard, real cron, exclusions, fapolicyd/inotify/nginx
   snippets, ClamAV, tamper checksum, freeze lock).

## Rules for every module

- Every class has a **no-argument constructor that does nothing heavy** and, if it needs hooks,
  a public `register()` method. `Plugin::boot()` creates and registers everything.
- Reach other services through `wpcybersec()->name` (see the list below). Never construct
  core services yourself except `new Storage()` in code that may run before boot.
- Escape all output (`esc_html`, `esc_attr`, `esc_url`, `wp_kses_post`), check capability
  `manage_options` and nonces on every form/AJAX/admin-post handler.
- Translatable strings use text domain `wp-cyber-security`. **Never use em dashes or en dashes**
  in any string or comment; use a plain hyphen.
- Icons: Dashicons only (`<span class="dashicons dashicons-shield"></span>`). No emojis.
- Datetimes in the DB are UTC; display with `get_date_from_gmt( $utc, get_option('date_format') . ' ' . get_option('time_format') )`.
- PHP 7.4 compatible syntax: no `match`, no nullsafe `?->`, no named arguments, no union types,
  no `str_contains` (use `false !== strpos`).

## Services (`wpcybersec()->...`)

| Property | Class | Owner |
|---|---|---|
| settings | `Settings` | core |
| storage | `Storage` | core |
| store | `Store` | core |
| logger | `Logger` | core |
| allowlist | `Allowlist` | core |
| quarantine | `Quarantine` | core |
| decisions | `Decisions` | core |
| snapshots | `Snapshots` | core (changes view) |
| ajax | `Ajax` | core |
| scanner | `Scanner` | engine |
| file_monitor | `File_Monitor` | engine |
| scan_job | `Scan_Job` | engine |
| db_scanner | `Db_Scanner` | engine (database scan) |
| user_watch | `User_Watch` | engine (administrator watch) |
| notifier | `Notifier` | gates |
| upload_gate | `Upload_Gate` | gates |
| install_gate | `Install_Gate` | gates |
| guard_manager | `Guard_Manager` | gates |
| sysadmin | `Sysadmin_Tools` | setup |
| admin | `Admin\Admin` | admin UI |

Static helpers: `Paths` (core), `Guard_Config` (core), `Installer` (core), `Cli` (setup),
`Signatures` (engine), `Admin\Assets` (core), `Diff` (changes view). `Originals` is created on
demand (`new Originals()`).

## Core API (already written - read the source in `includes/`)

- `Settings`: `defaults()`, `enums()`, `presets()`, `all()`, `get($key, $default)`,
  `update(array $values)`, `apply_level($level)`, `recipients()`. Action
  `wpcybersec_settings_updated($new, $old)`.
- `Storage`: `data_dir()`, `path($sub)`, `quarantine_dir()`, `jobs_dir()`, `spool_dir()`,
  `guard_dir()`, `ensure()`, `protect($dir)`, `is_in_webroot($path)`, static `is_within($path, $dir)`.
- `Paths` (static): `scan_root()`, `rel($abs)`, `abs($rel)`, `hash($rel)`, `ext($name)`,
  `is_executable($name)`, `is_excluded($rel)`.
- `Store`: constants `TYPE_*` (upload, install, file, threat), `STATUS_*` (pending, approved,
  denied, ignored, quarantined, restored, deleted, resolved), `SEV_*` (0 info, 1 medium, 2 high,
  3 critical), `STATE_*` (trusted, pending, threat). Items: `item_insert`, `item_get`,
  `item_update`, `items_query`, `items_count`, `counts()`, `item_find_open($type, $path, $sha256)`,
  `items_delete`. Manifest: `manifest_get_many`, `manifest_get`, `manifest_upsert_many`,
  `manifest_touch`, `manifest_unseen`, `manifest_delete`, `manifest_delete_prefix`,
  `manifest_count`, `manifest_set_state`, `manifest_truncate`, `manifest_page`. Log:
  `log_insert`, `log_query`, `log_prune`. Static `table`, `now`, `severity_label`, `client_ip`.
- `Allowlist`: `is_allowed_hash`, `allow_hash($sha256, $label, $note)`, `is_allowed_install($type, $slug)`,
  `allow_install($type, $slug, $label, $note)`, static `install_key`, `remove($id)`, `get($id)`,
  `query($args)`, `count()`, `hashes()`, `export_guard_file()`, `verify_integrity()` (true/false/null).
- `Quarantine`: `hold($src, $move = true)` -> `{quarantine_path, sha256, size}`|WP_Error,
  `restore($item)`, `to_temp($item)`, `purge($item)`, `exists($item)`, `stream($item)`.
- `Logger`: `log($event, $message, $context = array())`.
- `Decisions`: `ACTIONS`, static `available($item)`, `apply($action, $id)`, `bulk($action, $ids)`.
- `Guard_Config` (static): `file()`, `allow_file()`, `read()`, `write($config)`,
  `set_enabled($bool)`, `atomic_write($file, $content)`.
- `Ajax`: endpoints listed in `class-ajax.php` (scan_start/tick/status/cancel, item_action,
  bulk_action, counts, unlock, lock). Nonce action `Ajax::NONCE` = `wpcybersec_ajax`.
- `Admin\Assets`: `register()`, `enqueue()`. Handles `wpcybersec-base` (css) and
  `wpcybersec-core` (js, exposes `window.WPCyberSec`, see header comment in `assets/js/core.js`).
- `Installer`: `CRON_HOOKS`, `REDIRECT_OPTION` (`wpcybersec_activation_redirect`, set on activation),
  `activate()`, `install()`, `maybe_upgrade()`, `deactivate()`, `tables()`.

### Item row shape

```
id, type (upload|install|file|threat|user), status, severity (0-3),
path            relative path (file/threat), original file name (upload), "plugin:<slug>" (install),
                "db:option:<name>" / "db:post:<ID>" / "db:hfcm:<id>" / "db:snippets:<id>" (threat with source database),
                "user:<ID>" (user)
original_path   absolute path where the file lives / must be restored to ('' for uploads)
quarantine_path absolute path of the held copy ('' when nothing is held)
sha256, size, mime, source, user_id, ip,
details         array (decoded JSON), see below
created_at, updated_at, decided_by, decided_at
```

`details` keys used across modules (all optional):
- `hits`: list of `{ sig, title, severity, line, snippet }` (malware signature hits)
- `change`: `new` | `modified`; `previous_sha256`
- `verified`: `core` | `plugin` checksum verdicts, `checksum`: `mismatch` | `unknown_file`
- `post_id` (attach approved upload to this post), `context`: `media` | `sideload` | `plugin_zip` | `theme_zip` | `guard`
- `request_uri`, `script` (guard), `field` (guard form field name)
- `install_type` (`plugin`|`theme`), `slug`, `name`, `version`, `install_source` (`wporg`|`upload`|`url`)

Sources (`source` column): `media`, `sideload`, `rest`, `plugin_zip`, `theme_zip`, `guard`,
`scan`, `install`, `database` (Db_Scanner finding; `sha256` is the place-bound fingerprint, only
"ignore" applies, which stores it in the allowlist as kind `db`), `user` (User_Watch real time).

Database findings (`Db_Scanner`): options (decoder + eval payloads, document.write(unescape,
fromCharCode + eval; scripts from other sites and hidden iframes only in widget_*, theme_mods_*,
*custom_html*), posts of every type except revisions/oembed_cache/customize_changeset (publish,
draft, private, pending, future), and code plugin storage reported as medium "review" findings
(ihaf_insert_* options, hefo, wpcode posts, {prefix}hfcm_scripts, {prefix}snippets). Chunked by
primary key range; `Scan_Job` runs it in the finishing phase of full and baseline scans, with
opts `database => true`, and once a day for cron scans. Details: table, key, label, hits
(redacted snippets), fingerprint, seen_run. A complete run resolves open findings it no longer
sees. Last run summary: option `wpcybersec_db_scan`.

Administrator watch (`User_Watch`): option `wpcybersec_trusted_admins` (user ids, seeded from the
current administrators on install/upgrade or first use). Untrusted administrators (role or
super admin) become `user` items in real time (user_register, set_user_role, add_user_role,
grant_super_admin) and during whole-site scans. approve = trust; deny = role subscriber,
super admin revoked, sessions destroyed (refused for the current user and the last
administrator). Deleted or demoted accounts resolve their item.

Core integrity (`Scanner::integrity_issue()`, every scan mode including baseline): executable
or PHP-content files in wp-admin/ or wp-includes/ that core does not ship are high threats
(only when core checksums loaded; logs ignored); .htaccess-like files there and non-core PHP
files in the WordPress root (except wp-config.php, the exact guard bootstrap and a plain
Wordfence loader) are medium file items. Checksum mismatches of core, wordpress.org plugin and
own files are threats in every mode, for executable names and .js/.mjs. Whole-site runs count
missing core files (`missing_core` in status/last_result, "Missing core files: N" in the
summary).

## Changes view (what changed in a file)

Files: `includes/class-snapshots.php`, `includes/class-originals.php`, `includes/class-diff.php`,
`Admin\Reports_Page::render_changes()` (`admin.php?page=wpcybersec-reports&view=changes&item=<id>&from=<tab>&layout=unified|split`).

- `Snapshots`: gzip copies of file versions at `<data_dir>/snapshots/<k[0:2]>/<k[2:4]>/<k>.gz`
  (0600), `k = hmac_sha256(sha256, option wpcybersec_snapshot_key)` so a leaked fingerprint is
  never a download address. Only when setting `snapshots` is on, the name is executable, a config
  file or .js/.html/.svg, size <= `snapshot_max_kb`, and the content is not binary. API: `store($abs,
  $sha)`, `store_trusted($abs, $sha, $verify)` (skips official core/plugin checksum matches),
  `put_content($content)`, `has`, `get` (sha256 checked), `stored_at`, `stats`, `clear`, `prune`
  (daily from `wpcybersec_maintenance`, keeps versions referenced by the manifest or by a file/threat
  item's `sha256`, `details.previous_sha256`, `details.base_sha256`; resumable via a cursor option).
  `needs_backfill()`: the next whole-site scan also copies unchanged trusted files once (after the
  feature is switched on, the limit is raised, or copies are deleted).
- Capture points: `Scan_Job` (every file a run trusts, the current version of every reported file
  before it may be quarantined, the backfill), `File_Monitor::trust_file()` and
  `rebaseline_paths()`, `Decisions` quarantine/delete of a live file.
- `Originals::fetch($rel)`: official core file from core.svn (md5 must match core checksums) or
  wordpress.org plugin file from plugins.svn tag/trunk (sha256 must be in the plugin checksums JSON).
  Cached in Snapshots; misses cached 6 h. Remembered on the item as `details.base_sha256`.
- `Diff::for_item($item, $args)`: `{ mode diff|content|unavailable, reason, base_label, current_label,
  base, current, added, removed, html, notes, secrets, hit_lines }`. Base: previous copy, else official
  original, else content mode. Current: live file, held copy (`Quarantine::read()`), saved copy.
  Secrets are redacted (`Diff::redact()`) before comparing or showing. Rendering uses core's
  `Text_Diff` engine with its own escaped renderer (wp_text_diff() collapses whitespace).
- AJAX `diff_summary` (id) feeds the "Changes: +N -M lines vs ..." line in the expandable details.

## Engine module (owner: engine builder)

Files: `includes/class-scanner.php`, `includes/class-signatures.php`,
`includes/class-file-monitor.php`, `includes/class-scan-job.php`, `bin/cron.php`.

### `Scanner`
- `register()`: nothing required (may add cache cleanup).
- `scan_file($abs, $rel = '')`: array of hits `{ sig, title, severity, line, snippet }`. Reads
  at most `max_file_mb`. Skips binary media except the "PHP hidden in image" checks (head and
  tail 8 KB). Applies `min_severity`.
- `scan_upload($tmp_path, $original_name)`: hits for an incoming upload (name-based checks such
  as double extensions + content checks + optional ClamAV). Severity >= 2 means "malicious".
- `max_severity(array $hits)`: int.
- `verify($rel, $sha256, $md5 = '')`: `'match' | 'mismatch' | 'unknown'` using core checksums
  (`get_core_checksums()`, md5) and wordpress.org plugin checksums
  (`https://downloads.wordpress.org/plugin-checksums/{slug}/{version}.json`, sha256),
  cached in transients. Only when setting `use_checksums` is on.
- `is_core_path($rel)`, `plugin_slug_for($rel)` helpers.
- `clamav_available()`: bool, `clamav_scan($path)`: null (not available) or hits.

### `Signatures`
- static `all()`: list of `{ id, title, severity, pattern (PCRE), targets ('php'|'js'|'html'|'any'|'image'|'htaccess') }`.
  Low false positives are critical (must stay quiet on WooCommerce, Elementor, Yoast, Polylang).

### `File_Monitor`
- `register()`: schedules `wpcybersec_scheduled_scan` according to `scan_schedule` (reschedules
  on `wpcybersec_settings_updated`), hooks `wpcybersec_scheduled_scan` (starts an incremental
  job, ticks once) and `wpcybersec_scan_tick` (continues a running job, re-schedules itself in
  60s while running).
- `trust_file($abs, $sha256 = '')`: manifest row -> trusted (hash computed if empty).
- `forget_file($abs)`: delete the manifest row.
- `rebaseline_paths(array $abs_dirs)`: synchronously re-trust files under these folders (used
  after plugin/theme/core updates), BUT files with malware hits >= 2 or checksum mismatches
  become threat items instead of trusted. Never rebaselines the whole site.
- `evaluate($abs, $rel, $stat, $manifest_row, $job)`: decision logic shared with Scan_Job
  (may be private; Scan_Job is in the same module).

### `Scan_Job`
Only one job at a time. State in option `wpcybersec_job` (not autoloaded); file list in
`<jobs_dir>/<id>.list`.
- `start(array $opts)`: opts `mode` (`incremental`|`full`|`baseline`), `malware` (bool),
  `paths` (optional absolute folders), `trigger` (`manual`|`cron`|`cli`|`wizard`|`update`),
  `force` (bool). Returns job id string or WP_Error. If a job is running and not `force`,
  returns the running id.
- `tick($budget_seconds)`: does work for up to the budget, returns `status()`.
- `status()`: `{ id, state (idle|enumerating|processing|finishing|done|failed|cancelled), mode,
  malware, trigger, files_total, files_done, new, modified, deleted, threats, quarantined,
  skipped, started_at (unix), finished_at (unix), current (rel path), message, percent }`.
- `cancel()`, `last_result()` (status of the last finished job, option `wpcybersec_last_scan`),
  `run_to_completion(callable $progress = null)` for CLI and bin/cron.php.
- Decisions per file:
  - `baseline`: everything trusted, except malware hits (when `malware`) -> threat item.
  - `incremental`: unchanged files (same size+mtime) are skipped; new/changed files are hashed,
    checksum-verified (match -> trusted), allowlisted hash -> trusted, else: malware hits ->
    threat item (auto-quarantine critical if `auto_quarantine`); new executable files with
    `file_mode=quarantine_exec` -> quarantined + pending file item; else `file_mode=report` ->
    pending file item (file stays). Modified executable files: `modified_action`.
  - `full`: like incremental but also re-scans unchanged files for malware.
  - Duplicates: never create a second open item for the same path+hash.
  - Deleted files: manifest rows not seen this run are removed and counted (logged, no item).
- Calls `wpcybersec()->notifier->item_created($id)` for each new item, and
  `wpcybersec()->notifier->scan_finished($status)` at the end.

### `bin/cron.php`
CLI runner for real cron without WP-CLI: `php bin/cron.php [--full|--baseline] [--no-malware] [--wp=/abs/path]`.
Refuses to run from the web (`PHP_SAPI !== 'cli'` -> exit). Loads `wp-load.php`, runs a scan
to completion, prints a one-line summary.

## Gates module (owner: gates builder)

Files: `includes/class-upload-gate.php`, `includes/class-install-gate.php`,
`includes/class-guard-manager.php`, `includes/class-notifier.php`, `guard/guard.php`.

### `Upload_Gate`
- `register()`: `wp_handle_upload_prefilter` and `wp_handle_sideload_prefilter` (priority 1000).
- Policy (`upload_mode`): `hold_all` holds everything not allowlisted; `hold_risky` holds
  executable/script/archive/svg/html types, files whose real type does not match the extension,
  and anything with hits; `scan_only` holds only uploads with hits >= 2; `off` does nothing.
  Users with a role in `upload_bypass_roles` pass when clean. Malicious uploads (hits >= 2)
  are always held unless the hash is allowlisted. `gate_sideloads` controls sideloads.
- Holding = `quarantine->hold($tmp, false)` + item (type upload, status pending, path = original
  file name, source media|sideload|rest|plugin_zip|theme_zip, details.post_id/context/hits)
  + log + notifier, then `$file['error'] = <message>` so WordPress shows it in the uploader.
- `with_bypass(callable $fn)`: runs $fn with the gate disabled (used when importing).
- `on_approve(array $item)`: allowlist the hash; for media/sideload/rest uploads import the held
  file into the Media Library (`media_handle_sideload`, attach to `details.post_id`) and store
  `details.attachment_id`; for plugin/theme ZIPs also allowlist the install slug found in the
  ZIP (top folder) so the install gate lets it through. Purge the held copy after import.
- `on_deny(array $item)`: optional hook (logging).

### `Install_Gate`
- `register()`: `upgrader_source_selection` (hold new installs unless
  `Allowlist::is_allowed_install`; return WP_Error with a clear message and create an item of
  type install), optional update holding (`hold_updates`), `upgrader_process_complete`
  (call `file_monitor->rebaseline_paths()` for just the updated plugin/theme folders, or core
  folders after a core update), `file_mod_allowed` (when `freeze_mods` is on, return false
  unless unlocked).
- `on_approve(array $item)`: allowlist install key (and package hash if known).
- `unlock($minutes)`, `lock()`, `is_unlocked()`, `unlocked_until()` (unix, 0 when locked).

### `Guard_Manager`
- `register()`: imports the guard spool into items (`import_spool()`) on `admin_init` (cheap
  check: file size > 0) and on cron hook `wpcybersec_guard_import`; keeps the guard config in
  sync on `wpcybersec_settings_updated` and `wpcybersec_allowlist_changed`; re-enables the
  config on boot if the guard was installed (option `wpcybersec_guard_installed`).
- `bootstrap_path()`: `ABSPATH . 'wpcybersec-guard.php'`.
- `install()`: writes the bootstrap (checks `file_exists` before including the plugin's
  `guard/guard.php`, so deleting the plugin never fatals), `Guard_Config::write()`,
  `allowlist->export_guard_file()`, sets option `wpcybersec_guard_installed`.
- `uninstall()`: disables config; removes bootstrap only if `auto_prepend_file` no longer points to it.
- `status()`: `{ installed, active (constant WPCYBERSEC_GUARD_ACTIVE defined in this request),
  bootstrap_path, bootstrap_exists, prepend (ini value), conflict (other prepend file or null),
  sapi, pending_spool }`.
- `snippets()`: list of `{ id, label, file, code, help }` for .user.ini, .htaccess (mod_php),
  php-fpm pool, nginx fastcgi_param, php.ini.
- `write_user_ini()`: appends/updates `auto_prepend_file` in `ABSPATH/.user.ini`.
- `import_spool()`: int imported.

### `guard/guard.php`
Standalone (no WordPress). Defines `WPCYBERSEC_GUARD_ACTIVE`. Reads `WPCYBERSEC_GUARD_CONFIG`
(set by the bootstrap). Returns immediately if disabled or `$_FILES` empty or the request path
matches `exempt`. For each uploaded file (nested `$_FILES` arrays too) with no error:
sha256 the tmp file; allowlisted -> pass; else copy into `quarantine_dir`, append a JSON line
to `spool_file` (`time, script, uri, ip, field, name, size, sha256, quarantine_path, type`),
unlink the tmp file, and either answer `403` with the message (`block`) or strip it from
`$_FILES` (`strip`). Must never fatal: wrap in try/catch, fail open on internal errors.

### `Notifier`
- `register()`: cron `wpcybersec_digest` (daily) when `notify_mode=digest`.
- `item_created($id)`: instant mode emails recipients (throttle: one email per 10 minutes,
  queued items are summarized in the next email) and posts to `webhook_url` if set.
- `scan_finished(array $status)`: email only when threats/new pending items were found.
- `send_test()`: bool.
- `send_digest()`.

## Admin UI module (owner: admin builder)

Files: `includes/admin/class-admin.php`, `includes/admin/class-dashboard-page.php`,
`includes/admin/class-reports-page.php`, `assets/css/admin.css`, `assets/js/admin.js`.

- `Admin\Admin::register()`: menu `Cyber Security` (dashicons-shield, position 80, capability
  `manage_options`, count bubble = pending + threats), submenus Dashboard (`wpcybersec`),
  Reports (`wpcybersec-reports`), Settings (`wpcybersec-settings`, rendered by
  `Admin\Settings_Page`), Setup Wizard (`wpcybersec-wizard`, rendered by `Admin\Wizard`).
  Registers `Admin\Assets` on `admin_enqueue_scripts` and enqueues base + page assets only on
  plugin pages. Activation redirect: if option `Installer::REDIRECT_OPTION` is set and the wizard
  is not completed, delete it and redirect to the wizard (skip on bulk activation, network
  admin, AJAX). Admin bar node "Cyber Security (N)" for admins when N pending. Admin notice on
  other screens when the wizard is not completed. "Settings" and "Setup" action links on the
  plugins screen. admin-post handlers: `wpcybersec_download` (stream held file),
  `wpcybersec_allowlist_remove`.
- Header partial used by every page: `Admin\Admin::header($title, $subtitle, $actions_html)`
  renders `.wpcs-header` with the shield icon. **The setup builder uses this too.**
- Dashboard: status cards (protection level, pending approvals, threats, quarantine, files
  monitored, last scan), scan buttons (Quick scan = incremental, Full malware scan, Rebuild
  baseline) with a progress block, recent activity, guard and freeze status, link to wizard.
- Reports: tabs Pending approvals / Threats / Quarantine / Allowlist / Activity. Tables with
  type badge, file, size, hash, who/where, when, verdict/hits, status cell
  (`data-wpcs-status`), action buttons (`data-wpcs-action`) from `Decisions::available()`,
  expandable details (hits with snippet and line), bulk actions, search, pagination.
  Allowlist tab: remove entry. Activity tab: log with filters.

## Setup module (owner: setup builder)

Files: `includes/admin/class-wizard.php`, `includes/admin/class-settings-page.php`,
`includes/class-sysadmin-tools.php`, `includes/class-cli.php`, `assets/css/setup.css`,
`assets/js/setup.js`.

- Wizard steps: Welcome, Environment check, Protection level, Baseline scan, Notifications,
  Server hardening (sysadmin, optional), Done. Saves via admin-post `wpcybersec_wizard`.
  Baseline step runs `WPCyberSec.scan.run({mode:'baseline', malware:true, trigger:'wizard'})`.
  Completing sets `wizard_completed`.
- Settings page tabs: General (protection level presets + fine-grained upload/install/file
  monitor/schedule/notification settings) and Advanced for system administrators (data dir,
  scan root, exclusions, limits, early guard install + snippets, real cron, freeze lock,
  hardening snippets, fapolicyd/inotify/maldet, ClamAV, tamper checksum, import/export,
  uninstall behavior). Saves via admin-post `wpcybersec_save_settings`.
- `Sysadmin_Tools`: `diagnostics()` (list of `{ id, label, status pass|warn|fail|info, detail, fix }`),
  `cron_snippets()`, `apache_uploads_rules()`, `nginx_rules()`, `permission_commands()`,
  `fapolicyd_trust_export()`, `fapolicyd_rules()`, `inotify_script()`, `maldet_snippet()`,
  `write_uploads_htaccess()`, `hmac_snippet()`.
- `Cli`: static `register()` -> `WP_CLI::add_command('wpcybersec', ...)` with `status`, `scan`,
  `pending`, `approve`, `deny`, `allowlist`, `guard`, `unlock`, `lock`.

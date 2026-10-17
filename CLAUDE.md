# CyberGate Security

WordPress security plugin: full-site malware scan, holds every new upload/install/unknown file until an admin approves it, approvals remembered by SHA-256. Plugin lives in `cybergate-security/`; module contracts in `docs/ARCHITECTURE.md` (read it before changing cross-module APIs).

## Commands
- `scripts/build.sh` - lint, stage without dev files, rebuild checksums, zip to `dist/` and verify
- `scripts/build.sh --wporg` - same plus WordPress.org checks (needs real `Contributors:` in readme.txt)
- `scripts/build.sh --svn PATH` - sync trunk/tags/assets into a wp.org SVN checkout (prints svn commands, does not commit)
- `php cybergate-security/bin/build-checksums.php` - regenerate `checksums.json`; run after ANY plugin file change, or the plugin flags its own edited files as tampered
- `php cybergate-security/bin/cron.php [--full|--baseline] [--isolated] [--url=URL]` - run a scan to completion from the CLI (inside a WP install); `--isolated` loads no other plugin and no theme (mu-plugins still load); `--url` is the network address on multisite
- `wp wpcybersec report --file=report.html` - the downloadable security report (also Reports > Download report)
- Lint: `for f in $(find cybergate-security -name '*.php'); do php -l $f; done` and `node --check` on `assets/js/*.js`

## Code rules
- PHP 7.4 compatible syntax (no match, `?->`, named args, union types, `str_contains`); WordPress 6.0+
- Namespace `WPCyberSecurity\` (admin: `WPCyberSecurity\Admin\`), file `class-foo-bar.php` for `Foo_Bar`, autoloaded
- Services via `wpcybersec()->name`; module constructors stay cheap, hooks go in `register()`
- Capability checks via `Admin\Admin::can()` (network admin on multisite), plus nonce on every handler
- No em/en dashes anywhere (code, comments, UI strings); icons are Dashicons, no emojis
- Never show secrets: diff/snippet output goes through `Diff::redact()` / `Diff::redact_snippet()`
- Allowlist approvals are bound to executability: `is_allowed_hash( $sha, $executable )`

## Gotchas
- `class-signatures.php` contains malware patterns as data; it only passes scans because `checksums.json` matches it
- Activation runs after `plugins_loaded`, so `Installer` must not rely on booted services
- A whole-site scan without a baseline (`wpcybersec_baseline_at`) is converted to a baseline; never run an incremental scan on an empty manifest
- Files written by the plugin itself (`.htaccess`, `.user.ini`, `wp-config.php` edits) must be passed to `file_monitor->trust_file()` or the next scan reports them
- Guard (`guard/guard.php`) runs before WordPress via `auto_prepend_file`: no WP functions, PHP 5.6 syntax, must never fatal
- Real-site false positives to keep quiet: server `error_log` files (no extension) inside core folders, `wordfence-waf.php` in the root, bundled `wp-content/plugins/hello.php` (verify against core checksums, not the hello-dolly listing), thousands of changed files right after plugin updates
- Script injection hides in header/footer plugins (`{prefix}hfcm_scripts`, `ihaf_insert_*`, Code Snippets): the database scan must cover them
- ClamAV/maldet find more known infections but do not block attacks; say it that way in UI text
- Multisite is one network-wide install (`Network: true`): plugin options only through `Network::get_option()`/`update_option()` (never plain `get_option()`), tables through `Store::table()` (base prefix), cron through `Network::schedule_event()` and friends (main site only), page links through `Admin::page_url()` (Network Admin); anything tied to one site (media import, post links, site URLs) records `details.blog_id` and runs in `Network::on_site()`
- Host compatibility: files may live outside the scan root (absolute manifest keys), so guard live-file access with `Paths::in_scope()`, not "inside scan_root"; check `Storage::path_allowed()` before touching a path (open_basedir); a storage failure must never block a clean upload; budgets go through `Scan_Job::clamp_budget()`
- Never build test sandboxes with `wp core download`: its tar.gz extraction truncates long wp-includes/php-ai-client paths and the plugin (correctly) reports them; use the .zip from wordpress.org
- Admin pages must stay at 0 plugin queries: write small state options only through `Network::update_option()` (autoloaded `STATE_OPTIONS`), and read badge counts via `Store::counts()`; never run ClamAV or loopback tests inside an upload request (use the cached self-test / last ping)

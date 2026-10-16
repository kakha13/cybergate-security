# WP Cyber Security

WordPress security plugin: full-site malware scan, holds every new upload/install/unknown file until an admin approves it, approvals remembered by SHA-256. Plugin lives in `wp-cyber-security/`; module contracts in `docs/ARCHITECTURE.md` (read it before changing cross-module APIs).

## Commands
- `scripts/build.sh` - lint, stage without dev files, rebuild checksums, zip to `dist/` and verify
- `scripts/build.sh --wporg` - same plus WordPress.org checks (needs real `Contributors:` in readme.txt)
- `scripts/build.sh --svn PATH` - sync trunk/tags/assets into a wp.org SVN checkout (prints svn commands, does not commit)
- `php wp-cyber-security/bin/build-checksums.php` - regenerate `checksums.json`; run after ANY plugin file change, or the plugin flags its own edited files as tampered
- `php wp-cyber-security/bin/cron.php [--full|--baseline]` - run a scan to completion from the CLI (inside a WP install)
- Lint: `for f in $(find wp-cyber-security -name '*.php'); do php -l $f; done` and `node --check` on `assets/js/*.js`

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

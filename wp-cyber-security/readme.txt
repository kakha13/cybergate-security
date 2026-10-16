=== WP Cyber Security ===
Contributors: kakha13
Tags: security, malware scanner, file integrity, upload, quarantine
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Scans your site for malware and holds every new upload, install and unknown file until you approve it. Approve once, allowed always.

== Description ==

WP Cyber Security works like a door that only opens for files you know.

* **Scans everything.** WordPress core, plugins, themes, uploads and the web root are checked for malware, web shells and backdoors. Core and WordPress.org plugin files are compared with their official checksums, so original files are never reported.
* **Holds every new upload until you allow it.** Media uploads, files WordPress downloads, plugin and theme ZIPs and new installs wait in a private quarantine. You decide on the Reports page.
* **Allow once, allowed always.** Approving a file remembers its SHA-256 fingerprint. The same file is never held again, wherever it shows up. A file approved as an image is never accepted as a PHP file.
* **Shows exactly what changed.** For a modified file you get a line-by-line diff against the last approved version or the official original, with every malware match linked to its line. Passwords, keys and salts are masked.
* **Detects new and changed files.** A fingerprint of every file is recorded once; later scans report only what is new or different.
* **Recent changes for incidents.** If a site was already infected when the fingerprints were recorded, the infected files look normal. Reports > Recent changes lists every PHP, script and configuration file modified in the last 7, 14 or 30 days and says what explains each change: a WordPress, plugin or theme update, an official checksum, or nothing. Unexplained files can be read on screen and reported for review with one click.
* **A report for your developer.** "Download report" creates one HTML file with the scan results, everything waiting for a decision with the code that triggered it, settings, server checks and recent activity. Passwords, keys and email addresses are hidden, so it is safe to send.
* **Clean-room scan.** `php wp-content/plugins/wp-cyber-security/bin/cron.php --isolated --full` scans with every other plugin and the theme switched off for that run only, so a compromised plugin cannot hide files from the scanner.
* **Setup wizard.** Checks your server and fixes most findings with one click: wp-config.php permissions, the code editor, PHP in uploads, a data folder outside the web root.
* **For system administrators.** An optional early upload guard (auto_prepend_file) holds uploads sent to any PHP script, not only WordPress. Real cron, fapolicyd, inotify, nginx and Apache rules, ClamAV and a tamper check for the allowlist.
* **WP-CLI.** `wp wpcybersec status`, `scan`, `pending`, `approve`, `deny`, `allowlist`, `guard`, `unlock`, `lock`, `report`.

== Installation ==

1. Upload the plugin through Plugins > Add New Plugin > Upload Plugin, or install it from the directory.
2. Activate it. The setup wizard opens.
3. Follow the steps: environment check, protection level, baseline scan, alerts and optional server hardening.

== Frequently Asked Questions ==

= Will it block my own uploads? =

With the Balanced or Strict level every upload waits for approval, including yours. Choose Relaxed, or turn off "Hold administrators' own uploads too", to let clean uploads by administrators through.

= What happens when I update a plugin or WordPress? =

Updates of installed plugins, themes and core are re-checked right away against their official checksums and trusted. New installs wait for approval.

= Does it change wp-config.php or .htaccess? =

Only when you press a fix button. Every change to wp-config.php is checked for errors first, and the plugin's own lines are marked so you can find them.

= What does the isolated scan not cover? =

Must-use plugins (wp-content/mu-plugins) and drop-ins (db.php, object-cache.php, advanced-cache.php) always load with WordPress and cannot be switched off for a scan. The isolated scan lists them so you can check them yourself.

= Where are held files kept? =

In a private folder with random file names that cannot run as code. The wizard can move this folder outside the web root.

== External services ==

The plugin contacts these services. No personal data and no site content is sent; only the version and file paths needed for the lookup.

* **WordPress.org checksum API** (api.wordpress.org): official checksums of WordPress core files for your version, used to recognise original files. Sent: WordPress version and locale. [Terms](https://wordpress.org/about/privacy/)
* **WordPress.org plugin checksums** (downloads.wordpress.org): official checksums of installed plugins hosted on WordPress.org. Sent: plugin slug and version.
* **WordPress.org Subversion** (core.svn.wordpress.org, plugins.svn.wordpress.org): when you open the "What changed" view of a core or WordPress.org plugin file, the original file is downloaded once to compare against. Sent: the file path, plugin slug and version.
* **Your webhook URL** (optional): when you set one, alerts about held files and threats are posted there. Nothing is sent unless you enter a URL.

== Screenshots ==

1. Setup wizard: environment check with one-click fixes.
2. Choose a protection level.
3. An upload held for approval in the Media Library.
4. The Reports page where you allow or deny.
5. The "What changed" view of a modified file.

== Changelog ==

= 1.0.0 =
* First release.

#!/usr/bin/env bash
#
# cgav - CyberGate antivirus helper for the server (ClamAV + Linux Malware Detect).
#
# Install once (as root):   bash cgav.sh self-install /path/to/wordpress
# Then use:                 cgav <command>
#
#   status                  what is installed and running, and every watched site
#   sites                   WordPress sites found on this server, and which are watched
#   add-site PATH           watch one more site (one server, many sites: run it per site)
#   add-all                 watch every WordPress site found on this server
#   remove-site PATH        stop watching a site
#   install-clamav          install ClamAV, download signatures, start the scanner service
#   install-maldet          install Linux Malware Detect + inotify-tools, watch the sites in
#                           real time, start on boot, report-only (CyberGate decides)
#   monitor start|stop|status|reload   control maldet's real-time monitor (reload = restart
#                           with the current site list)
#   test [PATH]             harmless EICAR test: both engines must report it
#   update                  update ClamAV and maldet signatures
#   scan [PATH|all]         scan a site (or every watched site) now with maldet
#   logs                    last lines of the maldet monitor and event logs
#
# ClamAV and maldet are installed once per server and shared by all its sites.
# Every command is safe to run again: it checks what is already in place first.
# Nothing here deletes or moves site files.

set -u

CONF=/etc/cgav.conf
# shellcheck source=/dev/null
[ -f "$CONF" ] && . "$CONF"
SITE="${SITE:-}"
SITES_FILE=/etc/cgav.sites
MALDET=/usr/local/maldetect
MON_PATHS="$MALDET/monitor_paths"
# cPanel keeps its ClamAV build outside PATH.
[ -d /usr/local/cpanel/3rdparty/bin ] && PATH="$PATH:/usr/local/cpanel/3rdparty/bin"

if [ -t 1 ]; then G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; B=$'\e[1m'; N=$'\e[0m'; else G=; Y=; R=; B=; N=; fi
ok()   { printf '  %sok%s    %s\n' "$G" "$N" "$*"; }
no()   { printf '  %sno%s    %s\n' "$R" "$N" "$*"; }
warn() { printf '  %swarn%s  %s\n' "$Y" "$N" "$*"; }
head1(){ printf '\n%s== %s ==%s\n' "$B" "$*" "$N"; }
die()  { printf '%s%s%s\n' "$R" "$*" "$N" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

need_root() { [ "$(id -u)" = 0 ] || die "Run this as root (sudo -i first)."; }

# Package manager and service names for this distribution.
detect_os() {
  if have apt-get; then
    PKG=apt; CLAMD_SVC=clamav-daemon; FRESH_SVC=clamav-freshclam; MALDET_DEFAULTS=/etc/default/maldet
  elif have dnf || have yum; then
    PKG=dnf; have dnf || PKG=yum; CLAMD_SVC=clamd@scan; FRESH_SVC=clamav-freshclam; MALDET_DEFAULTS=/etc/sysconfig/maldet
  else
    die "Unsupported system: needs apt (Debian/Ubuntu) or dnf/yum (AlmaLinux/Rocky/CentOS/CloudLinux)."
  fi
}

pkg_install() {
  if [ "$PKG" = apt ]; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" >/dev/null
  else
    "$PKG" install -y "$@" >/dev/null
  fi
}

# A WordPress folder: wp-config.php in it, or one level up (allowed by WordPress).
is_wp() { [ -f "$1/wp-load.php" ] && { [ -f "$1/wp-config.php" ] || [ -f "$(dirname "$1")/wp-config.php" ]; }; }

# Watched sites: /etc/cgav.sites (one path per line) plus the single SITE= of older versions.
sites_list() {
  { [ -f "$SITES_FILE" ] && grep -v '^[[:space:]]*$' "$SITES_FILE"; [ -n "$SITE" ] && echo "$SITE"; } 2>/dev/null | awk '!seen[$0]++'
}

# WordPress sites in the folders hosting panels use (plus /var/www). Depth is fixed, so it stays fast.
discover_sites() {
  local d
  for d in /home/*/public_html /home/*/public_html/* /home/*/domains/*/public_html /home/*/web/*/public_html \
           /home/*/htdocs/* /www/wwwroot/* /var/www/vhosts/*/httpdocs /var/www/vhosts/*/httpdocs/* \
           /var/www/html /var/www/*/htdocs /var/www/*/public_html /var/www/*/public /var/www/*/data/www/* \
           /var/www/clients/client*/web*/web /home/master/applications/*/public_html /home/*/webapps/* \
           /sites/*/files /srv/www/*/public_html /srv/www/*; do
    [ -d "$d" ] && is_wp "$d" && (cd "$d" && pwd -P)
  done 2>/dev/null | awk '!seen[$0]++'
}

# Watched path that covers this site: itself, or a parent folder (maldet watches recursively).
watched_by() {
  local w
  while IFS= read -r w; do
    [ -n "$w" ] || continue
    case "$1/" in "${w%/}/"*) echo "$w"; return 0 ;; esac
  done < "$MON_PATHS" 2>/dev/null
  return 1
}

site_version() {
  sed -n 's/^[ *]*Version:[[:space:]]*\([^[:space:]]*\).*/\1/p' "$1/wp-content/plugins/cybergate-security/cybergate-security.php" 2>/dev/null | head -1
}

need_site() {
  # Commands that act on one site: the path given, else the only (or first) watched site.
  local want="${1:-}"
  if [ -z "$want" ]; then want="$(sites_list | head -1)"; fi
  [ -n "$want" ] && is_wp "$want" && { TARGET="$(cd "$want" && pwd -P)"; return 0; }
  die "No WordPress site given or watched. Run: cgav sites   then   cgav add-site /path/to/wordpress"
}

monitor_pids() { pgrep -f 'inotifywait.*maldetect' 2>/dev/null; }

# Hosting panel, from the same markers the plugin uses (Settings > Advanced shows its own result).
# Sets PANEL (id), PANEL_NAME and PANEL_WHY. Install folders count first; the site layout only
# gives a "likely" guess.
detect_panel() {
  PANEL=unknown; PANEL_NAME=""; PANEL_WHY=""
  local m
  for m in \
    "cpanel|cPanel|/usr/local/cpanel" \
    "plesk|Plesk|/usr/local/psa" \
    "plesk|Plesk|/opt/psa" \
    "directadmin|DirectAdmin|/usr/local/directadmin" \
    "cyberpanel|CyberPanel|/usr/local/CyberCP" \
    "aapanel|aaPanel / BT Panel|/www/server/panel" \
    "hestia|HestiaCP|/usr/local/hestia" \
    "vesta|VestaCP|/usr/local/vesta" \
    "cloudpanel|CloudPanel|/home/clp" \
    "cwp|CWP (Control Web Panel)|/usr/local/cwpsrv" \
    "ispconfig|ISPConfig|/usr/local/ispconfig" \
    "virtualmin|Virtualmin|/etc/webmin/virtual-server" \
    "webmin|Webmin|/etc/webmin" \
    "fastpanel|FASTPANEL|/usr/local/fastpanel2" \
    "ispmanager|ISPmanager|/usr/local/mgr5" \
    "runcloud|RunCloud|/etc/runcloud" \
    "gridpane|GridPane|/opt/gridpane"; do
    if [ -d "${m##*|}" ]; then
      PANEL="${m%%|*}"; m="${m#*|}"; PANEL_NAME="${m%%|*}"; PANEL_WHY="${m##*|}"
      return 0
    fi
  done
  local first; first="$(sites_list | head -1)"
  case "${first:-}/" in
    /www/wwwroot/*)                      PANEL=aapanel;    PANEL_NAME="aaPanel / BT Panel" ;;
    /var/www/vhosts/*)                   PANEL=plesk;      PANEL_NAME=Plesk ;;
    /home/u[0-9]*/domains/*/public_html/*) PANEL=hostinger; PANEL_NAME="Hostinger (hPanel)" ;;
    /home/*/domains/*/public_html/*)     PANEL=directadmin; PANEL_NAME=DirectAdmin ;;
    /home/*/web/*/public_html/*)         PANEL=hestia;     PANEL_NAME=HestiaCP ;;
    /home/*/htdocs/*)                    PANEL=cloudpanel; PANEL_NAME=CloudPanel ;;
    /var/www/clients/client*/web*/web/*) PANEL=ispconfig;  PANEL_NAME=ISPConfig ;;
    /home/master/applications/*)         PANEL=cloudways;  PANEL_NAME=Cloudways ;;
    /home/forge/*)                       PANEL=forge;      PANEL_NAME="Laravel Forge" ;;
    /home/ploi/*)                        PANEL=ploi;       PANEL_NAME=Ploi ;;
    /sites/*/files/*)                    PANEL=spinupwp;   PANEL_NAME=SpinupWP ;;
    *) return 0 ;;
  esac
  PANEL_WHY="likely, from the site folder $first"
}

# ------------------------------------------------------------------ status
cmd_status() {
  detect_os
  head1 "Sites"
  local s n=0
  while IFS= read -r s; do
    [ -n "$s" ] || continue; n=$((n+1))
    if ! is_wp "$s"; then no "$s: not a WordPress folder any more (cgav remove-site $s)"
    elif grep -qx "$s" "$MON_PATHS" 2>/dev/null; then local v; v="$(site_version "$s")"; ok "$s: watched by the monitor${v:+, CyberGate $v}"
    else warn "$s: not in $MON_PATHS (cgav add-site $s)"; fi
  done < <(sites_list)
  [ "$n" = 0 ] && warn "no site watched yet: cgav sites, then cgav add-site PATH (or cgav add-all)"
  detect_panel
  if [ "$PANEL" != unknown ]; then ok "hosting panel: $PANEL_NAME ($PANEL_WHY)"; else warn "hosting panel: none of the known panels found"; fi

  head1 "ClamAV"
  if have clamscan; then
    ok "installed: $(clamscan --version 2>/dev/null)"
  else
    no "not installed (cgav install-clamav)"
  fi
  if have clamdscan; then
    if systemctl is-active --quiet "$CLAMD_SVC" 2>/dev/null; then ok "scanner service $CLAMD_SVC is running"; else no "scanner service $CLAMD_SVC is not running"; fi
  fi
  if systemctl is-active --quiet "$FRESH_SVC" 2>/dev/null; then ok "signature updates ($FRESH_SVC) running"; elif have clamscan; then warn "signature update service $FRESH_SVC not running"; fi

  head1 "Linux Malware Detect"
  if [ -x "$MALDET/maldet" ]; then
    ok "installed: $("$MALDET/maldet" --help 2>/dev/null | sed -n 's/^Linux Malware Detect \(v[0-9.]*\).*/\1/p' | head -1), signatures $(cat "$MALDET/sigs/maldet.sigs.ver" 2>/dev/null || echo unknown)"
    Q="$(sed -n 's/^quarantine_hits="\([0-9]\)".*/\1/p' "$MALDET/conf.maldet" 2>/dev/null)"
    [ "$Q" = 0 ] && ok "report-only (quarantine_hits=0): CyberGate Security decides what to hold" || warn "quarantine_hits=$Q: maldet moves files itself"
    if have inotifywait && have ed && have perl && have which; then ok "inotify-tools, ed, perl and which installed"; else no "inotify-tools, ed, perl or which missing: real-time monitor cannot run (cgav install-maldet)"; fi
    if [ -n "$(monitor_pids)" ]; then ok "real-time monitor RUNNING (pid $(monitor_pids | tr '\n' ' '))"; else no "real-time monitor not running (cgav monitor start)"; fi
    if grep -q "^MONITOR_MODE=\"$MON_PATHS\"" "$MALDET_DEFAULTS" 2>/dev/null && systemctl is-enabled --quiet maldet 2>/dev/null; then ok "monitor starts on boot"; else warn "monitor does not start on boot (cgav install-maldet fixes it)"; fi
  else
    no "not installed (cgav install-maldet)"
  fi
  echo
}

# ------------------------------------------------------------------ ClamAV
cmd_install_clamav() {
  need_root; detect_os; detect_panel
  head1 "Before"; cmd_status | sed -n '/== ClamAV ==/,/== Linux/p' | sed '$d'
  head1 "Installing ClamAV"
  case "$PANEL" in
    cpanel)      ok "cPanel: using cPanel's own ClamAV package (same as WHM > cPanel > Manage Plugins > ClamAV)" ;;
    directadmin)
      if ! have clamscan && [ "${CGAV_OS_PACKAGES:-0}" != 1 ]; then
        warn "DirectAdmin installs ClamAV through CustomBuild. Run as root:"
        echo "        da build set clamav yes"
        echo "        da build clamav"
        echo "      (older installs: cd /usr/local/directadmin/custombuild && ./build set clamav yes && ./build clamav)"
        echo "      Then run: cgav status. To use the system packages anyway: CGAV_OS_PACKAGES=1 cgav install-clamav"
        return 0
      fi ;;
    plesk)       warn "Plesk: its own ClamAV comes with the Plesk Email Security extension (mail); for site files Plesk offers the Imunify extension. Installing ClamAV from the system packages for CyberGate Security." ;;
    unknown)     : ;;
    *)           ok "$PANEL_NAME: no ClamAV of its own for site files, using the system packages" ;;
  esac
  if [ -x /usr/local/cpanel/cpanel ]; then
    # cPanel ships its own ClamAV build; distribution packages would conflict with it.
    /scripts/update_local_rpm_versions --edit target_settings.clamav installed >/dev/null &&
      /scripts/check_cpanel_pkgs --fix --targets=clamav >/dev/null && ok "cPanel ClamAV installed (/usr/local/cpanel/3rdparty/bin)" ||
      die "cPanel ClamAV install failed: use WHM > Manage Plugins > ClamAV Scanner"
    head1 "After"; /usr/local/cpanel/3rdparty/bin/clamscan --version 2>/dev/null | sed 's/^/  ok    /'
    return 0
  fi
  if [ "$PKG" = apt ]; then
    apt-get update -qq >/dev/null
    pkg_install clamav clamav-daemon
  else
    pkg_install epel-release
    pkg_install clamav clamav-update clamd
    sed -i 's/^Example/#Example/' /etc/freshclam.conf /etc/clamd.d/scan.conf 2>/dev/null
    sed -i 's|^#LocalSocket .*|LocalSocket /run/clamd.scan/clamd.sock|' /etc/clamd.d/scan.conf 2>/dev/null
    have setsebool && setsebool -P antivirus_can_scan_system 1 2>/dev/null
  fi
  ok "packages installed"
  systemctl stop "$FRESH_SVC" 2>/dev/null
  freshclam --quiet && ok "signatures downloaded" || warn "freshclam reported a problem (often a temporary mirror limit; it retries on its own)"
  systemctl enable --now "$FRESH_SVC" >/dev/null 2>&1 && ok "signature updates enabled"
  systemctl enable --now "$CLAMD_SVC" >/dev/null 2>&1 && ok "scanner service $CLAMD_SVC started"
  sleep 5
  head1 "After"; cmd_status | sed -n '/== ClamAV ==/,/== Linux/p' | sed '$d'
  echo "  Next: cgav test   (then turn on 'Also scan uploads with ClamAV' in CyberGate Security > Settings > Advanced > Antivirus engines)"
}

# ------------------------------------------------------------------ maldet
cmd_install_maldet() {
  need_root; detect_os
  [ -n "$(sites_list)" ] || die "No site watched yet. Run: cgav sites   then   cgav add-site /path/to/wordpress (or cgav add-all)"
  head1 "Before"; cmd_status | sed -n '/== Linux Malware Detect ==/,$p'
  head1 "Installing Linux Malware Detect"
  # maldet needs perl; its real-time monitor needs inotifywait, ed and which (it looks ed up
  # with which). Minimal servers often lack them.
  if have inotifywait && have ed && have perl && have which; then ok "inotify-tools, ed, perl and which already installed"; else
    [ "$PKG" = apt ] || pkg_install epel-release
    pkg_install inotify-tools ed perl which && ok "inotify-tools, ed, perl and which installed"
  fi
  if [ -x "$MALDET/maldet" ]; then ok "maldet already installed"; else
    T="$(mktemp -d)"
    ( cd "$T" && curl -fsSLO https://www.rfxn.com/downloads/maldetect-current.tar.gz && tar xzf maldetect-current.tar.gz && cd maldetect-*/ && ./install.sh >/dev/null ) && ok "maldet installed" || die "maldet download or install failed"
    rm -rf "$T"
  fi
  if "$MALDET/maldet" -u >/dev/null 2>&1 && [ -s "$MALDET/sigs/maldet.sigs.ver" ]; then ok "signatures updated"; else warn "signature update failed: see $MALDET/logs/event_log"; fi

  # Report only: CyberGate Security holds files for approval, maldet just reports.
  sed -i 's/^quarantine_hits=.*/quarantine_hits="0"/' "$MALDET/conf.maldet"
  # Use the ClamAV engine for maldet scans when ClamAV is installed (faster, more signatures).
  have clamscan && sed -i 's/^scan_clamscan=.*/scan_clamscan="1"/' "$MALDET/conf.maldet"
  ok "report-only mode set (quarantine_hits=0)"

  local s
  while IFS= read -r s; do grep -qx "$s" "$MON_PATHS" 2>/dev/null || echo "$s" >> "$MON_PATHS"; done < <(sites_list)
  # Older maldet versions read the monitor mode from conf.maldet instead of the service defaults.
  sed -i "s|^default_monitor_mode=.*|default_monitor_mode=\"$MON_PATHS\"|" "$MALDET/conf.maldet"
  ok "$(sites_list | wc -l | tr -d ' ') site(s) in monitor_paths"

  # Start on boot through maldet's own service.
  touch "$MALDET_DEFAULTS"
  if grep -q '^MONITOR_MODE=' "$MALDET_DEFAULTS"; then
    sed -i "s|^MONITOR_MODE=.*|MONITOR_MODE=\"$MON_PATHS\"|" "$MALDET_DEFAULTS"
  else
    echo "MONITOR_MODE=\"$MON_PATHS\"" >> "$MALDET_DEFAULTS"
  fi
  systemctl daemon-reload 2>/dev/null
  systemctl enable maldet >/dev/null 2>&1 && ok "monitor starts on boot"

  cmd_monitor restart >/dev/null
  sleep 3
  head1 "After"; cmd_status | sed -n '/== Linux Malware Detect ==/,$p'
  echo "  Next: cgav test"
}

# ------------------------------------------------------------------ monitor
cmd_monitor() {
  need_root
  case "${1:-status}" in
    start)
      if [ -n "$(monitor_pids)" ]; then ok "monitor already running"; return 0; fi
      { have inotifywait && have ed && have perl && have which; } || die "inotify-tools, ed, perl or which missing: run cgav install-maldet"
      if [ -d /run/systemd/system ] && systemctl is-enabled --quiet maldet 2>/dev/null; then
        systemctl start maldet 2>/dev/null; sleep 3
      fi
      if [ -z "$(monitor_pids)" ]; then
        # Own session: maldet stops the monitor by killing its whole process group,
        # which would otherwise include this shell.
        setsid "$MALDET/maldet" --monitor "$MON_PATHS" >/dev/null 2>&1 </dev/null
      fi
      # Setting up recursive watches takes a while on big sites.
      for _ in $(seq 1 30); do [ -n "$(monitor_pids)" ] && break; sleep 1; done
      [ -n "$(monitor_pids)" ] && ok "monitor running" || no "monitor did not start: cgav logs" ;;
    stop)
      if systemctl is-active --quiet maldet 2>/dev/null; then systemctl stop maldet 2>/dev/null; fi
      "$MALDET/maldet" --kill-monitor >/dev/null 2>&1
      # Wait until it has really exited, or a start right after sees the old process.
      for _ in $(seq 1 15); do [ -z "$(monitor_pids)" ] && break; sleep 1; done
      [ -d /run/systemd/system ] && systemctl reset-failed maldet >/dev/null 2>&1
      [ -z "$(monitor_pids)" ] && ok "monitor stopped" || warn "monitor still running" ;;
    restart) cmd_monitor stop; cmd_monitor start ;;
    reload)
      # "maldet --monitor reload" re-reads only the settings, not monitor_paths, so a
      # changed site list needs a restart (a few seconds without watching).
      cmd_monitor stop >/dev/null; cmd_monitor start
      [ -n "$(monitor_pids)" ] && ok "monitor watches $(grep -c . "$MON_PATHS" 2>/dev/null) folder(s) from $MON_PATHS" ;;
    status)  [ -n "$(monitor_pids)" ] && ok "monitor RUNNING (pid $(monitor_pids | tr '\n' ' '))" || no "monitor not running" ;;
    *) die "Usage: cgav monitor start|stop|restart|status|reload" ;;
  esac
}

# ------------------------------------------------------------------ test
cmd_test() {
  need_root; need_site "${1:-}"
  F="$TARGET/cgav-eicar-test.txt"
  head1 "EICAR test (harmless standard test file, removed afterwards)"
  curl -fsS -o "$F" https://secure.eicar.org/eicar.com.txt || die "Could not download the test file"
  # maldet skips root-owned files by default, so give the file the site owner like a real upload.
  chown "$(stat -c %u:%g "$TARGET")" "$F" 2>/dev/null
  if have clamdscan && clamdscan --fdpass --no-summary "$F" 2>/dev/null | grep -q FOUND; then ok "ClamAV (daemon) detects it"
  elif have clamscan && clamscan --no-summary "$F" 2>/dev/null | grep -q FOUND; then ok "ClamAV detects it (daemon not used)"
  elif have clamscan; then no "ClamAV did not detect it"
  else warn "ClamAV not installed"; fi
  if [ -n "$(monitor_pids)" ]; then
    echo "  waiting up to 60 s for maldet's real-time monitor..."
    for _ in $(seq 1 12); do
      grep -q "cgav-eicar-test" "$MALDET/logs/event_log" 2>/dev/null && break
      sleep 5
    done
    grep -q "cgav-eicar-test" "$MALDET/logs/event_log" 2>/dev/null && ok "maldet monitor reported it" || warn "maldet has not reported it yet (it batches changes; check cgav logs in a minute)"
  elif [ -x "$MALDET/maldet" ]; then
    "$MALDET/maldet" -a "$F" 2>/dev/null | grep -qiE 'malware hits [1-9]' && ok "maldet scan detects it" || no "maldet did not detect it"
  fi
  rm -f "$F"; ok "test file removed"
}

# ------------------------------------------------------------------ update / scan / logs
cmd_update() {
  need_root; detect_os
  if have freshclam; then systemctl stop "$FRESH_SVC" 2>/dev/null; freshclam --quiet && ok "ClamAV signatures updated"; systemctl start "$FRESH_SVC" 2>/dev/null; fi
  [ -x "$MALDET/maldet" ] && "$MALDET/maldet" -u >/dev/null 2>&1 && ok "maldet signatures updated"
  [ -x "$MALDET/maldet" ] && "$MALDET/maldet" -d >/dev/null 2>&1 && ok "maldet itself up to date"
}

cmd_scan() {
  need_root
  [ -x "$MALDET/maldet" ] || die "maldet not installed: cgav install-maldet"
  local s
  if [ "${1:-}" = all ]; then
    while IFS= read -r s; do cmd_scan "$s"; done < <(sites_list)
    return 0
  fi
  need_site "${1:-}"
  head1 "Scanning $TARGET (report only, nothing is moved)"
  "$MALDET/maldet" -a "$TARGET" | grep -E 'scan completed|malware hits|report'
  echo "  Full report: $MALDET/maldet --report list   then   $MALDET/maldet --report <SCANID>"
}

cmd_logs() {
  head1 "maldet monitor (last 15)"; tail -n 15 "$MALDET/logs/inotify_log" 2>/dev/null || echo "  none"
  head1 "maldet events (last 15)"; tail -n 15 "$MALDET/logs/event_log" 2>/dev/null || echo "  none"
}

# ------------------------------------------------------------------ setup
cmd_sites() {
  head1 "WordPress sites on this server"
  local s found=0
  while IFS= read -r s; do
    found=1
    local v; v="$(site_version "$s")"
    local w; w="$(watched_by "$s")"
    if [ "$w" = "$s" ]; then ok "$s  (watched${v:+, CyberGate $v})"
    elif [ -n "$w" ]; then ok "$s  (watched as part of $w${v:+, CyberGate $v})"
    else warn "$s  (not watched${v:+, CyberGate $v}): cgav add-site $s"; fi
  done < <({ discover_sites; sites_list; } | awk '!seen[$0]++')
  [ "$found" = 1 ] || warn "none found in the usual folders: cgav add-site /path/to/wordpress"
  echo
}

cmd_add_site() {
  need_root
  [ -n "${1:-}" ] || die "Usage: cgav add-site /path/to/wordpress"
  is_wp "$1" || die "Not a WordPress folder: $1"
  local s; s="$(cd "$1" && pwd -P)"
  grep -qx "$s" "$SITES_FILE" 2>/dev/null || echo "$s" >> "$SITES_FILE"
  if [ -x "$MALDET/maldet" ]; then
    grep -qx "$s" "$MON_PATHS" 2>/dev/null || echo "$s" >> "$MON_PATHS"
    ok "watching $s"
    cmd_monitor reload
  else
    ok "added $s (install maldet to watch it: cgav install-maldet)"
  fi
}

cmd_remove_site() {
  need_root
  [ -n "${1:-}" ] || die "Usage: cgav remove-site /path/to/wordpress"
  local s; s="$( (cd "$1" 2>/dev/null && pwd -P) || echo "$1")"
  local f
  for f in "$SITES_FILE" "$MON_PATHS"; do
    [ -f "$f" ] && { grep -vx "$s" "$f" > "$f.tmp"; cat "$f.tmp" > "$f"; rm -f "$f.tmp"; }
  done
  [ "$SITE" = "$s" ] && sed -i '/^SITE=/d' "$CONF" 2>/dev/null
  ok "stopped watching $s"
  [ -n "$(monitor_pids)" ] && cmd_monitor reload
  return 0
}

cmd_add_all() {
  need_root
  local s n=0
  while IFS= read -r s; do
    if watched_by "$s" >/dev/null; then ok "already watched: $s"; continue; fi
    cmd_add_site "$s" >/dev/null && { ok "watching $s"; n=$((n+1)); }
  done < <(discover_sites)
  [ "$n" = 0 ] && warn "no WordPress sites found in the usual folders: cgav add-site /path/to/wordpress"
  [ -n "$(monitor_pids)" ] && cmd_monitor reload
  return 0
}

cmd_self_install() {
  need_root
  install -m 0755 "$0" /usr/local/bin/cgav && ok "installed as /usr/local/bin/cgav"
  # Older versions kept one site as SITE= in $CONF: move it into the site list.
  if [ -n "$SITE" ] && is_wp "$SITE"; then grep -qx "$SITE" "$SITES_FILE" 2>/dev/null || echo "$SITE" >> "$SITES_FILE"; fi
  sed -i '/^SITE=/d' "$CONF" 2>/dev/null
  [ -n "${1:-}" ] && cmd_add_site "$1"
  echo "  Next: cgav status   (other sites on this server: cgav sites)"
}

case "${1:-help}" in
  status)          cmd_status ;;
  install-clamav)  cmd_install_clamav ;;
  install-maldet)  cmd_install_maldet ;;
  monitor)         cmd_monitor "${2:-status}" ;;
  test)            cmd_test "${2:-}" ;;
  update)          cmd_update ;;
  scan)            cmd_scan "${2:-}" ;;
  logs)            cmd_logs ;;
  sites)           cmd_sites ;;
  add-site|set-site) cmd_add_site "${2:-}" ;;
  remove-site)     cmd_remove_site "${2:-}" ;;
  add-all)         cmd_add_all ;;
  self-install)    cmd_self_install "${2:-}" ;;
  *)               sed -n '3,/^$/p' "$0" | sed 's/^# \{0,1\}//' ;;
esac

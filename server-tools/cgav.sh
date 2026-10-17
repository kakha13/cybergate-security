#!/usr/bin/env bash
#
# cgav - CyberGate antivirus helper for the server (ClamAV + Linux Malware Detect).
#
# Install once (as root):   bash cgav.sh self-install /path/to/wordpress
# Then use:                 cgav <command>
#
#   status                  what is installed and running (run before and after anything)
#   install-clamav          install ClamAV, download signatures, start the scanner service
#   install-maldet          install Linux Malware Detect + inotify-tools, watch the site in
#                           real time, start on boot, report-only (CyberGate decides)
#   monitor start|stop|status   control maldet's real-time monitor
#   test                    harmless EICAR test: both engines must report it
#   update                  update ClamAV and maldet signatures
#   scan                    scan the whole site now with maldet (and ClamAV if present)
#   logs                    last lines of the maldet monitor and event logs
#
# Every command is safe to run again: it checks what is already in place first.
# Nothing here deletes or moves site files.

set -u

CONF=/etc/cgav.conf
# shellcheck source=/dev/null
[ -f "$CONF" ] && . "$CONF"
SITE="${SITE:-}"
MALDET=/usr/local/maldetect
MON_PATHS="$MALDET/monitor_paths"

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

need_site() {
  [ -n "$SITE" ] && [ -f "$SITE/wp-config.php" ] && return 0
  die "WordPress path unknown. Run: cgav set-site /path/to/wordpress"
}

monitor_pids() { pgrep -f 'inotifywait.*maldetect' 2>/dev/null; }

# ------------------------------------------------------------------ status
cmd_status() {
  detect_os
  head1 "Site"
  if [ -n "$SITE" ] && [ -f "$SITE/wp-config.php" ]; then ok "WordPress: $SITE"; else warn "WordPress path not set (cgav set-site /path/to/wordpress)"; fi

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
    if [ -n "$SITE" ] && grep -qx "$SITE" "$MON_PATHS" 2>/dev/null; then ok "site is in monitor_paths"; elif [ -n "$SITE" ]; then warn "site not in $MON_PATHS"; fi
    if grep -q "^MONITOR_MODE=\"$MON_PATHS\"" "$MALDET_DEFAULTS" 2>/dev/null && systemctl is-enabled --quiet maldet 2>/dev/null; then ok "monitor starts on boot"; else warn "monitor does not start on boot (cgav install-maldet fixes it)"; fi
  else
    no "not installed (cgav install-maldet)"
  fi
  echo
}

# ------------------------------------------------------------------ ClamAV
cmd_install_clamav() {
  need_root; detect_os
  head1 "Before"; cmd_status | sed -n '/== ClamAV ==/,/== Linux/p' | sed '$d'
  head1 "Installing ClamAV"
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
  need_root; detect_os; need_site
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

  grep -qx "$SITE" "$MON_PATHS" 2>/dev/null || echo "$SITE" >> "$MON_PATHS"
  # Older maldet versions read the monitor mode from conf.maldet instead of the service defaults.
  sed -i "s|^default_monitor_mode=.*|default_monitor_mode=\"$MON_PATHS\"|" "$MALDET/conf.maldet"
  ok "site added to monitor_paths"

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
        sleep 3
      fi
       [ -n "$(monitor_pids)" ] && ok "monitor running" || no "monitor did not start: cgav logs" ;;
    stop)
      if systemctl is-active --quiet maldet 2>/dev/null; then systemctl stop maldet 2>/dev/null; fi
      "$MALDET/maldet" --kill-monitor >/dev/null 2>&1
      sleep 2; [ -z "$(monitor_pids)" ] && ok "monitor stopped" || warn "monitor still running" ;;
    restart) cmd_monitor stop; cmd_monitor start ;;
    status)  [ -n "$(monitor_pids)" ] && ok "monitor RUNNING (pid $(monitor_pids | tr '\n' ' '))" || no "monitor not running" ;;
    *) die "Usage: cgav monitor start|stop|restart|status" ;;
  esac
}

# ------------------------------------------------------------------ test
cmd_test() {
  need_root; need_site
  F="$SITE/cgav-eicar-test.txt"
  head1 "EICAR test (harmless standard test file, removed afterwards)"
  curl -fsS -o "$F" https://secure.eicar.org/eicar.com.txt || die "Could not download the test file"
  # maldet skips root-owned files by default, so give the file the site owner like a real upload.
  chown "$(stat -c %u:%g "$SITE")" "$F" 2>/dev/null
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
  need_root; need_site
  [ -x "$MALDET/maldet" ] || die "maldet not installed: cgav install-maldet"
  head1 "Scanning $SITE (report only, nothing is moved)"
  "$MALDET/maldet" -a "$SITE" | grep -E 'scan completed|malware hits|report'
  echo "  Full report: $MALDET/maldet --report list   then   $MALDET/maldet --report <SCANID>"
}

cmd_logs() {
  head1 "maldet monitor (last 15)"; tail -n 15 "$MALDET/logs/inotify_log" 2>/dev/null || echo "  none"
  head1 "maldet events (last 15)"; tail -n 15 "$MALDET/logs/event_log" 2>/dev/null || echo "  none"
}

# ------------------------------------------------------------------ setup
cmd_set_site() {
  need_root
  [ -f "${1:-}/wp-config.php" ] || die "Not a WordPress folder: ${1:-<empty>}"
  SITE="$(cd "$1" && pwd)"
  echo "SITE=\"$SITE\"" > "$CONF"
  ok "site set to $SITE (saved in $CONF)"
}

cmd_self_install() {
  need_root
  install -m 0755 "$0" /usr/local/bin/cgav && ok "installed as /usr/local/bin/cgav"
  [ -n "${1:-}" ] && cmd_set_site "$1"
  echo "  Start with: cgav status"
}

case "${1:-help}" in
  status)          cmd_status ;;
  install-clamav)  cmd_install_clamav ;;
  install-maldet)  cmd_install_maldet ;;
  monitor)         cmd_monitor "${2:-status}" ;;
  test)            cmd_test ;;
  update)          cmd_update ;;
  scan)            cmd_scan ;;
  logs)            cmd_logs ;;
  set-site)        cmd_set_site "${2:-}" ;;
  self-install)    cmd_self_install "${2:-}" ;;
  *)               sed -n '3,20p' "$0" | sed 's/^# \{0,1\}//' ;;
esac

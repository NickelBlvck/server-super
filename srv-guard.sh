#!/usr/bin/env bash
# srv-guard — мини-скрипт защиты серверов Ubuntu/Debian.
#   базовая настройка · swap · CrowdSec + Console · fail2ban (резерв) · Psiphon (vps-psiphon)
#
#   sudo bash srv-guard.sh               меню
#   sudo bash srv-guard.sh <команда>     один пункт без меню (см. --help)
#
# Сетевые загрузки проверяются: ключ CrowdSec — по полному отпечатку,
# установщик vps-psiphon — по закреплённому коммиту и sha256.

set -uo pipefail

# ─── закреплённые версии и отпечатки ─────────────────────────────────────────
# При обновлении vps-psiphon пересчитай оба значения (см. README).
VPS_PSIPHON_REF="c28177d18a5337419616137400ed0462cf43eb51"
VPS_PSIPHON_SHA256="e41b9aeed9f5f11a2a6f1fe2103a74e075f1703a01bc4d1e5cf734e8cf30f4f3"
CROWDSEC_KEY_URL="https://packagecloud.io/crowdsec/crowdsec/gpgkey"
CROWDSEC_KEY_FPR="6A89E3C2303A901A889971D3376ED5326E93CD0C"
CROWDSEC_KEYRING="/etc/apt/keyrings/crowdsec-archive-keyring.gpg"
CROWDSEC_LIST="/etc/apt/sources.list.d/crowdsec.list"
PSI_CLI="/usr/local/sbin/vps-psiphon"
PSI_ENV="${PSI_ENV:-/etc/default/vps-psiphon}"
SHORTCUT="${SS_PATH:-/usr/local/bin/SS}"

export DEBIAN_FRONTEND=noninteractive
# needrestart только перечисляет сервисы, которым нужен рестарт, и не трогает их:
# на VPN-ноде внезапный рестарт xray рвёт всех клиентов.
export NEEDRESTART_MODE=l

# ─── вывод и ввод ────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  C_OK=$'\e[32m'; C_WARN=$'\e[33m'; C_ERR=$'\e[31m'; C_BOLD=$'\e[1m'; C_OFF=$'\e[0m'
else
  C_OK=""; C_WARN=""; C_ERR=""; C_BOLD=""; C_OFF=""
fi

step() { printf '\n%s==> %s%s\n' "$C_BOLD" "$*" "$C_OFF"; }
ok()   { printf '%s[ok]%s %s\n' "$C_OK" "$C_OFF" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_WARN" "$C_OFF" "$*" >&2; }
err()  { printf '%s[x]%s %s\n' "$C_ERR" "$C_OFF" "$*" >&2; }
die()  { err "$*"; exit 1; }

ask() {        # ask "вопрос" [по умолчанию] → ответ в stdout
  local answer=""
  read -r -p "$1${2:+ [$2]}: " answer || true
  printf '%s' "${answer:-${2:-}}"
}

secret() {     # secret "вопрос" → ввод без эха
  local value=""
  read -r -s -p "$1: " value || true
  printf '\n' >&2
  printf '%s' "$value"
}

confirm() {    # confirm "вопрос" → 0 при «да»
  local answer=""
  read -r -p "$1 [y/N]: " answer || true
  case "$answer" in y|Y|yes|д|Д|да|Да) return 0 ;; *) return 1 ;; esac
}

pause() { read -r -p "Enter — назад в меню " _ || true; }

# Каждый шаг идёт в подоболочке: die() завершает только его, меню продолжает работать.
run_action() {
  local rc=0
  ( "$@" ) || rc=$?
  (( rc == 0 )) || warn "Шаг завершился с ошибкой: $1 (код $rc)"
  return "$rc"
}

# ─── проверки окружения ──────────────────────────────────────────────────────
OS_ID="" OS_CODENAME="" OS_PRETTY=""

require_root() {
  [[ $EUID -eq 0 ]] || die "Запусти от root: sudo bash $0"
}

require_supported_os() {
  [[ -r /etc/os-release ]] || die "Нет /etc/os-release — не могу определить систему"
  # shellcheck source=/dev/null
  . /etc/os-release
  case "${ID:-}" in
    ubuntu|debian) ;;
    *) die "Поддерживаются только Ubuntu и Debian (сейчас: ${ID:-неизвестно})" ;;
  esac
  command -v apt-get >/dev/null || die "Нет apt-get"
  OS_ID="$ID"
  OS_CODENAME="${VERSION_CODENAME:-}"
  OS_PRETTY="${PRETTY_NAME:-$ID}"
}

# Фоновые unattended-upgrades на свежем VPS держат dpkg-lock: ждём, а не падаем.
wait_dpkg() {
  for _ in $(seq 1 60); do
    fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock >/dev/null 2>&1 || return 0
    sleep 5
  done
  die "dpkg занят дольше 5 минут: ps aux | grep -E 'apt|dpkg'"
}

apt_install() {
  wait_dpkg
  apt-get install -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "$@"
}

# ─── 1. базовая настройка ────────────────────────────────────────────────────
base_setup() {
  step "Базовая настройка: apt update / upgrade, cron, mc, wget"
  wait_dpkg
  apt-get update || die "apt-get update завершился с ошибкой"
  apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade \
    || die "apt-get upgrade завершился с ошибкой"
  apt_install cron mc wget || die "Не удалось установить cron, mc, wget"
  ok "Система обновлена, установлены cron, mc, wget"
  if [[ -f /var/run/reboot-required ]]; then
    warn "Нужна перезагрузка: обновилось ядро или базовые библиотеки"
  fi
}

# ─── 2. swap-файл ────────────────────────────────────────────────────────────
setup_swap() {
  step "Swap-файл"
  if [[ -n "$(swapon --show --noheadings)" ]]; then
    ok "Swap уже активен, ничего не меняю:"
    swapon --show
    return 0
  fi
  if [[ -e /swapfile ]]; then
    die "/swapfile уже есть, но не активен — разберись с ним вручную и запусти снова"
  fi

  local size num unit mb
  size="$(ask "Размер swap (например 2G, 512M)" 2G)"
  size="${size^^}"
  [[ "$size" =~ ^[1-9][0-9]{0,3}[MG]$ ]] || die "Неверный размер «$size»: нужно число и M или G"
  num="${size%?}"
  unit="${size: -1}"
  mb="$num"
  [[ "$unit" == G ]] && mb=$(( num * 1024 ))

  if ! fallocate -l "${mb}M" /swapfile 2>/dev/null; then
    dd if=/dev/zero of=/swapfile bs=1M count="$mb" status=none \
      || { rm -f /swapfile; die "Не удалось создать /swapfile (не хватает места?)"; }
  fi
  chmod 600 /swapfile
  mkswap /swapfile >/dev/null || { rm -f /swapfile; die "mkswap не сработал"; }
  swapon /swapfile || { rm -f /swapfile; die "swapon не сработал: файловая система не подходит для swap-файла"; }
  grep -qE '^/swapfile[[:space:]]' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
  ok "Swap ${size} включён и прописан в /etc/fstab"
  swapon --show
}

# ─── 3. CrowdSec ─────────────────────────────────────────────────────────────
# Из скачанного файла берём РОВНО один ключ с отпечатком CROWDSEC_KEY_FPR и кладём в keyring.
# Всё остальное, что пришло в ответе, не используем.
import_pinned_key() {  # import_pinned_key <файл с ключом> <куда положить keyring>
  local src="$1" out="$2" home got=""
  home="$(mktemp -d)" || return 1
  chmod 700 "$home"
  GNUPGHOME="$home" gpg --batch --quiet --import "$src" >/dev/null 2>&1
  GNUPGHOME="$home" gpg --batch --yes --export "$CROWDSEC_KEY_FPR" > "$out.tmp" 2>/dev/null
  if [[ -s "$out.tmp" ]]; then
    got="$(gpg --batch --with-colons --show-keys "$out.tmp" 2>/dev/null | awk -F: '$1=="fpr"{print $10; exit}')"
  fi
  gpgconf --homedir "$home" --kill all >/dev/null 2>&1
  rm -rf "$home"
  if [[ "$got" != "$CROWDSEC_KEY_FPR" ]]; then
    rm -f "$out.tmp"
    return 1
  fi
  mv -f "$out.tmp" "$out" && chmod 0644 "$out"
}

crowdsec_repo() {
  step "CrowdSec: APT-репозиторий (ключ проверяется по отпечатку)"
  command -v gpg >/dev/null 2>&1 || apt_install gnupg >/dev/null || die "Не удалось установить gnupg"
  local tmp cand path suite ok_repo=0
  local -a cands=("any any")
  [[ -n "$OS_CODENAME" ]] && cands+=("$OS_ID $OS_CODENAME")

  tmp="$(mktemp -d)" || die "mktemp не сработал"
  if ! curl -fsSL --connect-timeout 10 --max-time 60 -o "$tmp/key.asc" "$CROWDSEC_KEY_URL"; then
    rm -rf "$tmp"
    die "Не скачивается ключ CrowdSec: $CROWDSEC_KEY_URL"
  fi
  install -d -m 0755 "$(dirname "$CROWDSEC_KEYRING")"
  if ! import_pinned_key "$tmp/key.asc" "$CROWDSEC_KEYRING"; then
    rm -rf "$tmp"
    die "Отпечаток ключа CrowdSec не совпал с $CROWDSEC_KEY_FPR — отказываюсь"
  fi
  rm -rf "$tmp"

  for cand in "${cands[@]}"; do
    read -r path suite <<<"$cand"
    printf 'deb [signed-by=%s] https://packagecloud.io/crowdsec/crowdsec/%s %s main\n' \
      "$CROWDSEC_KEYRING" "$path" "$suite" > "$CROWDSEC_LIST"
    # обновляем только свой список: битый сторонний репозиторий на сервере не должен ломать проверку
    if apt-get update -qq -o Dir::Etc::sourcelist="$CROWDSEC_LIST" \
        -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0; then
      ok_repo=1
      break
    fi
    warn "Вариант репозитория «$path $suite» не отвечает, пробую следующий"
  done
  if (( ! ok_repo )); then
    rm -f "$CROWDSEC_LIST"
    die "Ни один вариант репозитория CrowdSec не поднялся"
  fi
  apt-get update -qq >/dev/null 2>&1 || true
  ok "Репозиторий CrowdSec подключён ($path $suite)"
}

crowdsec_install() {
  crowdsec_repo
  step "CrowdSec: движок, firewall-bouncer (nftables), сценарии SSH"
  apt_install crowdsec crowdsec-firewall-bouncer-nftables || die "Не удалось установить crowdsec и bouncer"
  cscli hub update >/dev/null 2>&1 || warn "cscli hub update не отработал"
  cscli collections install crowdsecurity/sshd crowdsecurity/linux >/dev/null 2>&1 \
    || warn "Коллекции sshd/linux не поставились — позже: cscli collections install crowdsecurity/sshd"

  mkdir -p /etc/crowdsec/acquis.d
  cat > /etc/crowdsec/acquis.d/srv-guard-sshd.yaml <<'EOF'
# Логи SSH из journald: sshd пишет и через ssh.service, и через ssh.socket (Ubuntu 24.04+)
source: journalctl
journalctl_filter:
  - "_COMM=sshd"
  - "_COMM=sshd-session"
labels:
  type: syslog
EOF

  systemctl enable crowdsec >/dev/null 2>&1 || die "Не удалось включить crowdsec в автозапуск"
  systemctl restart crowdsec || die "crowdsec не запустился: journalctl -u crowdsec -n 50"
  systemctl enable --now crowdsec-firewall-bouncer >/dev/null 2>&1 \
    || warn "bouncer не запустился: systemctl status crowdsec-firewall-bouncer"
  ok "CrowdSec и bouncer запущены"
  echo "Проверка: cscli metrics show acquisition — после неудачного входа по SSH строки sshd должны расти"
}

crowdsec_console() {
  step "CrowdSec Console: подключение сервера к общей панели"
  command -v cscli >/dev/null 2>&1 || die "CrowdSec не установлен — сначала пункт «CrowdSec»"
  echo "Enroll-ключ возьми в веб-консоли https://app.crowdsec.net (добавление нового движка)."
  local key
  key="$(secret "Enroll-ключ")"
  [[ -n "$key" ]] || die "Ключ не введён"
  cscli console enroll "$key" \
    || die "cscli console enroll не сработал: ключ неверный или нет доступа к app.crowdsec.net"
  systemctl reload crowdsec >/dev/null 2>&1 || systemctl restart crowdsec
  ok "Сервер отправил запрос в CrowdSec Console"
  echo "Если запрос ждёт подтверждения — подтверди движок в app.crowdsec.net, иначе сервер в панели не появится."
}

# ─── 4. fail2ban (резерв) ────────────────────────────────────────────────────
fail2ban_install() {
  step "fail2ban: резервная защита SSH"
  apt_install fail2ban || die "Не удалось установить fail2ban"

  local port="${SSH_PORT:-}"
  [[ -n "$port" ]] || port="$(sshd -T 2>/dev/null | awk '$1=="port"{print $2; exit}')"
  if ! [[ "$port" =~ ^[0-9]+$ ]]; then
    warn "SSH-порт не определился, беру 22 (если SSH на другом порту — SSH_PORT=... bash srv-guard.sh fail2ban)"
    port=22
  fi

  cat > /etc/fail2ban/jail.d/srv-guard.conf <<EOF
[sshd]
enabled  = true
backend  = auto
port     = $port
maxretry = 4
findtime = 10m
bantime  = 1h
EOF
  systemctl enable fail2ban >/dev/null 2>&1 || die "Не удалось включить fail2ban в автозапуск"
  systemctl restart fail2ban || die "fail2ban не запустился: journalctl -u fail2ban -n 50"
  ok "fail2ban: SSH-порт $port, 4 попытки за 10 минут → бан на 1 час"
  if systemctl is-active --quiet crowdsec; then
    warn "CrowdSec тоже активен. Для SSH обычно хватает одной системы: если оставляешь fail2ban, останови CrowdSec: systemctl disable --now crowdsec-firewall-bouncer crowdsec"
  fi
}

# ─── 5. Psiphon через vps-psiphon ────────────────────────────────────────────
psiphon_install() {  # psiphon_install [страна[,страна…]]
  step "Psiphon: установка vps-psiphon (закреплённая версия ${VPS_PSIPHON_REF:0:7})"
  local region="${1:-${PSIPHON_REGION:-}}"
  if [[ -z "$region" ]]; then
    region="$(ask "Страна выхода, ISO-код (DE; пул через запятую DE,NL; пусто — авто)" "")"
  fi
  region="${region^^}"
  [[ -z "$region" || "$region" =~ ^[A-Z]{2}(,[A-Z]{2})*$ ]] \
    || die "Неверный формат страны «$region»: пример DE или DE,NL,FR"

  if ! command -v docker >/dev/null 2>&1; then
    apt_install docker.io || die "Не удалось установить docker.io (нужен для vps-psiphon)"
  fi
  systemctl enable --now docker >/dev/null 2>&1 || die "docker не запустился"
  docker info >/dev/null 2>&1 || die "docker не отвечает (проверь: docker info)"

  local tmp file got rc
  tmp="$(mktemp -d)" || die "mktemp не сработал"
  file="$tmp/psiphon_install.sh"
  if ! curl -fsSL --connect-timeout 10 --max-time 60 -o "$file" \
      "https://raw.githubusercontent.com/Chara-Freedom/vps-psiphon/$VPS_PSIPHON_REF/psiphon_install.sh"; then
    rm -rf "$tmp"
    die "Не скачивается установщик vps-psiphon"
  fi
  got="$(sha256sum "$file" | awk '{print $1}')"
  if [[ "$got" != "$VPS_PSIPHON_SHA256" ]]; then
    rm -rf "$tmp"
    die "sha256 установщика не совпал (получен $got) — не запускаю"
  fi

  local -a args=()
  [[ -n "$region" ]] && args+=(--region "$region")
  bash "$file" "${args[@]}"
  rc=$?
  rm -rf "$tmp"
  (( rc == 0 )) || die "Установщик vps-psiphon завершился с кодом $rc"
  ok "vps-psiphon установлен"
  psiphon_outbound
}

psi_run() {  # psi_run <команда vps-psiphon> [аргументы]
  [[ -x "$PSI_CLI" ]] || die "vps-psiphon не установлен — сначала установка"
  "$PSI_CLI" "$@"
}

psiphon_outbound() {
  [[ -r "$PSI_ENV" ]] || die "Нет $PSI_ENV — vps-psiphon не установлен"
  local bind port
  bind="$(sed -n 's/^BIND=//p' "$PSI_ENV" | head -n1)"
  port="$(sed -n 's/^SOCKS_PORT=//p' "$PSI_ENV" | head -n1)"
  [[ -n "$bind" && "$port" =~ ^[0-9]+$ ]] || die "В $PSI_ENV нет BIND или SOCKS_PORT"
  cat <<EOF

Outbound для xray (адрес SOCKS, который реально опубликован на этом хосте):

{
  "tag": "psiphon-out",
  "protocol": "socks",
  "settings": {
    "address": "$bind",
    "port": $port
  }
}

UDP через этот outbound не направлять: локальный прокси Psiphon его не поддерживает.
EOF
}

psiphon_cli() {  # psiphon_cli <действие> [аргумент]
  local cmd="${1:-status}" arg="${2:-}"
  case "$cmd" in
    install)   psiphon_install "$arg" ;;
    status)    psi_run ;;
    rotate)    psi_run rotate ;;
    region)
      [[ -n "$arg" ]] || arg="$(ask "Новая страна выхода (ISO, например JP)" "")"
      arg="${arg^^}"
      [[ "$arg" =~ ^[A-Z]{2}$ ]] || die "Нужен код страны из двух букв, например JP"
      psi_run region "$arg" ;;
    pool)
      [[ -n "$arg" ]] || arg="$(ask "Страны для ротации через пробел (DE NL FR), пусто — очистить" "")"
      arg="${arg^^}"
      [[ -z "$arg" || "$arg" =~ ^[A-Z]{2}( [A-Z]{2})*$ ]] || die "Формат: DE NL FR"
      psi_run pool "$arg" ;;
    logs)      psi_run logs "${arg:-50}" ;;
    watchdog)  psi_run watchdog "${arg:-30}" ;;
    outbound)  psiphon_outbound ;;
    uninstall)
      if confirm "Удалить vps-psiphon полностью (контейнер, юниты, CLI)?"; then
        psi_run uninstall
      else
        printf 'Отменено.\n'
      fi ;;
    *) die "Неизвестное действие psiphon: $cmd (см. --help)" ;;
  esac
}

# ─── состояние ───────────────────────────────────────────────────────────────
show_status() {
  step "Состояние: $OS_PRETTY"
  free -h | sed -n '2,3p'
  echo
  local svc
  for svc in crowdsec crowdsec-firewall-bouncer fail2ban docker; do
    printf '  %-28s %s\n' "$svc" "$(systemctl is-active "$svc" 2>/dev/null)"
  done
  if command -v cscli >/dev/null 2>&1; then
    echo; echo "CrowdSec — решения (до 20):"
    cscli decisions list 2>/dev/null | head -n 20
    echo; echo "CrowdSec — источники логов:"
    cscli metrics show acquisition 2>/dev/null | head -n 20
  fi
  if [[ -x "$PSI_CLI" ]]; then
    echo; echo "Psiphon:"
    "$PSI_CLI" 2>/dev/null | head -n 20
  fi
  return 0
}

# ─── меню ────────────────────────────────────────────────────────────────────
psiphon_menu() {
  while true; do
    cat <<EOF

 Psiphon (vps-psiphon)
  1) Установить (страну выхода можно указать сразу)
  2) Состояние
  3) Ротация выхода: новый туннель, другой IP
  4) Сменить страну выхода
  5) Пул стран для ротации
  6) Логи клиента Psiphon
  7) Журнал watchdog
  8) Outbound для xray
  9) Удалить
  0) Назад
EOF
    read -r -p "Выбор: " choice || return 0
    case "$choice" in
      1) run_action psiphon_cli install ;;
      2) run_action psiphon_cli status ;;
      3) run_action psiphon_cli rotate ;;
      4) run_action psiphon_cli region ;;
      5) run_action psiphon_cli pool ;;
      6) run_action psiphon_cli logs ;;
      7) run_action psiphon_cli watchdog ;;
      8) run_action psiphon_cli outbound ;;
      9) run_action psiphon_cli uninstall ;;
      0) return 0 ;;
      "") continue ;;
      *) warn "Нет такого пункта: $choice"; continue ;;
    esac
    pause
  done
}

menu() {
  while true; do
    cat <<EOF

 srv-guard · $OS_PRETTY
  1) Базовая настройка: apt update/upgrade, cron, mc, wget
  2) Swap-файл
  3) CrowdSec + firewall-bouncer
  4) CrowdSec Console: подключить сервер к панели
  5) fail2ban: резерв для SSH
  6) Psiphon (vps-psiphon)
  7) Состояние
  0) Выход
EOF
    read -r -p "Выбор: " choice || { echo; exit 0; }
    case "$choice" in
      1) run_action base_setup ;;
      2) run_action setup_swap ;;
      3) run_action crowdsec_install ;;
      4) run_action crowdsec_console ;;
      5) run_action fail2ban_install ;;
      6) psiphon_menu; continue ;;
      7) run_action show_status ;;
      0) exit 0 ;;
      "") continue ;;
      *) warn "Нет такого пункта: $choice"; continue ;;
    esac
    pause
  done
}

# ─── команда SS ──────────────────────────────────────────────────────────────
# Один раз: sudo bash srv-guard.sh install. Дальше `SS` запускает файл из этого же каталога,
# поэтому после git pull переустанавливать ничего не нужно.
install_shortcut() {
  local self
  self="$(readlink -f "${BASH_SOURCE[0]}")"
  if [[ ! -f "$self" || "$self" == /dev/* ]]; then
    die "Запусти установку из сохранённого файла (git clone / git pull), а не через пайп"
  fi
  if [[ -e "$SHORTCUT" ]] && ! grep -q 'srv-guard.sh install' "$SHORTCUT"; then
    die "$SHORTCUT уже занят другой командой — переименуй её или удали вручную"
  fi
  {
    printf '#!/usr/bin/env bash\n# Создано командой: srv-guard.sh install. Не править вручную.\nSCRIPT=%q\n' "$self"
    cat <<'WRAP'
if [[ $EUID -ne 0 ]]; then exec sudo bash "$SCRIPT" "$@"; fi
exec bash "$SCRIPT" "$@"
WRAP
  } > "$SHORTCUT" || die "Не удалось записать $SHORTCUT"
  chmod 0755 "$SHORTCUT"
  ok "Команда SS установлена → $self"
  echo "Запуск: SS (без root запросит sudo). Регистр важен: SS — не то же, что системная ss."
  echo "После git pull в этом каталоге ничего переустанавливать не нужно."
}

usage() {
  cat <<'EOF'
srv-guard: защита сервера Ubuntu/Debian

  sudo bash srv-guard.sh                меню
  sudo bash srv-guard.sh <команда>

Команды:
  install               создать команду SS (один раз; после git pull ничего не нужно)
  base                  apt update/upgrade, cron, mc, wget
  swap                  swap-файл /swapfile (спросит размер)
  crowdsec              CrowdSec + firewall-bouncer (nftables) + сценарии SSH
  console               подключить сервер к CrowdSec Console (спросит enroll-ключ)
  fail2ban              fail2ban для SSH (резерв)
  status                состояние
  psiphon <действие>    install [КОД[,КОД…]] | status | rotate | region КОД |
                        pool "DE NL FR" | logs [n] | watchdog [n] | outbound | uninstall

Переменные окружения:
  SSH_PORT=2222         порт SSH для fail2ban (по умолчанию — из sshd -T)
  PSIPHON_REGION=DE     страна выхода для psiphon install
EOF
}

main() {
  case "${1:-}" in
    -h|--help|help) usage; return 0 ;;
  esac
  require_root
  require_supported_os
  if (( $# == 0 )); then
    menu
    return 0
  fi
  case "$1" in
    install)  run_action install_shortcut ;;
    base)     run_action base_setup ;;
    swap)     run_action setup_swap ;;
    crowdsec) run_action crowdsec_install ;;
    console)  run_action crowdsec_console ;;
    fail2ban) run_action fail2ban_install ;;
    status)   run_action show_status ;;
    psiphon)  shift; run_action psiphon_cli "$@" ;;
    *)        usage; exit 1 ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi

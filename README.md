# srv-guard

Мини-скрипт для защиты серверов Ubuntu/Debian. Один файл, без конфигов на диске.

Что умеет:

- **base**: `apt update`, `apt upgrade`, установка `cron`, `mc`, `wget`.
- **swap**: создание `/swapfile` (спросит размер), запись в `/etc/fstab`.
- **crowdsec**: CrowdSec + `crowdsec-firewall-bouncer-nftables`, коллекции `sshd` и `linux`.
- **console**: подключение сервера к [CrowdSec Console](https://app.crowdsec.net). Это общая панель, где видны все подключённые серверы.
- **fail2ban**: резерв для SSH, если CrowdSec не пойдёт.
- **psiphon**: установка и управление через [vps-psiphon](https://github.com/Chara-Freedom/vps-psiphon): страна выхода, ротация, пул стран, логи, журнал watchdog, outbound для xray, удаление.
- **status**: состояние сервисов, решения CrowdSec, источники логов, Psiphon.

Не входят (как и просили): порт node-agent, SYNPROXY, опубликованные Docker-порты, fleet auto-sync, сохранение конфига.

## Запуск

Склонируй репозиторий на сервер и запусти от root из его папки:

```bash
sudo bash srv-guard.sh
```

Без аргументов откроется меню. Можно и отдельной командой:

```bash
sudo bash srv-guard.sh base
sudo bash srv-guard.sh swap
sudo bash srv-guard.sh crowdsec
sudo bash srv-guard.sh console
sudo bash srv-guard.sh psiphon install DE
sudo bash srv-guard.sh status
```

Порядок для нового сервера: `base` → `swap` → `crowdsec` → `console` → `psiphon`. `fail2ban` ставь вместо CrowdSec, а не вместе с ним.

Enroll-ключ для `console` берётся в веб-консоли app.crowdsec.net при добавлении нового движка. Ключ вводится без эха и в скрипте нигде не сохраняется.

## Команда `SS`

На сервере, в папке склонированного репозитория, один раз:

```bash
sudo bash srv-guard.sh install
```

После этого достаточно набрать `SS`. Без root команда сама запросит sudo. После `git pull` ничего переустанавливать не нужно: `SS` запускает файл из той же папки. Если папку переместили, установку нужно повторить. Регистр важен: `SS` и системная `ss` — разные команды.

## Проверка

```bash
cscli metrics show acquisition      # строки sshd должны расти после неудачного входа
cscli decisions list                # активные баны
fail2ban-client status sshd         # если ставил fail2ban
```

Проверь на тестовом сервере: с другой машины сделай несколько неудачных попыток входа по SSH и убедись, что счётчики растут и бан срабатывает.

Скрипт **не** добавляет твой IP в allowlist. Если ошибёшься паролем или ключом несколько раз, свой адрес можно забанить. Разбан:

```bash
cscli decisions delete --ip 203.0.113.7       # CrowdSec
fail2ban-client set sshd unbanip 203.0.113.7  # fail2ban
```

## Важно

1. **CrowdSec по умолчанию банит на всех портах.** Bouncer блокирует забаненные адреса для всего входящего трафика, включая VPN-порты. На VPN-ноде это риск: community-блоклист или ложный бан адреса за CGNAT отрежет реальных клиентов. В [node-accelerator](https://github.com/jestivald/node-accelerator) это решено тем, что баны действуют только на SSH. В этом скрипте так пока не сделано.
2. **Скрипт не запускался на настоящем Ubuntu-сервере.** Проверены синтаксис, shellcheck, закреплённые хэши и логика меню, парсинга и импорта ключа. Перед продом запусти на тестовой VPS.
3. **Psiphon.** Установщик тянет образ `swarupsengupta2007/psiphon:latest` с Docker Hub без закрепления по digest, то есть доверяешь этому образу. Не ставь Psiphon на сервер в стране, от которой обходишь блокировки: upstream прямо предупреждает. По умолчанию SOCKS публикуется на адрес шлюза docker0 (обычно `172.17.0.1`), а не наружу. Проверь `ss -tlnp` после установки.
4. **Проверка подлинности.** CrowdSec: ключ репозитория ставится только если его полный отпечаток совпал с `6A89E3C2303A901A889971D3376ED5326E93CD0C`. vps-psiphon: установщик запускается только если его sha256 совпал с `VPS_PSIPHON_SHA256`. Если upstream обновился, скрипт откажется запускать его. Тогда пересчитай `VPS_PSIPHON_REF` и `VPS_PSIPHON_SHA256` в начале скрипта.
5. **Обновления ядра.** `base` использует `NEEDRESTART_MODE=l`: сервисы не перезапускаются сами, чтобы не оборвать VPN-клиентов. Если появилось уведомление о перезагрузке, сделай её в удобное время.

## Что трогает скрипт

| Что | Где |
|---|---|
| swap | `/swapfile`, `/etc/fstab` |
| CrowdSec | `/etc/apt/keyrings/crowdsec-archive-keyring.gpg`, `/etc/apt/sources.list.d/crowdsec.list`, `/etc/crowdsec/acquis.d/srv-guard-sshd.yaml` |
| fail2ban | `/etc/fail2ban/jail.d/srv-guard.conf` |
| Psiphon | пакет `docker.io`, `/etc/default/vps-psiphon`, `/usr/local/sbin/vps-psiphon*`, юниты systemd |

## Откат

```bash
systemctl disable --now crowdsec-firewall-bouncer crowdsec
apt purge -y crowdsec crowdsec-firewall-bouncer-nftables
apt purge -y fail2ban
swapoff /swapfile && rm -f /swapfile && sed -i '\#^/swapfile#d' /etc/fstab
sudo bash srv-guard.sh psiphon uninstall
```

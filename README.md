# Firewall-UI

Автономная веб-панель управления системным файрволлом Linux. Проект основан на firewall-логике и визуальном стиле [SawaMEN/3x-ui](https://github.com/SawaMEN/3x-ui), но работает как отдельный сервис.

## Возможности

- UFW, firewalld, nftables и iptables.
- Автоматическая установка UFW, если на сервере нет поддерживаемого firewall backend.
- Безопасные managed-правила: Firewall-UI не должен очищать чужую конфигурацию администратора.
- Confirmed rollback: опасное изменение правил получает временный rollback token. Если интерфейс не подтверждает доступность, предыдущий снимок восстанавливается автоматически.
- Защита порта панели, внешнего reverse-proxy порта и SSH.
- Auto-sync слушающих TCP/UDP-портов и ручные правила.
- Расширенные политики: Allow/Deny, source IP/CIDR, TCP/UDP, диапазоны портов, IPv4/IPv6, интерфейс, приоритет и описание.
- Управление ICMP/ping.
- TOTP 2FA.
- Allowlist IP/CIDR для доступа к самой панели.
- Ограничение brute-force входа и `Retry-After`.
- Dashboard с backend/status, слушающими и публичными портами, правилами, контейнерами и потенциально незащищёнными сервисами.
- Live-таблица TCP/UDP IPv4/IPv6 сокетов, процессов, PID и executable.
- Серверный кэш сокетов + SSE: UI не сканирует `/proc` на каждый запрос.
- Docker и Podman: container/image, published host port и internal port.
- Разрешение/удаление простого firewall-правила прямо из таблицы портов.
- Audit log действий и история снимков правил с восстановлением.
- Export/restore backup конфигурации firewall и runtime-настроек.
- Stable и rolling Dev update channels.
- SHA-256 проверка обновлений, сохранение предыдущего бинарника и ручной `firewall-ui rollback`.
- Русский/английский интерфейс и темы light, dark, ultra-dark, colorful, blue-gray, cyberpunk.

## Быстрая установка

```bash
bash <(curl -Ls https://raw.githubusercontent.com/SawaMEN/Firewall-UI/main/install.sh)
```

Установщик проверяет Linux/systemd/архитектуру и обнаруживает активный firewall backend. Если поддерживаемого файрволла нет, устанавливает UFW через системный пакетный менеджер. Готовый бинарник проверяется по SHA-256 из release manifest до установки. При повторном запуске конфигурация и учётная запись сохраняются, а работающая служба перезапускается. При ошибке запуска восстанавливаются предыдущий бинарник, CLI и systemd unit.

Проверка системы без установки: `bash install.sh --check`. Для автоматической установки задайте `FIREWALL_UI_NONINTERACTIVE=1`: если пароль не задан, установщик сгенерирует его и покажет один раз. Значение `FIREWALL_UI_UPDATE_CHANNEL=stable` или `dev` выбирает источник первой установки; при повторном запуске используется сохранённый канал. Локальный бинарник можно передать через `FIREWALL_UI_BINARY`, а его ожидаемую сумму — через `FIREWALL_UI_SHA256`.

**По умолчанию панель слушает только `127.0.0.1:8088`.** Для удалённого доступа используйте SSH tunnel или reverse proxy с HTTPS. Публичный HTTP bind нужно включить явно:

```bash
sudo FIREWALL_UI_LISTEN_HOST=0.0.0.0 \
  FIREWALL_UI_PORT=8088 \
  FIREWALL_UI_USERNAME=admin \
  FIREWALL_UI_PASSWORD='long-random-password' \
  bash install.sh
```

При публичном bind установщик выводит предупреждение.

UFW после установки не включается автоматически. Управление firewall включается из панели.

## Управление сервисом

Команды `firewall-ui update` и `firewall-ui rollback` проверяют конфигурацию до замены бинарника, затем проверяют работу службы. При ошибке запуска восстанавливается текущая версия; предыдущая сохранённая версия не перезаписывается. Успешный rollback меняет текущую и предыдущую версии местами. Для обновления без интерактивного подтверждения используйте `FIREWALL_UI_NONINTERACTIVE=1 firewall-ui update`.

Чтобы обновить сам консольный менеджер вместе с бинарником, повторно запустите установщик: существующие настройки и учётные данные сохранятся.

```bash
firewall-ui
```

Команды:

```bash
firewall-ui status
firewall-ui start
firewall-ui stop
firewall-ui restart
firewall-ui logs
firewall-ui update
firewall-ui rollback
firewall-ui credentials
firewall-ui uninstall
```

Пути:

- бинарник: `/usr/local/firewall-ui/firewall-ui`
- runtime config: `/etc/firewall-ui/config.json`
- credentials: `/etc/firewall-ui/environment`
- state: `/var/lib/firewall-ui/state.json`
- audit/history: рядом со state-файлом

## Безопасность панели

В «Настройки → Веб-панель и безопасность» доступны:

- bind localhost / все IPv4 / все IPv6;
- порт панели;
- внешний порт reverse proxy;
- Secure Cookie;
- абсолютные пути к HTTPS-сертификату и приватному ключу PEM (пара проверяется перед сохранением);
- IP/CIDR allowlist;
- TOTP 2FA;
- rollback timeout;
- интервал server-side port monitor.

CIDR allowlist нельзя сохранить, если он исключает IP текущего подключения.

TOTP setup возвращает стандартный `otpauth://` URI и secret для любого совместимого authenticator.

Смена сертификата, ключа или порта перезапускает установленную systemd-службу. При прямом доступе браузер переходит на новый порт и протокол; при reverse proxy внешний адрес сохраняется.

Проверка файла конфигурации без запуска службы:

```bash
/usr/local/firewall-ui/firewall-ui -config /etc/firewall-ui/config.json -check-config
```

## Firewall rollback

Перед изменениями enable/disable, auto-sync, ping, sync, manual/advanced rules, restore history и restore backup Firewall-UI сохраняет состояние.

После успешного ответа UI подтверждает транзакцию отдельным запросом. Если соединение пропало и подтверждение не пришло до deadline, сервер автоматически восстанавливает предыдущий firewall snapshot.

Порт панели и SSH всегда идут раньше пользовательских advanced deny rules в managed nftables/iptables цепочках.

## Расширенные правила

Поддерживаются:

- `allow` / `deny`;
- TCP / UDP / ANY;
- один порт или диапазон;
- source IPv4/IPv6/CIDR;
- конкретный interface;
- IPv4 / IPv6 / оба;
- priority;
- label.

Для UFW IPv4-only/IPv6-only advanced rule без source IP/CIDR отклоняется, поскольку UFW не может надёжно выразить такую политику одной high-level командой.

Firewalld advanced rule с конкретным interface отклоняется; для такой политики используйте zone assignment либо nftables/iptables/UFW.

## Порты, процессы и контейнеры

Firewall-UI читает host socket tables из `/proc/net`, сопоставляет inode с процессами через `/proc/<pid>/fd`, кэширует snapshot и отправляет изменения в UI через Server-Sent Events.

Дополнительно обнаруживаются опубликованные порты запущенных Docker/Podman контейнеров через их CLI.

Сокеты внутри отдельного network namespace контейнера без published host port не отображаются как обычный host listener.

## Backup, история и audit

Из настроек можно:

- скачать JSON backup;
- восстановить backup;
- просмотреть историю снимков firewall;
- восстановить предыдущий снимок;
- просмотреть audit log действий.

Backup не экспортирует пароль пользователя и TOTP secret.

## Обновления

Версия Stable хранится в `VERSION`.

- **Stable** — ручная проверка/установка из UI или CLI.
- **Dev** — rolling release из `main`, сервер может устанавливать автоматически.

Release workflow публикует `update.json` с URL бинарника и SHA-256. И встроенный updater, и CLI проверяют checksum перед заменой бинарника.

Перед заменой текущий бинарник сохраняется как `.previous`. Для аварийного отката:

```bash
sudo firewall-ui rollback
```

Версия этого релиза: **1.1.0**.

## Reverse proxy / HTTPS

Рекомендуемая схема:

```text
Internet -> HTTPS reverse proxy -> 127.0.0.1:8088 Firewall-UI
```

Укажите public reverse-proxy port в настройках и включите Secure Cookie.

Встроенный TLS:

```bash
/usr/local/firewall-ui/firewall-ui \
  -config /etc/firewall-ui/config.json \
  -tls-cert /path/fullchain.pem \
  -tls-key /path/privkey.pem \
  -secure-cookies
```

## Сборка и проверки

Нужны Go 1.25+, Node.js 24+ и npm.

```bash
make build
make test
```

CI проверяет:

- shell syntax;
- production `npm audit` для high severity;
- TypeScript/Vite build;
- `gofmt`;
- `go test -race ./...`;
- `go vet ./...`;
- Linux amd64/arm64 builds.

Frontend встраивается в Go binary; Node.js на сервере не нужен.

## Ограничения

Firewall-UI управляет firewall того network namespace, в котором запущен сервис. При штатном systemd запуске это host namespace.

Права root требуются для полного чтения владельцев сокетов и изменения firewall.

Чужие администраторские правила имеют собственный порядок/приоритет. Firewall-UI не пытается принудительно переупорядочивать внешние UFW/firewalld правила.

## Лицензия

GPL-3.0. Сведения о перенесённом коде: [NOTICE.md](NOTICE.md).

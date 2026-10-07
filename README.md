# Firewall-UI

Автономная веб-панель управления системным файрволлом Linux. Основана на firewall-логике и визуальном стиле [SawaMEN/3x-ui](https://github.com/SawaMEN/3x-ui), но работает как отдельный сервис без 3x-ui и собственной базы данных.

## Возможности

- UFW, firewalld, nftables и iptables.
- Установка UFW из панели и автоматическая установка UFW установщиком, если на сервере не найден поддерживаемый файрволл.
- Безопасное включение и выключение управления правилами без уничтожения чужой конфигурации файрволла.
- Автоматическая синхронизация открытых портов со слушающими TCP/UDP-сервисами.
- Ручные правила TCP, UDP и TCP+UDP с описаниями.
- Защита порта веб-панели, настроенного внешнего reverse-proxy порта и SSH.
- Управление входящим ICMP/ping.
- Таблица всех локальных TCP/UDP IPv4/IPv6-сокетов: порт, адрес, состояние, процесс, PID и executable.
- Поиск по порту, адресу, процессу, PID и пути, фильтры и автообновление.
- Отдельные страницы «Файрволл», «Порты и процессы» и «Настройки».
- Настройка bind-адреса, порта панели, внешнего reverse-proxy порта и Secure Cookie из веб-интерфейса.
- Шесть тем из интерфейса 3x-ui: light, dark, ultra-dark, colorful, blue-gray и cyberpunk.
- Русский и английский интерфейс.
- HttpOnly/SameSite session cookie, CSRF-защита и ограничение попыток входа.
- CLI-меню `firewall-ui` для службы, логов, обновления, смены логина/пароля и удаления.

## Быстрая установка

Рекомендуемый вариант — опубликованный release:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/SawaMEN/Firewall-UI/main/install.sh)
```

Установщик:

1. проверяет Linux, systemd и архитектуру;
2. проверяет наличие поддерживаемого файрволла;
3. если UFW/firewalld/nftables/iptables отсутствуют — устанавливает UFW через системный пакетный менеджер;
4. загружает бинарник для amd64 или arm64;
5. создаёт конфигурацию и credentials;
6. устанавливает systemd unit и CLI `firewall-ui`;
7. запускает и включает сервис.

UFW устанавливается, но не включается автоматически. Управление файрволлом включается пользователем из веб-панели.

Если release-бинарник ещё не опубликован, установщик может собрать текущий `main` из исходников при наличии Go, Node.js/npm и tar.

По умолчанию установщик слушает `0.0.0.0:8088`. Значения можно задать заранее:

```bash
sudo FIREWALL_UI_PORT=2096 \
  FIREWALL_UI_LISTEN_HOST=127.0.0.1 \
  FIREWALL_UI_USERNAME=admin \
  FIREWALL_UI_PASSWORD='long-random-password' \
  bash install.sh
```

## Управление после установки

```bash
firewall-ui
```

Также доступны команды:

```bash
firewall-ui status
firewall-ui start
firewall-ui stop
firewall-ui restart
firewall-ui logs
firewall-ui update
firewall-ui credentials
firewall-ui uninstall
```

Бинарник сервиса устанавливается в `/usr/local/firewall-ui/firewall-ui`, конфигурация — в `/etc/firewall-ui/config.json`, credentials — в `/etc/firewall-ui/environment`, состояние — в `/var/lib/firewall-ui/state.json`.

## Настройки панели

В разделе «Настройки» можно изменить:

- доступ только с localhost, со всех IPv4-интерфейсов или со всех IPv6-интерфейсов;
- порт панели;
- внешний порт reverse proxy;
- режим Secure Cookie.

При смене порта Firewall-UI сначала добавляет новый порт в защитные правила, сохраняет конфигурацию и только затем перезапускается через systemd. При прямом доступе браузер автоматически переходит на новый порт.

Логин и пароль меняются командой:

```bash
firewall-ui credentials
```

## Reverse proxy и HTTPS

Для reverse proxy рекомендуется оставить внутренний bind на `127.0.0.1`, указать внешний публичный порт в настройках панели и включить Secure Cookie при HTTPS.

Встроенный TLS также поддерживается через конфигурацию или аргументы запуска:

```bash
/usr/local/firewall-ui/firewall-ui \
  -config /etc/firewall-ui/config.json \
  -tls-cert /path/fullchain.pem \
  -tls-key /path/privkey.pem \
  -secure-cookies
```

## Ручная сборка

Нужны Go 1.25+, Node.js 24+ и npm.

```bash
make build
make test
```

Frontend встраивается в Go-бинарник. После сборки Node.js на сервере не требуется.

GitHub Actions проверяет проект и собирает Linux amd64/arm64. Workflow `Release` публикует установочные бинарники при push тега вида `v*`.

## Ручной запуск

```bash
export FIREWALL_UI_USERNAME=admin
export FIREWALL_UI_PASSWORD='long-random-password'

./firewall-ui \
  -config ./config.json
```

При отсутствии config-файла используются безопасные значения по умолчанию: `127.0.0.1:8088`, состояние в `/var/lib/firewall-ui/state.json`.

Старые параметры `-listen`, `-state`, `-external-port`, `-tls-cert`, `-tls-key` и `-secure-cookies` сохранены как overrides поверх config-файла.

## Ограничения

Список сокетов соответствует network namespace процесса Firewall-UI. При обычном запуске через systemd это namespace хоста. Сокеты внутри отдельных container namespaces и DNAT-перенаправления без локального сокета не отображаются как отдельные процессы хоста.

Данные PID/executable зависят от прав доступа к `/proc`. Поэтому сервис рекомендуется запускать от root.

Автосинхронизация открывает обнаруженные нелокальные слушающие TCP/UDP-порты. Если нужен строго выборочный доступ, отключите автосинхронизацию и используйте ручные правила.

## Лицензия

GPL-3.0. Подробности о перенесённом коде: [NOTICE.md](NOTICE.md).

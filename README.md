# Firewall-UI

Автономный веб-сервис управления системным файрволлом Linux. Интерфейс, темы и код управления файрволлом перенесены из [SawaMEN/3x-ui](https://github.com/SawaMEN/3x-ui), исходный коммит `cf730af652387a2e99fa1cda20674b038a6edfdf`.

## Возможности

- Исходный React / Ant Design интерфейс файрволла 3x-ui: включение, синхронизация, ping IPv4/IPv6, ручные правила TCP / UDP / TCP+UDP с описанием.
- Шесть исходных тем: светлая, тёмная, ultra-dark, colorful, blue-gray, cyberpunk. Русский и английский интерфейс.
- UFW, firewalld, nftables и iptables; установка UFW через apt, dnf, yum, pacman, zypper или apk.
- Таблица всех локальных TCP/UDP-сокетов IPv4/IPv6: порт, адрес привязки, состояние, процесс, PID; путь исполняемого файла в подсказке. Общие сокеты показывают всех владельцев. По умолчанию показаны слушающие сокеты; переключатель позволяет видеть остальные соединения.
- Поиск по порту, адресу, процессу, PID и пути; фильтр протокола, сортировка, пагинация и автообновление раз в 5 секунд.
- Автосинхронизация открывает порты слушающих сервисов и закрывает собственные правила после исчезновения сервиса. Порты, привязанные только к loopback, автоматически не открываются. По умолчанию автосинхронизация включена после включения управления; её можно отключить и пользоваться ручными правилами.
- Защита порта панели, явно заданного внешнего порта reverse proxy и обнаруженных SSH-портов.
- Отдельные nftables-таблица `firewall_ui` и iptables-цепочка `FIREWALL-UI`; чужие нативные input hooks не перезаписываются. Для UFW/firewalld выключение удаляет только правила, созданные этой панелью, сохраняя системный файрволл.
- Сессии с HttpOnly/SameSite cookie, CSRF-защита, ограничение попыток входа. Состояние сохраняется атомарно в JSON; база данных и 3x-ui не нужны.

## Сборка

Нужны Go 1.25+, Node.js 24+ и npm.

```bash
make build
make test
```

Интерфейс встраивается в бинарник Go. После сборки Node.js на сервере не требуется. GitHub Actions проверяет проект и собирает бинарники Linux amd64/arm64 в артефакт `firewall-ui-linux`.

## Запуск

Запускайте на самом Linux-сервере от root: права нужны для изменения файрволла и просмотра всех владельцев сокетов.

```bash
export FIREWALL_UI_USERNAME=admin
read -rs -p 'Password (12+ characters): ' FIREWALL_UI_PASSWORD
export FIREWALL_UI_PASSWORD
sudo --preserve-env=FIREWALL_UI_USERNAME,FIREWALL_UI_PASSWORD ./firewall-ui \
  -listen 127.0.0.1:8088 \
  -state /var/lib/firewall-ui/state.json
```

Пароля по умолчанию нет. Введите минимум 12 символов. Доступ через SSH-туннель:

```bash
ssh -L 8088:127.0.0.1:8088 root@SERVER
```

Откройте `http://127.0.0.1:8088`. Сам запуск не включает файрволл: управление активируется переключателем в интерфейсе.

Для прямого HTTPS:

```bash
./firewall-ui -listen 0.0.0.0:8088 \
  -tls-cert /path/fullchain.pem -tls-key /path/privkey.pem
```

При HTTPS reverse proxy направьте запросы на `127.0.0.1:8088`, сохраняя исходный заголовок Host; добавьте `-external-port 443 -secure-cookies` к запуску. Внешний порт задаётся администратором, а не берётся из произвольных клиентских заголовков.

## systemd

```bash
sudo install -m 0755 firewall-ui /usr/local/bin/firewall-ui
sudo install -d -m 0700 /etc/firewall-ui
sudo install -m 0644 deploy/firewall-ui.service /etc/systemd/system/
sudo install -m 0600 /dev/null /etc/firewall-ui/environment
sudoedit /etc/firewall-ui/environment
```

Запишите в файл:

```ini
FIREWALL_UI_USERNAME=admin
FIREWALL_UI_PASSWORD=YOUR_LONG_RANDOM_PASSWORD
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now firewall-ui
sudo journalctl -u firewall-ui -f
```

При использовании reverse proxy измените `ExecStart`, добавив параметры внешнего порта и secure cookie.

## Ограничения

Список сокетов соответствует сетевому namespace сервиса: при обычном запуске systemd это весь хост. Сокеты внутри изолированных container namespaces и перенаправления DNAT без локального сокета не представлены как отдельные процессы хоста. Имена владельцев зависят от прав `/proc`; у завершившихся процессов, TIME_WAIT и некоторых ядерных сокетов PID отсутствует. Снимок обновляется, поэтому процесс может исчезнуть между чтением сокета и его владельца.

Автосинхронизация открывает каждый обнаруженный нелокальный слушающий TCP/UDP-порт. Для выборочного доступа отключите её и задайте ручные правила. Совместная работа двух панелей, одновременно меняющих политику одного системного файрволла, требует согласования администратором.

## Лицензия

GPL-3.0, как и исходный 3x-ui. Сведения о перенесённом коде: [NOTICE.md](NOTICE.md).

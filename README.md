# Relay-сервер

Relay-сервер принимает публичные TCP/TLS-подключения, читает SNI из
`ClientHello` без завершения TLS-сессии и передает поток на подключенное
Android-устройство через gRPC-туннель. Пользовательский HTTPS завершается на
устройстве, а сервер только маршрутизирует трафик.

## Что нужно установить

- Go 1.24 или новее.
- PostgreSQL.
- OpenSSL для генерации локальных сертификатов.
- На Windows: `cmd.exe` или PowerShell для `.bat`-скриптов.

На Linux зависимости можно поставить так:

```bash
# Debian/Ubuntu
sudo apt update
sudo apt install postgresql openssl git

# Fedora
sudo dnf install postgresql-server openssl git

# Arch Linux
sudo pacman -S postgresql openssl git
```

После установки Go команда `go version` должна быть доступна в `PATH`.

Также проверьте, что:

- порты `443`, `50051` и `8443` свободны;
- брандмауэр, антивирус и роутер пропускают входящие подключения на эти порты;
- DNS нужных доменов указывает на IP-адрес relay-сервера.

## Локальный запуск

### Windows

1. Создайте локальный файл настроек:

   ```bat
   copy .env.example relay.env
   ```

2. Отредактируйте `relay.env`.

   Минимально нужны:

   - `SECRET_API_KEY` - ключ доступа к административному API;
   - `DATABASE_URL` или `RELAY_DATABASE_DSN` - строка подключения к PostgreSQL;
   - `RELAY_ENROLLMENT_TOKEN` - токен регистрации устройств.

   Остальные параметры в `.env.example` задают пути к сертификатам, лимиты и
   интервалы фоновых проверок. Для обычного локального запуска их можно не
   менять.

3. Создайте базу PostgreSQL, указанную в `relay.env`.

   Миграции выполняются автоматически при старте сервера.

4. Сгенерируйте локальные сертификаты:

   ```bat
   certs\generate_certs.bat
   ```

5. Запустите сервер:

   ```bat
   run_relay.bat
   ```

`run_relay.bat` загружает переменные из `relay.env`, проверяет обязательные
значения и локальные сертификаты, затем выполняет `go run .`.

### Linux

1. Создайте локальный файл настроек:

   ```bash
   cp .env.example relay.env
   ```

2. Отредактируйте `relay.env`.

3. Создайте пользователя и базу PostgreSQL.

   Пример для локальной разработки:

   ```bash
   sudo -u postgres createuser relay
   sudo -u postgres createdb -O relay relay
   sudo -u postgres psql -c "ALTER USER relay WITH PASSWORD 'relay_dev';"
   ```

4. Сгенерируйте локальные сертификаты:

   ```bash
   sh certs/generate_certs.sh
   ```

5. Запустите сервер:

   ```bash
   sh run_relay.sh
   ```

Если хотите запускать скрипты напрямую, добавьте право на исполнение:

```bash
chmod +x run_relay.sh certs/generate_certs.sh
./run_relay.sh
```

На Linux порт `443` является привилегированным. Для локальной проверки проще
запустить сервер через `sudo` или временно поменять порт. Для production-сервера
лучше выдать нужное право только бинарному файлу или настроить запуск через
systemd.

## Порты

Сервер слушает:

- `:443` - публичный входящий HTTPS-трафик;
- `:50051` - gRPC-туннель для устройств;
- `:8443` - административный интерфейс и API.

## Сертификаты

Каталог `certs` предназначен для локальных TLS-файлов. Сгенерированные ключи и
сертификаты не хранятся в репозитории.

Скрипт генерации создает:

- `ca.crt` / `ca.key` - локальный центр сертификации для устройств;
- `server.crt` / `server.key` - сертификат gRPC-сервера;
- `admin.crt` / `admin.key` - сертификат административного HTTPS-сервера;
- `admin-chain.crt` - цепочку сертификатов для браузеров и утилит.

На production-сервере для административного интерфейса, API и gRPC можно
использовать обычные сертификаты, например Let's Encrypt. Отдельный CA для
устройств все равно нужен: он выпускает и проверяет клиентские сертификаты
Android-клиентов.

Пути к сертификатам задаются в `relay.env`:

- `RELAY_GRPC_CERT_FILE` и `RELAY_GRPC_KEY_FILE`;
- `RELAY_ADMIN_CERT_FILE` и `RELAY_ADMIN_KEY_FILE`;
- `RELAY_DEVICE_CA_CERT_FILE`;
- `RELAY_DEVICE_CA_KEY_FILE`.

## Домены

Устройство регистрирует домен через административный API. Сервер создает DNS-проверку,
ждет TXT-запись и после успешной проверки начинает принимать трафик для этого
домена.

Текущее состояние доменов хранится в таблице `domains`. История действий
сохраняется в `domain_histories`, поэтому для аудита нужно смотреть базу, а не
текстовые логи.

## Логи

Сервер пишет диагностические логи в:

- `server.log`;
- `admin.log`.

Файлы ротируются внутри процесса. Логи удобны для отладки, но не являются
источником истины для владения доменами и истории изменений.

## Проверки

В примерах ниже используются условные значения:

- `<DOMAIN>` - пользовательский домен, привязанный к Android-устройству;
- `<RELAY_IP>` - публичный IP-адрес relay-сервера.

В PowerShell можно задать переменные так:

```powershell
$DOMAIN = "device.example.com"
$RELAY_IP = "203.0.113.10"
```

Проверить DNS:

```powershell
nslookup $DOMAIN
```

Проверить доступность портов:

```powershell
Test-NetConnection $RELAY_IP -Port 443
Test-NetConnection $RELAY_IP -Port 50051
Test-NetConnection $RELAY_IP -Port 8443
```

Проверить HTTPS-запрос через обычный DNS:

```powershell
curl.exe -vk "https://$DOMAIN/"
```

Проверить конкретный relay-сервер, даже если DNS еще не обновился:

```powershell
curl.exe -vk --resolve "${DOMAIN}:443:${RELAY_IP}" "https://$DOMAIN/"
```

# Relay Server

Сервер relay принимает публичные TCP/TLS-подключения, читает SNI из
ClientHello без завершения TLS-сессии и прокидывает поток на подключенное
устройство через gRPC-туннель. TLS для пользовательского HTTPS завершается на
стороне устройства, а не на relay-сервере.

## Что должно быть установлено

Для корректной работы сервера на машине с relay нужны:

- Go 1.24 или новее. Скрипты запуска выполняют сервер через `go run .`.
- PostgreSQL. Сервер подключается к базе из `DATABASE_URL` или
  `RELAY_DATABASE_DSN`.
- OpenSSL. Нужен для генерации локальных сертификатов. На Windows
  `certs\generate_certs.bat` ищет `openssl.exe` в Git for Windows,
  OpenSSL-Win64/OpenSSL-Win32 или в `PATH`; на Linux используется команда
  `openssl` или путь из переменной `OPENSSL`.
- Git for Windows опционален, но удобен: в стандартной установке обычно есть
  `C:\Program Files\Git\mingw64\bin\openssl.exe`.
- Windows `cmd.exe`/PowerShell для запуска `.bat`-скриптов.

На Linux установите:

```bash
# Debian/Ubuntu
sudo apt update
sudo apt install postgresql openssl git

# Fedora
sudo dnf install postgresql-server openssl git

# Arch Linux
sudo pacman -S postgresql openssl git
```

Go 1.24+ установите из пакетов дистрибутива, snap/asdf/mise или с официального
сайта Go. После установки команда `go version` должна быть доступна в `PATH`.

Также проверьте сетевые условия:

- Порты `443`, `50051` и `8443` должны быть свободны.
- Firewall/антивирус/роутер должны пропускать входящие подключения на нужные
  порты.
- DNS нужных доменов должен указывать на IP relay-сервера.

## Локальный запуск

### Windows

1. Создайте локальный файл окружения:

   ```bat
   copy .env.example relay.env
   ```

2. Отредактируйте `relay.env`.

   Обязательные переменные:

   - `SECRET_API_KEY` - ключ доступа к admin API.
   - `DATABASE_URL` или `RELAY_DATABASE_DSN` - строка подключения к PostgreSQL.

   Дополнительные переменные:

   - `RELAY_ENROLLMENT_TOKEN` - включает endpoint регистрации устройств.
   - `TLS_CLIENT_AUTH` - режим проверки клиентских сертификатов для gRPC.
   - `RELAY_INGRESS_MAX_CONNS` - лимит одновременных public TCP-подключений.
   - `RELAY_MAX_STREAMS_PER_DEVICE` - лимит активных stream на устройство.
   - `RELAY_CONTROL_QUEUE_SIZE` - размер очереди control frames.
   - `RELAY_DATA_QUEUE_SIZE` - размер очереди data frames.
   - `RELAY_CONTROL_BUDGET` - доля control frames в writer loop.
   - `RELAY_DATA_BUDGET` - доля data frames в writer loop.
   - `RELAY_DATA_QUEUE_SOFT_LIMIT` - мягкий порог перегрузки data queue.
   - `RELAY_DATA_QUEUE_HARD_LIMIT` - жесткий порог перегрузки data queue.
   - `RELAY_DNS_CHALLENGE_TTL_SECONDS` - срок действия DNS challenge,
     по умолчанию `86400` секунд.
   - `RELAY_DNS_INSTRUCTION_TTL_SECONDS` - рекомендуемый TTL создаваемой
     TXT-записи, по умолчанию `300` секунд.
   - `RELAY_DNS_VERIFY_MIN_INTERVAL_SECONDS` - минимальный интервал между
     ручными DNS-проверками одного challenge, по умолчанию `60` секунд.
   - `RELAY_DNS_VERIFY_INITIAL_INTERVAL_SECONDS` - задержка до первой
     автоматической проверки, по умолчанию `30` секунд.
   - `RELAY_DNS_VERIFY_MAX_INTERVAL_SECONDS` - максимальный интервал
     автоматического backoff, по умолчанию `900` секунд.
   - `RELAY_DNS_VERIFY_JITTER_PERCENT` - случайное отклонение интервала,
     по умолчанию `10` процентов.
   - `RELAY_DNS_VERIFY_WORKER_INTERVAL_SECONDS` - период поиска due challenge,
     по умолчанию `5` секунд.
   - `RELAY_DNS_VERIFY_WORKER_BATCH_SIZE` - размер batch фонового worker,
     по умолчанию `32`.
   - `RELAY_DNS_VERIFY_WORKER_CONCURRENCY` - максимум параллельных DNS-проверок
     одного worker, по умолчанию `8`.
   - `RELAY_DNS_VERIFY_CLAIM_LEASE_SECONDS` - срок резервирования challenge
     worker-ом, по умолчанию `30` секунд.
   - `RELAY_DNS_VERIFY_LOOKUP_TIMEOUT_SECONDS` - таймаут одного DNS lookup,
     по умолчанию `5` секунд.
   - `RELAY_MAX_ACTIVE_DNS_CHALLENGES_PER_DEVICE` - максимум одновременно
     активных challenge устройства, по умолчанию `32`.
   - `RELAY_MAX_DNS_VERIFY_ATTEMPTS_PER_CHALLENGE` - необязательный жесткий
     лимит прямых запросов проверки. Фоновый worker продолжает проверки
     до успеха или истечения challenge.

   Повторный запрос регистрации до истечения challenge возвращает то же имя
   и значение TXT-записи. Новый токен создается только после истечения
   предыдущего challenge. Автоматические проверки выполняются с
   backoff `30 секунд, 1, 2, 5, 10 и 15 минут`. Результат сохраняется
   в PostgreSQL. При живом туннеле устройство получает
   `DomainVerificationUpdate`, а при следующем подключении актуальные
   состояния `pending`, `verified` и `expired` передаются в `Welcome`.

3. Создайте базу PostgreSQL, указанную в `DATABASE_URL`.

   Миграции выполняются автоматически при старте сервера.

4. Сгенерируйте локальные сертификаты:

   ```
   certs\generate_certs.bat
   ```

5. Запустите сервер:

   ```
   run_relay.bat
   ```

`run_relay.bat` загружает переменные из `relay.env`, проверяет наличие обязательных
значений и локальных сертификатов, затем выполняет `go run .`. Если запускать
`go run .` напрямую, переменные окружения все равно должны быть уже заданы в
процессе.

### Linux

1. Создайте локальный файл окружения:

   ```bash
   cp .env.example relay.env
   ```

2. Отредактируйте `relay.env`.

   Минимально нужны `SECRET_API_KEY` и `DATABASE_URL` или
   `RELAY_DATABASE_DSN`.

3. Создайте пользователя и базу PostgreSQL под значения из `relay.env`.

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

Если хотите запускать скрипты напрямую, выставьте executable bit:

```bash
chmod +x run_relay.sh certs/generate_certs.sh
./run_relay.sh
```

На Linux порт `443` является privileged port. Если сервер запускается не от
root, выдайте бинарнику capability или используйте systemd unit с нужными
правами. Для локальной проверки проще временно запускать через `sudo`, но для
production лучше не держать весь процесс под root.

## Порты

Сервер слушает:

- `:443` - публичный TCP ingress для HTTPS passthrough.
- `:50051` - gRPC-туннель для устройств.
- `:8443` - admin UI/API.
- `127.0.0.1:6060` - локальные debug endpoints: `expvar` и `pprof`.

## Сертификаты

Каталог `certs` предназначен для локальных и сгенерированных TLS-файлов.
Сгенерированные `.key`, `.crt`, `.csr`, `.srl` и `.cnf` игнорируются git.
В репозитории хранятся только скрипты генерации:
`certs\generate_certs.bat` для Windows и `certs/generate_certs.sh` для Linux.

Для локальной разработки на Windows используйте:

```bat
certs\generate_certs.bat
```

На Linux используйте:

```bash
sh certs/generate_certs.sh
```

Скрипт создает:

- `ca.crt` / `ca.key` - локальный CA для relay.
- `server.crt` / `server.key` - сертификат gRPC-сервера.
- `admin.crt` / `admin.key` - сертификат admin HTTPS-сервера.
- `admin-chain.crt` - цепочка для браузеров и инструментов, которым нужен CA.

Для production лучше использовать реальные сертификаты для публичных HTTPS
endpoint'ов. Сертификаты Let's Encrypt могут заменить `certs/admin.crt` и
`certs/admin.key`, если admin UI/API открыт наружу. gRPC-туннель также может
использовать публичный server certificate, но `certs/ca.crt` все равно нужен
для проверки клиентских сертификатов устройств при `TLS_CLIENT_AUTH=require`.

Пути задаются через переменные:

- `RELAY_GRPC_CERT_FILE` и `RELAY_GRPC_KEY_FILE`;
- `RELAY_ADMIN_CERT_FILE` и `RELAY_ADMIN_KEY_FILE`;
- `RELAY_DEVICE_CA_CERT_FILE` для проверки клиентских сертификатов;
- `RELAY_DEVICE_CA_KEY_FILE` для endpoint регистрации устройств.

Пример для VPS, где gRPC и admin используют один публичный hostname:

```text
RELAY_GRPC_CERT_FILE=/etc/letsencrypt/live/relay.example.com/fullchain.pem
RELAY_GRPC_KEY_FILE=/etc/letsencrypt/live/relay.example.com/privkey.pem
RELAY_ADMIN_CERT_FILE=/etc/letsencrypt/live/relay.example.com/fullchain.pem
RELAY_ADMIN_KEY_FILE=/etc/letsencrypt/live/relay.example.com/privkey.pem
RELAY_DEVICE_CA_CERT_FILE=/etc/relay/pki/device-ca.crt
RELAY_DEVICE_CA_KEY_FILE=/etc/relay/pki/device-ca.key
```

Let's Encrypt не заменяет device CA: публичный сертификат защищает серверные
endpoint, а отдельный CA выпускает и проверяет клиентские сертификаты
устройств. Закрытый ключ device CA должен быть доступен только пользователю
relay.

При `SIGTERM` сервер прекращает принимать новые ingress-соединения, отправляет
подключенным устройствам `GoAway`, по умолчанию ждёт 5 секунд и затем корректно
останавливает gRPC, admin, ingress и debug-серверы. Параметры:

- `RELAY_GOAWAY_PLANNED_RETRY_AFTER_SECONDS` - когда устройству пробовать
  переподключиться;
- `RELAY_GOAWAY_SHUTDOWN_DRAIN_MS` - время доставки `GoAway` и завершения
  текущего обмена;
- `RELAY_SHUTDOWN_TIMEOUT_SECONDS` - общий предел финального завершения.

## Состояние доменов и история

Таблица `domains` хранит текущего владельца домена и операционный статус.
Записи удаляются мягко, поэтому один и тот же FQDN можно позже зарегистрировать
на другое устройство без потери истории.

Таблица `domain_histories` хранит append-only аудит жизненного цикла домена:

- `REGISTER`
- `BIND`
- `UNBIND`
- `ENABLE`
- `DISABLE`
- `DELETE`

Записи истории сохраняют `fqdn`, а при наличии также `domain_id` и `device_id`.
Для бизнес-аудита нужно использовать эту таблицу, а не `server.log` или
`admin.log`.

## Логи

`server.log` и `admin.log` - диагностические логи. Они ротируются внутри
процесса: текущий файл переименовывается в `.1`, старые backup-файлы сдвигаются
дальше, по умолчанию хранится не больше пяти backup-файлов.

Эти логи полезны для отладки и эксплуатации, но не являются источником истины
для владения доменами или истории их изменений.

## Проверки

Проверить, что домен резолвится в relay:

```powershell
[System.Net.Dns]::GetHostAddresses("example.android-tunnel.online")
```

Проверить ingress напрямую, минуя DNS:

```powershell
curl.exe -vk --resolve example.android-tunnel.online:443:192.168.31.250 https://example.android-tunnel.online/
```

Проверить тесты проекта:

```bat
go test ./...
```

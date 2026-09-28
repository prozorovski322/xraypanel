# xraypanel

Self-hosted панель управления прокси-инфраструктурой на базе
[Xray-core](https://github.com/XTLS/Xray-core).

Три компонента:

| Компонент | Что делает |
|---|---|
| **panel** | Control plane: REST API, публичная подписка, gRPC-сервер для нод. Единственный источник правды. Трафик не проксирует. |
| **node agent** | Data plane на сервере выхода. Управляет локальным `xray-core` как дочерним процессом, отдаёт статистику и health. В БД не ходит никогда. |
| **frontend** | SPA-админка и публичная страница подписки. |

Ноды **дозваниваются до панели** по gRPC поверх mTLS и держат долгоживущий стрим.
Поэтому у нод нет входящих портов и они работают за NAT. Панель — свой CA, каждая
нода получает клиентский сертификат при регистрации.

Как части связаны между собой: [`docs/architecture.md`](docs/architecture.md). Решения и
их обоснования: [`docs/decisions.md`](docs/decisions.md).

## Статус

Все вехи плана реализованы. Приёмка M12 в реальном окружении — развёртывание на чистой VPS
по [`docs/deployment.md`](docs/deployment.md) и импорт подписки в четыре клиента на
устройствах — выполняется оператором; в CI стек поднимается и проверяется на собранных
образах.

- [x] M1 — каркас, конфигурация, логирование, crypto, схема БД, health-пробы
- [x] M2 — аутентификация админа (argon2id, JWT с ротацией refresh, TOTP, API-ключи)
- [x] M3 — генератор конфига Xray и Reality
- [x] M4 — генератор ссылок подписки и форматов клиентов
- [x] M5 — REST: пользователи, группы, inbound'ы, hosts, ноды, API-ключи
- [x] M6 — протокол нод и PKI (CA, enrollment, mTLS, долгоживущий стрим)
- [x] M7 — node agent (supervisor xray, локальный кеш, доставка конфига, Docker-образ)
- [x] M8 — рантайм-реконсиляция: пользователи без рестарта ядра
- [x] M9 — сбор статистики и биллинг трафика (дельты без потерь, идемпотентный приём, воркеры)
- [x] M10 — принуждение лимитов и сроков, сбросы по периодам, вебхуки с подписью
- [x] M11 — админка: React, вход с 2FA, все разделы, живой статус нод, графики трафика
- [x] M12 — публичная подписка и её страница, лимит запросов, Caddy с ACME, production
  compose, бэкапы с проверкой и восстановлением, публикация образов

## Установка

Production — пять контейнеров одним compose-файлом: PostgreSQL, миграции, панель, Caddy с
админкой и сертификатом, бэкапы.

```bash
cd deploy
cp panel.env.example .env      # домен, пароль БД, мастер-ключ, первый администратор
docker compose up -d
```

Пошагово, с первой нодой, обновлением, бэкапами и восстановлением:
[`docs/deployment.md`](docs/deployment.md).

## Разработка

### Требования

- Go 1.26+
- PostgreSQL 16 (клиентские `pg_dump`/`pg_restore` той же версии — для тестов бэкапа)
- Node 24 и npm — для админки
- Docker — для локальной БД; есть путь и без него, см. ниже
- Референсные бинарники — только для тестов, без них соответствующие проверки
  пропускаются: [Xray-core](https://github.com/XTLS/Xray-core/releases) (конфиги),
  [sing-box](https://github.com/SagerNet/sing-box/releases) и
  [mihomo](https://github.com/MetaCubeX/mihomo/releases) (профили подписки)

### Быстрый старт

```bash
cp .env.example .env
openssl rand -hex 32           # вписать в .env как PANEL_SECRET_KEY
make dev-up
make migrate
make run
```

```bash
curl -s localhost:8080/healthz
curl -s localhost:8080/readyz
```

`/healthz` — liveness, БД не трогает: зависимость от БД в liveness-пробе превращает
моргание базы в цикл перезапусков и удлиняет аварию. `/readyz` — readiness, проверяет БД.

### Без Docker

Docker Desktop на Windows требует прав администратора, WSL2 и перезагрузки — это много для
того, чтобы просто прогнать тесты. Есть путь на нативном Postgres:

```bash
scripts/dev-db.sh init     # создать кластер и базу (один раз)
scripts/dev-db.sh start    # поднять
scripts/dev-db.sh reset    # снести базу и накатить схему заново
scripts/dev-db.sh stop
```

Скрипт кладёт каталог данных **вне репозитория**: папку проекта, синхронизируемую OneDrive
или Dropbox, клиент синхронизации перепишет под работающим сервером и разрушит кластер.

Интеграционные тесты берут DSN из `TEST_DATABASE_URL` и работают на том же нативном
Postgres:

```bash
createdb panel_test
TEST_DATABASE_URL=postgres://panel:panel@127.0.0.1:5432/panel_test?sslmode=disable \
  PG_BIN=/usr/lib/postgresql/16/bin \
  make test-integration
```

`PG_BIN` — каталог с `pg_dump`/`pg_restore` для тестов бэкапа; без него они ищутся в `PATH`
и пропускаются, если не найдены (в CI — падают).

### Цели

```bash
make help              # список целей
make test              # юнит-тесты
make test-integration  # интеграционные (нужен TEST_DATABASE_URL)
make check             # то же, что прогоняет CI: формат, vet, линтер, тесты
make dev-reset         # снести локальную БД и накатить схему заново
make sqlc              # перегенерировать слой доступа к данным
make ui-dev            # админка на 127.0.0.1:5173 (нужен Node и `make ui-install`)
make images            # образы panel, web и backup для deploy/docker-compose.yml
```

### Проверка настоящими клиентами

Golden-файлы доказывают, что генератор стабилен, но не то, что его вывод корректен.
Конфиг, прошедший ревью и не принятый Xray, — это нода, которая не стартует. Поэтому тесты
прогоняют каждую генерируемую комбинацию через `xray run -test` и отдельно сверяют наш
x25519 с `xray x25519`:

```bash
XRAY_BINARY=/path/to/xray SINGBOX_BINARY=/path/to/sing-box MIHOMO_BINARY=/path/to/mihomo \
  make test
```

Без переменных эти тесты пропускаются. В CI версии зафиксированы, а архив Xray проверяется
по публикуемому релизом digest'у.

Профили подписки проверяются так же и по той же причине: YAML или JSON может выглядеть
безупречно для ревьюера и быть отвергнут клиентом, который его грузит, — а пользователь
увидит «ошибка импорта» без объяснений.

### Кодогенерация

Сгенерированный код (`internal/postgres/gen`, `internal/nodectl`,
`internal/xray/{app,common,proxy}`, `frontend/src/api/schema.d.ts`) лежит в гите, поэтому
для обычной сборки и тестов генераторы не нужны. Перегенерация:

```bash
make sqlc    # слой доступа к БД из internal/postgres/queries
make proto   # протокол нод и API ядра из api/proto
make ui-api  # типы админки из api/openapi.yaml
```

Под `api/proto/xray/` лежит описание того подмножества API самого Xray-core, через которое
агент меняет пользователей на работающем ядре. Это транскрипция чужого wire-контракта, а не
зависимость от ядра; раскладка каталогов повторяет его собственную, чтобы происхождение
каждого сообщения было видно. Почему не зависимость — ADR-065.

`make proto` не требует ни `protoc`, ни установленных плагинов: buf приносит свой
компилятор, а плагины вызываются через `go run` с зафиксированными версиями (ADR-055). CI
проверяет, что перегенерация не даёт diff'а.

### Известная проблема на Windows

Windows Application Control (Smart App Control) блокирует запуск свежесобранных бинарников
Go — тестовых и обычных — по репутации, непредсказуемо: один и тот же пакет то запускается,
то нет.

```
fork/exec ...\go-build...\pkg.test.exe: An Application Control policy has blocked this file
```

Это **не** падение тестов — тесты при этом не запускались. Отличать по тексту ошибки.
Помогает прогон попакетно с повтором через `go test -c`. Полностью лечится отключением
Smart App Control, но это изменение системной политики. Подробнее: ADR-029.

На такой машине `go run` для самого buf работает, а собранные им плагины блокируются;
их приходится собирать в отдельный каталог и подсовывать через `buf generate --template`.

## API

Контракт: [`api/openapi.yaml`](api/openapi.yaml). Он сверяется с реальным роутером тестом в
обе стороны — недокументированный роут и документированный несуществующий одинаково валят
сборку, иначе спека, из которой генерируют клиентов, тихо начала бы описывать не тот API.

Два вида вызывающих, оба в `Authorization: Bearer`, различаются формой значения: токен
администратора (проверяется по роли) и API-ключ `xpk_...` (по скоупам).

```bash
# войти
ACCESS=$(curl -s -X POST localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"root","password":"..."}' | jq -r .access_token)

# создать пользователя, безопасно к ретраям
curl -s -X POST localhost:8080/api/v1/users \
  -H "Authorization: Bearer $ACCESS" \
  -H 'Idempotency-Key: 7f3a-1' \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","traffic_limit":107374182400}'

# токен подписки пользователя и его ссылки
curl -s localhost:8080/api/v1/users/1/subscription -H "Authorization: Bearer $ACCESS" | jq

# то, что получит клиент: формат по User-Agent или ?format=base64|clash|singbox|json
curl -si localhost:8080/sub/<token> -A 'mihomo/1.19'

# посмотреть, что получит нода, не деплоя
curl -s localhost:8080/api/v1/nodes/1/config -H "Authorization: Bearer $ACCESS" | jq .structural_hash

# выписать ноде одноразовый токен регистрации: в ответе токен, отпечаток CA и имя,
# которое нода должна требовать в сертификате панели. Токен показывается один раз.
curl -s -X POST localhost:8080/api/v1/nodes/1/enrollment-tokens -H "Authorization: Bearer $ACCESS"

# держит ли этот процесс стрим ноды прямо сейчас
curl -s localhost:8080/api/v1/nodes/1/connection -H "Authorization: Bearer $ACCESS" | jq

# подписаться на события; secret в ответе показывается один раз
curl -s -X POST localhost:8080/api/v1/webhooks \
  -H "Authorization: Bearer $ACCESS" -H 'Content-Type: application/json' \
  -d '{"url":"https://billing.example.com/hook","events":["user.limited"]}'

# сколько трафика насчитано пользователю по дням
curl -s "localhost:8080/api/v1/users/1/traffic?from=2026-09-01" -H "Authorization: Bearer $ACCESS" | jq
```

Ноды говорят с панелью не по HTTP: отдельный gRPC-порт с mTLS, нода звонит сама.
Подробно: [`docs/node-protocol.md`](docs/node-protocol.md).

## Нода

Нода — один образ: агент как PID 1, xray-core дочерним процессом, `network_mode: host`.
Панель — единственный источник правды о том, что нода запускает; своего конфига у ноды нет.

```bash
docker build -f deploy/node.Dockerfile --build-arg XRAY_VERSION=v26.3.27 -t xraypanel-node .
```

Оператору нужны три значения, и все три приходят одним ответом панели при выписке
одноразового токена: адрес, токен и отпечаток CA. Отпечаток обязателен — без него нода не
может проверить панель **до** отправки токена, а значит отдала бы его тому, кто ответит на
адресе.

Авария панели не является аварией сервиса: нода поднимает ядро из локального кеша ещё до
того, как первый раз позвонит панели.

Изменения состава пользователей применяются на работающем ядре, без рестарта: добавление,
удаление и перевыпуск пользователя не рвут чужих соединений. Рестарт остаётся для того, что
API ядра сделать не может — добавления inbound'а и изменений структурной части, — и
записывается в аудит как `node.core_restarted`. Подробно:
[`docs/node-agent.md`](docs/node-agent.md).

## Конфигурация

Только через переменные окружения, все валидируются на старте — панель не стартует на
плохом значении и сообщает обо **всех** найденных проблемах сразу. Полный список с
комментариями: [`.env.example`](.env.example); для production —
[`deploy/panel.env.example`](deploy/panel.env.example).

Секретов в репозитории нет и быть не может. `PANEL_SECRET_KEY` шифрует все секреты в БД и
выводит из себя ключ подписи JWT, поэтому управлять надо ровно одним секретом. Храните его
отдельно от бэкапов базы.

## Документация

- [`docs/architecture.md`](docs/architecture.md) — компоненты, потоки, состояние, отказы, границы доверия
- [`docs/deployment.md`](docs/deployment.md) — установка, обновление, бэкапы, восстановление
- [`docs/decisions.md`](docs/decisions.md) — архитектурные решения с обоснованиями
- [`docs/authentication.md`](docs/authentication.md) — вход, 2FA, API-ключи, сценарий curl
- [`docs/xray-config.md`](docs/xray-config.md) — как собирается config.json, Reality, хэши
- [`docs/subscriptions.md`](docs/subscriptions.md) — ссылки, форматы, заголовки, эндпоинт `/sub`, страница, лимит
- [`docs/traffic.md`](docs/traffic.md) — учёт трафика: дельты, батчи, партиции, диагностика
- [`docs/enforcement.md`](docs/enforcement.md) — лимиты, сроки, сбросы, вебхуки и их проверка
- [`docs/frontend.md`](docs/frontend.md) — админка и страница подписки: запуск, сессия, экраны, чеклист
- [`docs/migrations.md`](docs/migrations.md) — работа с миграциями, восстановление из бэкапа
- [`docs/node-protocol.md`](docs/node-protocol.md) — регистрация нод, mTLS, стрим, отзыв
- [`docs/node-agent.md`](docs/node-agent.md) — агент: супервизор ядра, кеш, применение конфига, диагностика

## Лицензия

Код оригинальный. Лицензия будет выбрана до первой публикации.

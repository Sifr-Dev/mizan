<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/banner-dark.svg">
    <img alt="GO_DB — built from zero" src=".github/banner-light.svg" width="100%">
  </picture>
</p>

# Go Clean Architecture API

A layered Go REST API and React/TypeScript client for registration, authentication, task ownership, and explicit administrator management.

The project uses Go, chi, PostgreSQL with sqlc-generated queries, Redis-backed sessions and rate limiting, JWT access tokens, and a Vite frontend. It is a real implementation with a deliberately small operational surface; the claims below describe the code in this repository rather than a hypothetical production deployment.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│ Delivery                                             │
│ chi handlers, middleware, CORS, request validation   │
├─────────────────────────────────────────────────────┤
│ Use cases                                            │
│ user, task, and administrator application services   │
├─────────────────────────────────────────────────────┤
│ Domain                                               │
│ entities, DTOs, repository/service interfaces        │
├─────────────────────────────────────────────────────┤
│ Infrastructure / repositories                        │
│ pgx/sqlc adapters, Redis sessions and rate limiter   │
└─────────────────────────────────────────────────────┘
```

The domain package contains the business types and interfaces. It does use `google/uuid` for identifiers, so the earlier claim that it has zero external imports is not repeated here.

## Implemented security contract

- **No implicit administrator:** the API never creates or promotes an account at startup. An administrator is created only by the explicit `cmd/admin` command, and an existing email is rejected rather than promoted. Administrator email and password input is validated before use.
- **Purpose-bound JWTs:** access and refresh tokens use HS256 only and contain `token_use`, `sid`, `jti`, issuer, audience, subject, issued-at, not-before, and expiry claims. A refresh token is rejected by protected routes.
- **Session-backed token families:** access and refresh tokens reference one server-side Redis session family. The stored current access/refresh JTIs are checked against each presented token, so a JTI cannot be substituted within a family.
- **Bounded refresh rotation:** rotation atomically consumes the current refresh JTI, preserves the family's absolute expiry, and issues the current role from the database. Reuse of a consumed refresh token revokes the successor family; logout revokes the family as well.
- **Browser storage boundary:** the refresh token is not returned in JSON or exposed to JavaScript; it is a host-only, HttpOnly, SameSite cookie. The short-lived access token exists only in JavaScript memory. A page reload restores the session through the refresh cookie, concurrent requests share one refresh operation, and same-origin tabs coordinate rotation with Web Locks and `BroadcastChannel`.
- **Cookie request origin policy:** refresh and logout validate a browser `Origin` against the exact CORS allowlist or the request Host. `SameSite=None` requires `Secure` and an explicit Origin. Non-browser clients without an Origin remain supported for `SameSite=Strict` or `Lax`.
- **Current-role authorization:** administrator routes resolve the role from the database on each request rather than trusting a role copied into a bearer token.
- **Explicit CORS:** cross-origin origins come from `CORS_ALLOWED_ORIGINS`. Wildcards, userinfo, paths, queries, and fragments are rejected; production origins must use HTTPS. The CORS middleware is not installed for an empty allowlist, so no cross-origin browser access is granted.
- **Bounded requests:** JSON endpoints require `Content-Type: application/json`, reject unknown fields and trailing JSON, and enforce `REQUEST_MAX_BODY_BYTES`.
- **Canonical email:** application input is trimmed and lowercased. Migration `000004_normalize_user_identity` preflights duplicate canonical addresses, normalizes existing email/role values, constrains roles, and adds a unique canonical-email index.
- **Rate limiting:** the Redis limiter uses one atomic Lua operation for increment and expiry, returns the actual key TTL in rate-limit headers, keeps authentication traffic in a separate counter namespace, skips CORS preflight, and fails closed by default when Redis is unavailable. It is a fixed-window counter, not a sliding-window algorithm.
- **Trusted proxy boundary:** forwarding headers are ignored unless the immediate peer belongs to `TRUSTED_PROXY_CIDRS`. A trusted proxy chain is evaluated right-to-left, and `X-Real-IP` is never used as a fallback.

## Project layout

```
├── cmd/api/                         # API composition root and server lifecycle
├── cmd/admin/                       # explicit, non-promoting administrator provisioning
├── config/                          # environment configuration and validation
├── internal/delivery/handler/       # HTTP handlers, router, middleware, responses
├── internal/domain/                 # entities, DTOs, errors, interfaces
├── internal/infra/auth/             # strict JWT manager and session stores
├── internal/infra/db/               # PostgreSQL and Redis setup
├── internal/repository/             # sqlc-backed repository adapters
├── internal/usecase/                # application services
├── migrations/                      # ordered SQL migrations
├── sqlc/queries/                    # typed SQL query source
├── frontend/                        # React/TypeScript client
└── docs/openapi.yaml                # HTTP contract
```

## Prerequisites

- Go `1.26.3+`
- Node.js `22.12+` and npm
- PostgreSQL 16 and Redis 7 for a local run
- Docker Compose is optional but convenient for the local services
- `migrate` v4.20.1 and `sqlc` v1.31.1 are optional local developer tools; they are not bundled in the API image

## Local setup

```sh
git clone https://github.com/Sifr-Dev/GO_DB.git
cd GO_DB
cp .env.example .env
```

Edit `.env` before starting the API. Set `JWT_SECRET` to a unique random value of at least 32 bytes, for example `openssl rand -hex 32`; the example file intentionally leaves it empty so the known placeholder cannot be used accidentally. The example CORS origins are for the local Vite server; use an explicit HTTPS origin list for a deployed frontend. Explicitly injected environment variables take precedence over `.env`, and a process whose injected `APP_ENV` is `production` does not load `.env` at all.

Start the containerized API:

```sh
docker compose up -d --build api
```

Compose starts the pinned PostgreSQL and Redis images, runs the migrations in a one-shot service, and starts the API only after the migration exits successfully. The API listens on `http://localhost:8080` and serves the production frontend from the same image. Stop the stack with `docker compose down`; add `-v` only when the local database and Redis data may be deleted.

For a Go/Vite development loop, start the dependencies and apply migrations on the host instead:

```sh
docker compose up -d postgres redis
make migrate-up
make run
```

The Vite development server listens on `http://localhost:3000` and proxies `/api` to the API. Migration `000004_normalize_user_identity` intentionally stops if two existing accounts have the same canonical email or if an unsupported role exists. Resolve those rows explicitly before retrying; the migration does not choose which duplicate account to delete.

### Provision an administrator

The API startup path intentionally does not provision an administrator. After the database and migrations are ready, provide one-time values and run the explicit command:

```sh
ADMIN_EMAIL=owner@example.com \
ADMIN_PASSWORD='use-a-unique-password-of-at-least-12-bytes' \
ADMIN_NAME='Owner' \
go run ./cmd/admin
```

The command creates an administrator only when the normalized email does not already exist. It never promotes an existing user. Keep the password out of shell history and rotate it according to the deployment's secret-management policy.

## API examples

### Register

```sh
curl -i -X POST http://localhost:8080/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"name":"John Doe","email":"john@example.com","password":"secret123"}'
```

The JSON envelope contains `data.access_token` and `data.user`. The refresh session is set as an HttpOnly cookie; it is not included in the JSON body.

### Log in and call a protected endpoint

```sh
curl -i -c cookies.txt -X POST http://localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"john@example.com","password":"secret123"}'

TOKEN='<access-token from the JSON response>'
curl http://localhost:8080/api/v1/users/me \
  -H "Authorization: Bearer $TOKEN"
```

### Rotate and revoke a session

```sh
curl -i -b cookies.txt -c cookies.txt -X POST \
  http://localhost:8080/api/v1/auth/refresh

curl -i -b cookies.txt -c cookies.txt -X POST \
  http://localhost:8080/api/v1/auth/logout
```

The refresh response replaces the cookie. Rotation does not extend the server-side absolute family expiry. Replaying an already-consumed refresh cookie is treated as reuse and revokes the current successor family.

### Tasks

```sh
curl -X POST http://localhost:8080/api/v1/tasks \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"title":"Buy groceries","description":"Milk, eggs, bread"}'

curl http://localhost:8080/api/v1/tasks \
  -H "Authorization: Bearer $TOKEN"
```

Administrator routes are under `/api/v1/admin` and require a current database role of `admin`. The full route and error contract is in [`docs/openapi.yaml`](docs/openapi.yaml).

## Configuration reference

| Variable | Purpose | Default/requirement |
|---|---|---|
| `APP_ENV` | Runtime environment (`local`, `dev`, `prod`) | required |
| `DATABASE_URL` | PostgreSQL connection string | required |
| `REDIS_URL` | Redis connection string | required |
| `JWT_SECRET` | HS256 signing secret | required; at least 32 bytes |
| `JWT_ISSUER` / `JWT_AUDIENCE` | Token issuer and audience | `go-clean-api` / `go-clean-api-client` |
| `JWT_ACCESS_EXPIRATION` | Access-token lifetime | required |
| `JWT_REFRESH_EXPIRATION` | Absolute refresh-family lifetime | required; longer than access lifetime |
| `CORS_ALLOWED_ORIGINS` | Comma-separated exact origins | empty (same-origin only); HTTPS required in production |
| `TRUSTED_PROXY_CIDRS` | CIDRs allowed to supply forwarding headers | empty |
| `REQUEST_MAX_BODY_BYTES` | Maximum JSON body size | `1048576` |
| `RATE_LIMIT_MAX_REQUESTS` | Requests per API window | `100` |
| `RATE_LIMIT_WINDOW` | API limit window | `1m` |
| `RATE_LIMIT_FAIL_OPEN` | Whether Redis failures pass through | `false` |
| `AUTH_COOKIE_SECURE` | Secure flag for the refresh cookie | `false`; required `true` in production and with `SameSite=None` |
| `AUTH_COOKIE_SAME_SITE` | `strict`, `lax`, or `none` | `strict` |

## Development and verification

```sh
make fmt-check
make vet
make test
cd frontend && npm ci --ignore-scripts && npm test && npm run build
```

The service-backed integration suite is opt-in locally because it needs isolated PostgreSQL and Redis instances. Apply the migrations, then provide both service URLs:

```sh
GO_DB_INTEGRATION_DATABASE_URL='postgres://postgres:postgres@localhost:5432/go_db_test?sslmode=disable' \
GO_DB_INTEGRATION_REDIS_URL='redis://localhost:6379/0' \
go test -race -count=1 ./internal/integration
```

The repository CI workflow runs four independent checks: Go formatting/vet/race tests/builds; PostgreSQL and Redis integration tests with migrations and sqlc drift detection; a container build and runtime smoke test; and frontend tests, production build, and dependency audit. The integration job installs `migrate` v4.20.1 with the PostgreSQL driver and `sqlc` v1.31.1. The container job builds the image, validates Compose, applies migrations, waits for `/health`, registers a user, and calls the protected profile endpoint. `make lint` requires the separately installed `golangci-lint` binary and is not equivalent to `go vet`.

The unit suite covers JWT purpose/claims/JTI binding/rotation/reuse revocation, absolute family expiry, configuration and environment precedence, request framing, CORS, cookie Origin policy, rate-limit scope/outage policy, trusted-proxy traversal, registration error mapping, refreshed database roles, administrator provisioning, and frontend refresh/transient-failure behavior. The service-backed suite verifies real PostgreSQL registration/login/current-role behavior, HTTP cookie rotation and reuse revocation, concurrent refresh serialization, live Redis Lua rotation, session persistence across store instances, rate-limit expiry/outage policy, and credentialed CORS/cookie behavior.

## Container notes

The multi-stage `Dockerfile` pins its Node, Go, and Alpine images by digest, builds the frontend before compiling a native-architecture API binary, runs as an unprivileged user, and exposes a health check. The Compose file pins PostgreSQL, Redis, the migration image, and the development frontend image; it binds development services to loopback and is not a production deployment manifest. The API and migration services use Compose DNS names (`postgres` and `redis`) rather than `localhost`. Copy `.env.example` to `.env` before using Compose and replace the example database credentials and JWT secret.

## Known limitations

- Browser session coordination has deterministic unit coverage, but there is no real multi-browser end-to-end test in the repository.
- Cookie-authenticated refresh/logout use SameSite plus exact Origin validation rather than a separate double-submit CSRF token. A deployment that cannot use those browser controls should add a CSRF token before enabling a broader cross-site policy.
- Reuse detection revokes the affected session family, but there is no operator dashboard for reviewing reuse events or changing a user's password.
- The rollback for migration `000004_normalize_user_identity` removes the added index and role constraint but cannot reconstruct pre-normalization email or role values.
- No repository license has been added; the owner must choose one before redistribution.

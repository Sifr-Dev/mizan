<div align="center">

<img src="assets/banner.svg" alt="Aegis — layered authentication API and React client" width="100%">

# Aegis

**A layered Go API for authentication and tasks, with a React client and real session rotation.**

<p>
  <img alt="Go 1.26.3" src="https://img.shields.io/badge/GO-1.26.3-00ADD8?style=for-the-badge&logo=go&logoColor=white&labelColor=05070a">
  <img alt="React 18" src="https://img.shields.io/badge/REACT-18-61DAFB?style=for-the-badge&logo=react&logoColor=white&labelColor=05070a">
  <img alt="Tests: 65 Go + 11 frontend" src="https://img.shields.io/badge/TESTS-65_GO_%2B_11_FRONTEND-39c5cf?style=for-the-badge&labelColor=05070a">
  <img alt="License MIT" src="https://img.shields.io/badge/LICENSE-MIT-2ea043?style=for-the-badge&labelColor=05070a">
  <img alt="CI" src="https://github.com/Sifr-Dev/Aegis/actions/workflows/ci.yml/badge.svg">
</p>

</div>

> Aegis (formerly `mizan`) is a complete authentication surface: chi handlers, use
> cases, sqlc repositories, Redis-backed session families, and a Vite frontend
> that keeps the refresh token out of JavaScript.

## What it is

Aegis is a Go REST API plus React/TypeScript client for registration, login,
task ownership and explicit administrator management. The backend is layered —
delivery (chi), use cases, domain interfaces, infrastructure (pgx/sqlc, Redis,
JWT) — and the frontend consumes a documented OpenAPI contract. It is a real
implementation with a deliberately small operational surface: the claims below
describe this repository, not a hypothetical deployment.

The module path (`github.com/Sifr-Dev/mizan`) and the `go-clean-api` app name are
unchanged so imports and container identifiers keep working. The product name is
Aegis, the repository is `Sifr-Dev/Aegis` (the former `mizan` URL redirects),
and the browser UI and page title say Aegis.

## Current capabilities

### Authentication and sessions

- **Registration, login, refresh, logout** with canonicalised (trimmed,
  lowercased) email input and a unique canonical-email index added by migration
  `000004_normalize_user_identity` (`internal/usecase/`, `migrations/`).
- **Purpose-bound JWTs** — HS256 only, with `token_use`, `sid`, `jti`, issuer,
  audience, subject, `iat`, `nbf` and `exp`; a refresh token is rejected by
  protected routes (`internal/infra/auth/`; `auth_test.go`).
- **Session-backed token families** — Redis stores the current access/refresh
  JTIs per family, so a JTI cannot be substituted inside a family
  (`internal/infra/auth/`, `internal/repository/`).
- **Bounded refresh rotation** — rotation atomically consumes the current JTI,
  preserves the family's absolute expiry and issues the current database role;
  reuse of a consumed token revokes the successor family, and logout revokes the
  family (`internal/usecase/`; `usecase_test.go`).
- **Browser storage boundary** — the refresh token is a host-only, HttpOnly,
  SameSite cookie, never in JSON and never visible to JavaScript; the access
  token lives only in memory, is restored through the refresh cookie on reload,
  and concurrent requests share one refresh operation across tabs via Web Locks
  and `BroadcastChannel` (`frontend/src/api/session.ts`; 10 Node tests).
- **Cookie origin policy** — refresh/logout validate `Origin` against the exact
  CORS allowlist or the request Host; `SameSite=None` requires `Secure` and an
  explicit Origin (`internal/delivery/handler/cookie_origin.go`; handler tests).
- **Explicit administrator provisioning** — startup never creates or promotes an
  account; `cmd/admin` creates one only when the normalised email does not exist
  (`cmd/admin/main.go`).
- **Current-role authorization** — admin routes resolve the role from the
  database on each request instead of trusting a token claim
  (`internal/delivery/handler/middleware/auth.go`).

### Request handling

- **Explicit CORS** from `CORS_ALLOWED_ORIGINS`: wildcards, userinfo, paths,
  queries and fragments rejected; HTTPS required in production; middleware is
  not installed for an empty allowlist (`router.go`, `middleware_test.go`).
- **Bounded JSON** — `Content-Type: application/json` required, unknown fields
  and trailing JSON rejected, `REQUEST_MAX_BODY_BYTES` enforced (`handler_test.go`).
- **Rate limiting** — one atomic Redis Lua increment-and-expiry, real TTL in the
  rate-limit headers, separate auth namespace, preflight skipped, fail-closed by
  default (`internal/delivery/handler/middleware/ratelimit.go`).
- **Trusted proxy boundary** — forwarding headers ignored unless the peer is in
  `TRUSTED_PROXY_CIDRS`; chains evaluated right-to-left; `X-Real-IP` never used
  as a fallback (`middleware/clientip.go`; `middleware_test.go`).
- **Tasks CRUD and admin routes** under `/api/v1`, documented in
  `docs/openapi.yaml` (`task_handler.go`, `admin_handler.go`).
- **Health endpoint and graceful shutdown** in `cmd/api/main.go`.

### Verification surface

- **59 Go unit tests** plus **6 service-backed integration tests** (65 total,
  `go test ./...`).
- **10 frontend tests** with the Node test runner (`npm test`).
- **1 Playwright end-to-end test** of login → protected dashboard → logout
  (`frontend/e2e/auth.spec.mjs`).
- **Four CI jobs** — Go format/vet/race/build; PostgreSQL+Redis integration with
  migrations and sqlc drift detection; container build and runtime smoke test;
  frontend test, build, dependency audit and browser test.

## Quick start

```sh
git clone https://github.com/Sifr-Dev/Aegis.git
cd mizan
cp .env.example .env
```

Set `JWT_SECRET` to a unique value of at least 32 bytes (`openssl rand -hex 32`);
the example leaves it empty on purpose. Then:

```sh
docker compose up -d --build api      # PostgreSQL, Redis, migrations, API
```

The API listens on `http://localhost:8080` and serves the built frontend. For a
host development loop:

```sh
docker compose up -d postgres redis
make migrate-up
make run          # Vite dev server on :3000 proxies /api to the API
```

Provision the first administrator explicitly:

```sh
ADMIN_EMAIL=owner@example.com \
ADMIN_PASSWORD='use-a-unique-password-of-at-least-12-bytes' \
ADMIN_NAME='Owner' \
go run ./cmd/admin
```

Register and call a protected route:

```sh
curl -i -X POST http://localhost:8080/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"name":"John Doe","email":"john@example.com","password":"secret123"}'

curl -i -c cookies.txt -X POST http://localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"john@example.com","password":"secret123"}'
```

The access token is in `data.access_token`; the refresh session is the HttpOnly
cookie. `POST /api/v1/auth/refresh` replaces the cookie without extending the
family's absolute expiry.

## Verification

```sh
make fmt-check
make vet
make test                       # go test -race -coverprofile=coverage.out ./...
go build ./cmd/...
cd frontend && npm test && npm run build && npm run test:e2e
```

Service-backed integration suite (needs PostgreSQL and Redis):

```sh
GO_DB_INTEGRATION_DATABASE_URL='postgres://postgres:...@localhost:5432/mizan_test?sslmode=disable' \
GO_DB_INTEGRATION_REDIS_URL='redis://localhost:6379/0' \
go test -race -count=1 ./internal/integration
```

Observed on this machine (2026-11-28; Go 1.27.4, Node 26.13.1, PostgreSQL 16.16,
Valkey 8, AMD Ryzen 7 7435HS, Linux 7.3.4):

```text
go test -race ./...
  ok  config 71.0% | handler 37.7% | middleware 74.6% | infra/auth 63.3%
  ok  usecase 64.8%  (total statement coverage 44.2%)
  59 unit tests passed, 6 integration tests skipped without service URLs

GO_DB_INTEGRATION_* go test -race ./internal/integration
  ok  6 integration tests passed against real PostgreSQL 16 and Valkey 8

frontend: npm test -> 10 passed, 0 failed
frontend: npm run build -> 1937 modules, dist/assets index-D-Vye4Vm.js 399.19 kB (128.48 kB gzip)
frontend: npm run test:e2e -> 1 passed (login, dashboard, logout)
```

The container job and `npm audit` were not run locally (no Docker daemon on this
host); CI runs both. Statement coverage is 44.2% overall because `cmd/*`,
`internal/domain`, `internal/infra/db`, `internal/repository` and generated code
contain no tests; that is reported rather than rounded up.

## Architecture

```text
┌─────────────────────────────────────────────────────┐
│ Delivery      chi handlers, middleware, CORS, JSON   │
├─────────────────────────────────────────────────────┤
│ Use cases     user, task, administrator services     │
├─────────────────────────────────────────────────────┤
│ Domain        entities, DTOs, repository interfaces  │
├─────────────────────────────────────────────────────┤
│ Infra         pgx/sqlc, Redis sessions, JWT          │
└─────────────────────────────────────────────────────┘
```

| Path | Responsibility |
|---|---|
| `cmd/api/` | Composition root, server lifecycle |
| `cmd/admin/` | Explicit, non-promoting administrator provisioning |
| `config/` | Environment parsing and validation |
| `internal/delivery/handler/` | Handlers, router, middleware, responses |
| `internal/usecase/` | Application services |
| `internal/domain/` | Entities, DTOs, errors, interfaces |
| `internal/infra/auth/` | JWT manager and session stores |
| `internal/repository/` | sqlc-backed adapters |
| `migrations/`, `sqlc/queries/` | Schema and query source |
| `frontend/` | React/TypeScript client and Playwright test |
| `docs/openapi.yaml` | HTTP contract |

## Limitations

- Browser session coordination has deterministic unit coverage and one mocked
  Playwright flow; there is no real multi-browser end-to-end test.
- Cookie-authenticated refresh/logout rely on SameSite plus exact Origin
  validation rather than a double-submit CSRF token. A deployment that cannot use
  those browser controls should add a CSRF token before widening the policy.
- Reuse detection revokes the affected family, but there is no operator dashboard
  for reuse events and no password-change flow.
- The rollback for migration `000004` drops the index and role constraint but
  cannot reconstruct pre-normalisation email or role values.
- The rate limiter is a fixed-window counter, not a sliding-window algorithm.
- No email verification, password reset, MFA, or account deletion.
- `make lint` needs a separately installed `golangci-lint`; CI uses `go vet`.

## Roadmap (NOT IMPLEMENTED)

- Real multi-browser E2E coverage and a CSRF token mode.
- Password change, reset and email verification flows.
- Sliding-window rate limiting and per-route budgets.
- Admin audit log for reuse and role changes.
- Refresh-family listing/revocation UI for the account owner.
- OpenAPI-generated client types instead of hand-written ones.
- A load benchmark for the auth and task routes.

## License

MIT. See [LICENSE](LICENSE).

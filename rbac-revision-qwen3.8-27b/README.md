# RBAC Benchmark Service (Go)

An in-memory, multi-tenant, role-based access control (RBAC) HTTP API for a
commerce management service. It is a complete, self-contained implementation of
the public challenge spec in `qwen_prompt.md`: standard library only, no
database, no external auth, thread-safe in-memory store, default-deny
centralized authorization.

This is the **implementation under evaluation**. The authoritative contract is
the public spec; this README documents the exact contract the code implements.

---

## Build, run, test

The project is a single Go module (`module rbac`, Go 1.27). No external
dependencies.

```sh
# Build
go build ./...

# Run (default port :8080)
go run . -addr :8080 -seed=true
# or a compiled binary
go build -o rbac . && ./rbac -addr :8080

# Lint / format
gofmt -l .
go vet ./...

# Tests (unit + HTTP integration)
go test ./...

# Race detector (concurrency / TOCTOU checks)
go test -race ./...
```

### Flags

| Flag    | Default  | Meaning                          |
|---------|----------|----------------------------------|
| `-addr` | `:8080`  | `host:port` to listen on         |
| `-seed` | `true`   | Load the public fixture dataset   |

On a normal start the server prints the exact opaque-token fixtures to the log,
e.g.:

```
acme   / u-acme-admin     admin                                  Bearer tok-acme-u-acme-admin
globex / u-multi          viewer (tenant-specific role)          Bearer tok-globex-u-multi
```

---

## Authentication & identity model

- **Authentication** is an *opaque bearer token* in the
  `Authorization: Bearer <token>` header. The token string is opaque: a client
  cannot read identity out of it. The **server** holds the only mapping
  `token -> {user, tenant}`.
- **The tenant is fixed by the token**, not by any client-supplied header,
  query string, or JSON field. This is what enforces strict tenant isolation:
  a caller can only ever reach the data of the tenant their token grants.
- **The role is resolved live** from the tenant membership table on every
  request, so membership updates and revocations take effect on the next
  request.
- **Client-supplied identity is never trusted.** `X-User-Id`, `X-Role`, or a
  `role`/`userId`/`tenant` field in the JSON body are ignored for
  authorization; they only ever name a *target* of an authorized operation.

### Membership & tenants

- Users may hold **different roles in different tenants** (see `u-multi`:
  admin in `acme`, viewer in `globex`).
- A user with **no membership** in the requested tenant is forbidden (403) for
  every operation on that tenant.
- Membership management (`/api/v1/members`) is **admin-only** within a tenant.
- **Last-admin protection**: a tenant's final administrator cannot be removed or
  demoted (409 Conflict) until another admin exists.

---

## Tenants, members, tokens (seeded when `-seed=true`)

| Tenant   | Members                                             |
|----------|-----------------------------------------------------|
| `acme`   | `u-acme-admin` (admin), `u-acme-manager` (manager), `u-acme-v`/`u-acme-v2` (viewer), `u-multi` (admin) |
| `globex` | `u-globex-admin` (admin), `u-multi` (viewer)        |

Opaque token format: `tok-<tenant>-<user>`, e.g. `tok-acme-u-acme-admin`.
Every user also has a token matching their tenant; newly added members get a
token minted automatically (`tok-<tenant>-<user>`).

---

## Permission matrix

`R`=read/list, `C`=create, `U`=update, `D`=delete. Viewer ownership applies
where noted. Tenant isolation and the audit-log read-only rule always apply.

| Resource     | Admin | Manager | Viewer           |
|--------------|-------|---------|------------------|
| Products     | CRUD  | CRU     | R                |
| Prices       | CRUD  | RU      | R                |
| Orders       | CRUD  | CRU     | R, own only      |
| Customers    | CRUD  | RU      | none             |
| Invoices     | CRUD  | CR      | R, own only      |
| Payments     | CRUD  | R       | none             |
| Refunds      | CRUD  | CR      | none             |
| Inventory    | CRUD  | RU      | R                |
| API Keys     | CRUD  | none    | none             |
| Audit Logs   | R     | R       | none             |
| Members      | CRUD  | none    | none             |

Default deny governs anything not listed.

---

## API

Base path: `/api/v1/<resource>`. A small public liveness probe `GET /health`
needs no auth.

### Generic resource routes (all ten resources)

| Method | Path                              | Behavior                                   | Verb |
|--------|-----------------------------------|--------------------------------------------|------|
| GET    | `/api/v1/<resource>`              | List (filter + pagination)                 | R    |
| GET    | `/api/v1/<resource>/{id}`         | Get one                                     | R    |
| POST   | `/api/v1/<resource>`              | Create                                     | C    |
| PUT    | `/api/v1/<resource>/{id}`         | Full replace update                        | U    |
| PATCH  | `/api/v1/<resource>/{id}`         | Partial update                             | U    |
| DELETE | `/api/v1/<resource>/{id}`         | Delete                                     | D    |

For `audit-logs`, only `GET` (list) is allowed; any write is `405`.

### Member management (admin-only)

| Method | Path                       | Behavior                 |
|--------|----------------------------|--------------------------|
| GET    | `/api/v1/members`          | List members (paginated) |
| POST   | `/api/v1/members`          | Add {`user`,`role`}      |
| PATCH  | `/api/v1/members/{user}`   | Promote/demote {`role`}  |
| DELETE | `/api/v1/members/{user}`   | Revoke membership        |

### Nested (parent-child, child-of-order)

| Method | Path                              | Behavior                                   |
|--------|-----------------------------------|--------------------------------------------|
| GET    | `/api/v1/orders/{id}/payments`    | Payments of an order (needs R on both)     |
| GET    | `/api/v1/orders/{id}/refunds`    | Refunds of an order (needs R on both)      |
| GET    | `/api/v1/orders/{id}/invoices`   | Invoices of an order (needs R on both)     |

Child creation enforces **parent referential integrity**: a `payment`/`refund`/
`invoice`/`price`/`inventory` record requires its parent (`order`/`product`) to
exist in the same tenant, and the actor must hold read on the parent.

### List filtering & pagination

Query parameters:

| Param    | Effect                                                        |
|----------|---------------------------------------------------------------|
| `limit`  | Page size (default 20, max 100; non-numeric / negative → 400) |
| `offset` | Page offset (default 0; negative → 400)                       |
| `owner`  | Filter to this owner (owner-scoped resources support it)      |
| `status` | Filter to this status string                                  |
| `parent` | Filter to this parent id (child resources)                    |

List responses are an envelope:

```json
{ "items": [ ... ], "total": 12, "limit": 20, "offset": 0, "hasMore": false }
```

### Field model (resource-specific fields are free-form JSON)

Core fields (server-assigned / immutable after create): `id`, `tenant`,
`createdAt`, `updatedAt`, and for owner-scoped resources `owner`. Child
resources carry the parent id in the conventional field (`product` for
`prices`/`inventory`, `order` for `payments`/`refunds`/`invoices`).

Create-validation requires (per resource): `products`{sku,name}, `prices`
{product,amount}, `orders`{customer,status}, `customers`{name,email},
`invoices`{order,amount}, `payments`{order,amount}, `refunds`{order,amount},
`inventory`{product,quantity}, `api-keys`{name}. Numeric fields
(`amount`, `quantity`, `unitPrice`) must be numeric; `quantity` must be a
non-negative integer; `email` must contain `@`.

---

## Status codes & precedence

For a protected request the following precedence is applied, top to bottom:

1. Missing / malformed / unknown bearer token → **401**
2. Caller has no membership in the token's tenant → **403**
3. Unknown resource type → **404**
4. HTTP method not permitted for *any* role on that resource → **405**
5. Resource / object not found in the tenant → **404**
6. Role lacks the verb, ownership mismatch, cross-tenant, or last-admin rule → **403** (or **409** for the last-admin rule)
7. Validation failures → **400**

Success: **200** (GET/list/update/delete-confirmed), **201** (create),
**204** (member delete, confirmed removal).

Errors use a uniform envelope:

```json
{ "error": { "code": "forbidden", "message": "..." } }
```

where `code` ∈ `bad_request`, `unauthorized`, `forbidden`, `not_found`,
`method_not_allowed`, `conflict`.

**Denied writes never mutate state.** A forbidden create/update/delete returns
the 4xx and leaves the store unchanged (covered by tests).

---

## Concurrency & correctness

A single `sync.RWMutex` guards all state. Reads take the read lock; every
mutating store method takes the **write lock and re-resolves the authoritative
role from the membership table before mutating**. This closes the
time-of-check/time-of-use gap for concurrent membership changes (verified by
`go test -race`). The store's `principal` role field is advisory only — it is
never trusted.

---

## Test coverage

`go test -race ./...` runs:

- **`roles_test.go`** — the full permission matrix, audit-log read-only,
  default-deny/unknown-resource, and 405 detection.
- **`store_test.go`** — revocation-takes-effect, deny-leaves-state-unchanged,
  last-admin protection, admin-only member management, tenant isolation,
  tenant-specific roles, owner scoping, parent integrity, audit append, and two
  concurrency/TOCTOU tests.
- **`server_test.go`** — black-box HTTP: 401/403/404/405 behavior, forged
  identity headers are ignored, cross-tenant isolation, nested routes,
  validation (400), member management, last-admin over HTTP, and
  membership-change-takes-effect over HTTP.

Run with: `go test -race -count=1 ./...` (the concurrency tests use the race
detector).

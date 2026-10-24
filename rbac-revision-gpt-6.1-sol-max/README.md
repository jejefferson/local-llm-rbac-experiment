# In-memory Go RBAC API

This repository implements the ten-resource challenge in `Flint_prompt.md` using
only the Go standard library. The starting directory contained the prompt alone;
there was no separately exported API specification, starter code, or test suite.
The HTTP contract and public fixtures below define those missing details. The
original prompt is unchanged.

## Build, run, and test

Go 1.22 or newer is required. There are no dependencies to download. These commands
disable module downloads and automatic toolchain downloads explicitly:

```sh
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
go build -buildvcs=false -o /tmp/rbac .
/tmp/rbac -addr 127.0.0.1:8080
```

Both entrypoints use the same implementation:

```sh
go run -buildvcs=false . -addr 127.0.0.1:8080
go run -buildvcs=false ./cmd/server -addr 127.0.0.1:8080
```

`-addr` defaults to `:8080`; `-addr 127.0.0.1:0` chooses an available port and logs
the actual address. The executable handles SIGINT/SIGTERM with graceful shutdown.
Fixtures are embedded, so the binary can run from any working directory.
`-buildvcs=false` permits building this exported directory without Git metadata.

```sh
go test ./...
go test -race ./...
go vet ./...
```

The Makefile supplies `build`, `run`, `test`, `race`, `vet`, and `check` targets.
`make check` runs tests, the race detector, and vet with module downloads disabled.

## Authentication and initial data

`GET /health` returns `200 {"status":"ok"}` without authentication. All other
requests require `Authorization: Bearer <token>`. Tokens are case-sensitive opaque
strings resolved to an immutable server-side identity. The Bearer scheme is
case-insensitive. Multiple Authorization headers are rejected. Headers such as
`X-Role`, `X-User-ID`, and `X-Tenant-ID` have no effect. Query parameters and request
bodies never establish identity or grant a role.

The public fixture is [`internal/rbac/fixtures/seed.json`](internal/rbac/fixtures/seed.json).
Every fresh process starts with the same two tenants, six identities, memberships,
and records of all ten resource types:

| User ID | Role in `tenant-a` | Role in `tenant-b` | Bearer token |
| --- | --- | --- | --- |
| `user-admin` | admin | viewer | `fX3jVrw2gnN8RAq4zv7CkPy5LWa0eJu1bM9sHD6QotE` |
| `user-manager` | manager | admin | `sK9cBhV4dT2xJF0pL7mQyN8uW5rzG3aE6nH1oAvXikI` |
| `user-viewer` | viewer | manager | `vD5qTk8WJ0yPeR4gN2bAx6LrH1sCU3F9iz7mOaYwXnE` |
| `user-viewer-2` | viewer | viewer | `hG2mQn7XzR4cV9wK1aF6sL8yT0bDP5eU3jNiAoCvWkM` |
| `user-admin-2` | no membership | admin | `pR8wYj2NvK6bD0sL4aF9mT1xU7cHe5G3qZiAoCkXnVM` |
| `user-outsider` | no membership | no membership | `zN4xWc9TjH2bR7vL0mK5sD8yP1aFG6eU3qAiOoCvXkM` |

Useful records in `tenant-a` include `product-a-1`, `product-a-2`, `price-a-1`,
`customer-a-1`, `customer-a-2`, `payment-a-1`, `refund-a-1`, `inventory-a-1`,
`api-key-a-1`, and `audit-log-a-1`. Orders `order-a-viewer`, `order-a-other`, and
`order-a-manager` belong respectively to `user-viewer`, `user-viewer-2`, and
`user-manager`. Their invoices are `invoice-a-viewer`, `invoice-a-other`, and
`invoice-a-manager` with the same owners. The fixture contains all parent links.

`tenant-b` has analogous `*-b-*` records, including `order-b-admin` and
`invoice-b-admin` owned by `user-admin`, and `order-b-other` and `invoice-b-other`
owned by `user-viewer-2`.

Membership changes apply to the next operation using the same token. They do not
change that user's roles in another tenant. Removing membership preserves records
and ownership; rejoining restores the same identity. Identity creation, token
rotation, and tenant creation are outside this API. Resource API keys are commerce
records and do not authenticate as fixture users.

## Permission matrix

`R` covers both list and item reads. `U` covers both PATCH and PUT.

| Resource/path | Admin | Manager | Viewer |
| --- | --- | --- | --- |
| `products` | CRUD | CRU | R |
| `prices` | CRUD | RU | R |
| `orders` | CRUD | CRU | R, own only |
| `customers` | CRUD | RU | none |
| `invoices` | CRUD | CR | R, own only |
| `payments` | CRUD | R | none |
| `refunds` | CRUD | CR | none |
| `inventory` | CRUD | RU | R |
| `api-keys` | CRUD | none | none |
| `audit-logs` | R | R | none |
| `members` | CRUD | none | none |

Unknown roles, resources, and actions grant no permissions. Tenant membership is
required independently of resource permission. A viewer sees only orders whose
`owner_id` equals the authenticated user and invoices inherited from those orders.
This restriction applies before filtering, pagination, and totals are computed.

## Resource routes and responses

For each of the ten exact resource names above:

| Method | Path | Success |
| --- | --- | --- |
| GET | `/tenants/{tenant_id}/{resource}` | 200, list envelope |
| POST | `/tenants/{tenant_id}/{resource}` | 201, created record and Location header |
| GET | `/tenants/{tenant_id}/{resource}/{id}` | 200, record |
| PATCH | `/tenants/{tenant_id}/{resource}/{id}` | 200, updated record |
| PUT | `/tenants/{tenant_id}/{resource}/{id}` | 200, replaced record |
| DELETE | `/tenants/{tenant_id}/{resource}/{id}` | 204, empty body |

Audit writes always return 403. PATCH merges supplied editable fields. PUT replaces
editable fields, requires all required attributes, removes omitted optional fields,
and restores defaults. IDs, ownership, timestamps, generated API keys, and parent
links remain immutable. Deleting a record referenced by another commerce record
returns 409; delete its children first. There are no implicit cascades.

Each record has server-managed `id`, `tenant_id`, `created_at`, and `updated_at`
attributes. Timestamps use UTC RFC3339 with optional fractional seconds. Orders and
invoices also have `owner_id`. A newly created order belongs to the authenticated
creator. A new invoice inherits its order's owner even when staff creates it.
Client-supplied identity, tenant, role, or other read-only fields are rejected.

Example single record:

```json
{
  "id": "product-a-1",
  "tenant_id": "tenant-a",
  "name": "Coffee A",
  "description": "Whole bean coffee",
  "sku": "COFFEE-A",
  "active": true,
  "created_at": "2026-01-01T00:00:00Z",
  "updated_at": "2026-01-01T00:00:00Z"
}
```

Lists return an array even when empty:

```json
{"data": [], "total": 0, "limit": 20, "offset": 0}
```

IDs are ASCII strings of 1–128 characters containing letters, digits, `.`, `_`,
or `-`, excluding `.` and `..`. A single trailing slash is accepted. Unknown route
segments, unsupported nesting, empty path segments, and encoded slashes return 404.

### Editable JSON fields

All create/update requests require `Content-Type: application/json` (an optional
charset is allowed) and one nonempty JSON object, at most 1 MiB. Duplicate keys,
trailing JSON, unknown keys, null field values, and incorrect types are rejected.
Money is an integer in minor units, preserved as signed 64-bit JSON integers;
decimal fractions and exponent notation are rejected. Currency is three uppercase
ASCII letters. Parent reference IDs are immutable after creation.

| Resource | Required on POST/PUT | Optional fields and defaults |
| --- | --- | --- |
| `products` | `name` string | `description` string, `sku` string, `active` boolean (true) |
| `prices` | `product_id`, `amount` integer ≥ 0, `currency` | `active` boolean (true) |
| `orders` | `customer_id`, `total` integer ≥ 0, `currency` | `status` (pending), `notes` string |
| `customers` | `name` string, `email` address string | `phone` string |
| `invoices` | `order_id`, `amount` integer ≥ 0, `currency` | `number` string, `status` (draft) |
| `payments` | `order_id`, `amount` integer ≥ 0, `currency` | `invoice_id`, `method` string, `status` (pending) |
| `refunds` | `payment_id`, `amount` integer > 0 | `reason` string, `status` (pending) |
| `inventory` | `product_id`, `quantity` integer ≥ 0 | `location` string |
| `api-keys` | `name` string | `enabled` boolean (true), `scopes` array of strings (empty) |
| `audit-logs` | read-only | generated `actor_id`, `action`, `resource`, `resource_id`, `details` |

When `invoice_id` is supplied on a payment, `order_id` can be derived from that
invoice. If both are supplied they must refer to the same order. All references
must resolve in the selected tenant. A missing or foreign reference returns 404.
API key `key` values are generated with `crypto/rand` and visible only to admins.

Allowed statuses:

- Orders: `pending`, `confirmed`, `processing`, `paid`, `shipped`, `completed`, `cancelled`.
- Invoices: `draft`, `open`, `paid`, `void`, `uncollectible`.
- Payments: `pending`, `succeeded`, `failed`, `refunded`.
- Refunds: `pending`, `succeeded`, `failed`.

Required name strings must contain a non-whitespace character. Limits are in UTF-8
bytes: names and inventory locations 200; descriptions and notes 4000; SKU, phone,
invoice number, and payment method 100; refund reason 1000; email 254. Emails must
be plain addresses without display names. At most 100 nonempty scopes are accepted,
each at most 100 bytes. Optional strings can be empty. Status values describe
records; the API does not implement a payment processor or financial workflows.

### Filters, sorting, and pagination

List routes accept:

- `limit`: 1–100, default 20.
- `offset`: nonnegative integer, default 0.
- `sort`: `id` (default), `created_at`, or `updated_at`.
- `order`: `asc` (default) or `desc`.
- Exact equality filters for `id` and each scalar editable field of that resource.
  Orders/invoices also allow `owner_id`. Audit logs allow `actor_id`, `action`,
  `resource`, and `resource_id`. Array fields and API key secrets cannot be filters.

Multiple filters combine with AND. Sorting uses the ID as a deterministic tie
breaker. Time sorts compare actual instants. `total` is the visible, filtered
count before pagination. Offsets past the end return an empty array. Unknown or
repeated query parameters return 400. Query parameters are supported only on GET
collections; they cannot select a different tenant or authenticate a user.

### Nested resources

The same verbs and permissions apply to these parent/child routes:

| Path following `/tenants/{tenant_id}/` | Child foreign key |
| --- | --- |
| `products/{id}/prices[/{child_id}]` | `product_id` |
| `products/{id}/inventory[/{child_id}]` | `product_id` |
| `customers/{id}/orders[/{child_id}]` | `customer_id` |
| `orders/{id}/invoices[/{child_id}]` | `order_id` |
| `orders/{id}/payments[/{child_id}]` | `order_id` |
| `invoices/{id}/payments[/{child_id}]` | `invoice_id` |
| `payments/{id}/refunds[/{child_id}]` | `payment_id` |

Valid edges can be chained, for example
`/tenants/tenant-a/orders/order-a-viewer/invoices/invoice-a-viewer/payments`.
Every ancestor must exist, be readable, and belong to the preceding parent in the
same tenant. The final item must belong to the immediate parent. Unreadable,
foreign, or mismatched parents/items return 404. Collection results are constrained
to the parent. POST/PUT/PATCH can omit the immediate foreign key because the path
provides it; an explicitly conflicting foreign key returns 400.

## Tenant memberships

Only current tenant admins can access these routes:

| Method | Path | Body | Success |
| --- | --- | --- | --- |
| GET | `/tenants/{tenant_id}/members` | none | 200, list envelope |
| POST | `/tenants/{tenant_id}/members` | `{"user_id":"user-outsider","role":"viewer"}` | 201, member and Location |
| GET | `/tenants/{tenant_id}/members/{user_id}` | none | 200, member |
| PUT/PATCH | `/tenants/{tenant_id}/members/{user_id}` | `{"role":"manager"}` | 200, member |
| DELETE | `/tenants/{tenant_id}/members/{user_id}` | none | 204 |

A member is `{"tenant_id":"tenant-a","user_id":"user-viewer","role":"viewer"}`.
Only the three exact role strings are accepted. POST requires a known fixture user
and fails with 409 if already a member. Updating/removing a missing membership
returns 404, including users who belong only to another tenant. List filters are
`user_id` and `role`; sort keys are `user_id` (default) and `role`, with the same
pagination and order parameters as commerce lists.

Removing or demoting the last admin returns `409` with error code `last_admin`.
An admin may transfer administration by first adding/promoting another admin and
then removing/demoting itself. Concurrent changes cannot leave a tenant without
an admin. Member `user_id` is the target identity, never the request's identity.

## Errors, authorization order, and concurrency

Errors use a stable JSON envelope:

```json
{"error":{"code":"forbidden","message":"this role cannot perform the requested action"}}
```

| Status | Meaning |
| --- | --- |
| 400 | Invalid JSON, fields, filters, or inconsistent parent arguments |
| 401 | Missing/malformed/unknown bearer token; includes WWW-Authenticate |
| 403 | No membership, disallowed action, or any audit write |
| 404 | Unknown tenant/route/item/reference, or an item/parent hidden by ownership |
| 405 | Unsupported method for collection/item shape; includes Allow |
| 409 | Existing member, last-admin protection, immutable relationship, or dependent records |
| 413 | Request body exceeds 1 MiB |
| 415 | Missing or unsupported JSON Content-Type |

Except for health, authentication precedes route handling. After a route is
recognized, the server checks tenant existence, current membership, method, resource
permission, ancestor visibility, and item visibility. A denied action returns 403
before body-validation errors or object-existence details are exposed. Items from
another tenant and other users' orders/invoices are hidden with 404. These choices
define behavior where no original public specification was supplied.

The server decodes bounded input before acquiring storage locks, then rechecks
current membership and authorizes inside the operation's lock. All mutable state
uses one RWMutex: reads share a read lock, while writes include permission checks,
parent validation, last-admin checks, data mutation, and audit creation in one
exclusive critical section. Responses are deep copies made under the lock and
encoded after unlocking. There are no cached authorization decisions or gaps
between membership checks and mutations.

Each successful commerce or membership write creates an immutable audit record
with actor, action (`create`, `update`, `delete`), resource, and target ID. Membership
audit details include the new/previous role as applicable; commerce details are
null and never include API secrets. Denied/invalid writes leave all stored state,
including audits, unchanged. Reads do not create audit events.

## HTTP examples

```sh
export RBAC_TOKEN=fX3jVrw2gnN8RAq4zv7CkPy5LWa0eJu1bM9sHD6QotE

curl http://127.0.0.1:8080/health
curl -H "Authorization: Bearer $RBAC_TOKEN" \
  'http://127.0.0.1:8080/tenants/tenant-a/products?limit=10'
curl -H "Authorization: Bearer $RBAC_TOKEN" \
  -H 'Content-Type: application/json' -d '{"name":"New product"}' \
  http://127.0.0.1:8080/tenants/tenant-a/products
```

## Verification and scope

Tests exercise HTTP handlers through public request paths, including the complete
permission matrix, ownership, tenant boundaries, spoofed identities, rejected writes
with unchanged state, nested CRUD, reference integrity, exact integer amounts,
member lifecycle, and concurrent CRUD. Concurrent role changes are checked against
the serialized audit history to ensure each committed write was authorized at its
commit point. Concurrent admin removals/demotions must retain an admin.

The process is intentionally in-memory: restarting restores fixtures. One global
lock favors simple, verifiable authorization consistency. No private evaluator,
hidden tests, reference implementation, external database, or auth service is used.
Compatibility with an unavailable external specification cannot be verified.

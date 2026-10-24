# qwen prompt — Implement the Go RBAC benchmark challenge

You are the coding agent responsible for implementing an authorization service in Go.

**Your working directory contains ONLY the exported, public RBAC challenge.** Treat the API specification, permission matrix, seed fixtures, and starter interfaces in this directory as the authoritative contract. Your task is to implement that contract fully and correctly, not to build a separate application or change the benchmark's requirements.

## Mission

Implement a complete, in-memory, multi-tenant role-based access control (RBAC) HTTP API for a commerce management service. You own the implementation end-to-end: inspect the starter repository, implement missing functionality, write meaningful tests, run the program and its tests, diagnose failures, and fix them. Do not stop after generating code. Finish when the implementation is working to the fullest extent possible.

## Read before coding

1. Inspect the repository structure and read the complete public API specification, README, fixtures, and permission matrix.
2. Understand the expected executable entrypoint, startup flags, routes, JSON shapes, status codes, seed data, and test commands.
3. Identify placeholders/TODOs and existing public tests.
4. Write a brief internal implementation plan and proceed with the changes. Do not ask for confirmation between steps.

The public challenge specification overrides the abbreviated reminder below if any detail differs.

## Minimum required behavior

- Go standard library wherever practical, `net/http`, JSON, thread-safe in-memory storage; no database, no external auth service.
- Ten resource types: `products`, `prices`, `orders`, `customers`, `invoices`, `payments`, `refunds`, `inventory`, `api-keys`, `audit-logs` (use the EXACT public names and paths from the challenge specification).
- Three roles: `admin`, `manager`, `viewer`.
- Centralized authorization, default deny; all resource and member-management endpoints protected.
- Correct authentication from server-side, opaque bearer-token fixtures. Never trust roles or user IDs from client-supplied headers, query strings, or JSON payloads.
- Tenant-specific membership: users may have different roles in different tenants. Membership updates and revocations must be effective on subsequent requests.
- Respect resource ownership restrictions, parent-child relationships, filtering and pagination in list endpoints, and strict tenant isolation.
- Correct 401/403/404/405 behavior as specified; do not leak data or mutate state when access is denied.
- Reject attempts to promote a user without permission, modify other tenants, change role using forged headers, or remove/demote the last tenant administrator.
- Preserve correctness under concurrent authorization, membership changes, and CRUD requests. Do not introduce data races or time-of-check/time-of-use authorization gaps.

For convenience, the public permission matrix is repeated below (the public challenge remains the source of truth):

| Resource | Admin | Manager | Viewer |
|---|---|---|---|
| Products | CRUD | CRU | R |
| Prices | CRUD | RU | R |
| Orders | CRUD | CRU | R, own orders only |
| Customers | CRUD | RU | None |
| Invoices | CRUD | CR | R, own invoices only |
| Payments | CRUD | R | None |
| Refunds | CRUD | CR | None |
| Inventory | CRUD | RU | R |
| API Keys | CRUD | None | None |
| Audit Logs | R | R | None |

`R` = read/list, `C` = create, `U` = update, `D` = delete. Viewer ownership applies where specified. Tenant isolation always applies. Audit logs are read-only for every role.

## How to work

- Implement the complete HTTP behavior, not just authorization helpers. Build handlers, route parsing, input validation, seeded in-memory repositories, memberships, ownership restrictions, list filtering, and nested resource checks as necessary.
- Prefer simple, clear Go structures and explicit error handling. Keep the existing project layout, interfaces, and dependencies unless a change is necessary for correctness.
- Add meaningful unit and HTTP integration tests that exercise both permitted and rejected requests. In particular, test cross-tenant object access, role changes and revocations, spoofed identity headers, a user's own versus another user's orders/invoices, and denied writes that must leave state unchanged.
- Run `gofmt`, the repository's test commands, and `go test -race ./...` where supported. Fix real failures; do not silence failing tests by weakening assertions or skipping test cases.
- Exercise the HTTP API through its public routes, not only through function-level tests. Ensure the entrypoint and startup contract match the public specification so an external evaluator can run it.
- Do not remove or rewrite the task specification to make implementation easier.

## Evaluation integrity (mandatory)

- Work only within the exported challenge directory provided to you.
- **Do not look for, inspect, open, or import the reference implementation, private evaluator, hidden tests, negative-control variants, or any parent/sibling directories that might contain them.** They are intentionally excluded from your working copy.
- Do not modify the evaluator, test harness, scoring logic, environment, or hidden test fixtures. Do not hard-code test-case responses.
- Use only public specification, public tests, observed program behavior, and your own implementation.
- Do not access external networks to obtain a solution. Use the existing project and local Go toolchain.
- Never claim hidden tests passed; you cannot run them from this challenge directory.

## Definition of done

Continue implementing and testing until all of the following hold, or you encounter a concrete blocker you cannot resolve:

1. The application builds and starts using the documented startup command and address flag.
2. All ten resources, memberships, and nested relationships have the required endpoints and authorization behavior.
3. Public tests pass, including HTTP behavioral tests.
4. New unit and integration tests cover positive and negative security cases.
5. `go test -race ./...` passes where supported.
6. The implementation and tests are formatted, self-contained, and ready for independent black-box evaluation.

At the end, respond briefly with:
- What you implemented.
- The exact build/run/test commands actually executed.
- Number of tests passing and failing, if available.
- Any incomplete requirements or known limitations.

**Start inspecting the challenge project now, implement it, and verify the result autonomously.**

# Can a local LLM build a secure RBAC service?

This repository holds the code that three AI coding agents generated for the LinkedIn article
[Can a local LLM build a secure RBAC service quickly, with just one prompt?](https://www.linkedin.com/pulse/can-local-llm-build-secure-rbac-service-quickly-just-one-vladimir-wsiof/)

The code is published exactly as the agents left it. We did not fix or change anything.

> **Warning.** This is experimental code with known security bugs (see below). Do not use it in production.
> All tokens in the code are test fixtures.

## The idea

Broken access control is the number one risk in the [OWASP Top 10 2025](https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/).
Many companies still have no real RBAC, or have one with gaps. We wanted to know how close we are to a laptop that can
close this gap by itself, with little help from a developer.

Every agent got the same prompt in an empty folder: build a multi-tenant commerce API in Go, with role-based access
control as the core and ten business endpoints around it (products, prices, orders, customers, invoices, payments,
refunds, inventory, API keys, audit logs). Every endpoint must be protected by RBAC. The prompt file is inside each
folder (`Flint_prompt.md` or `qwen_prompt.md`, same text).

## The three agents

| Folder | Model | Where it ran | Agent | Time |
| --- | --- | --- | --- | --- |
| [`rbac-revision-gpt-6.1-sol-max`](rbac-revision-gpt-6.1-sol-max) | GPT-6.1-Sol, reasoning effort max | cloud, regular subscription | Codex CLI | 26.5 min |
| [`rbac-revision-flint-64k`](rbac-revision-flint-64k) | Flint (`flint:latest`, 40B mixture of experts) with a 64k context window | laptop, offline | OpenCode + Ollama | 35.5 min |
| [`rbac-revision-qwen3.8-27b`](rbac-revision-qwen3.8-27b) | Qwen3.8 27B (`qwen3.8:27b-mlx`, dense) | laptop, offline | OpenCode + Ollama | 118 min |

The local models were started like this:

```sh
ollama launch opencode --model flint-64k
ollama launch opencode --model qwen3.8:27b-mlx
```

Hardware for the local runs and for all tests: MacBook Pro M4 Max, 36 GB RAM.

## How to run

Each folder is a separate Go module with no external dependencies.

```sh
cd rbac-revision-gpt-6.1-sol-max && go test ./... && go run ./cmd/server -addr 127.0.0.1:8080
cd rbac-revision-flint-64k       && go test ./... && go run . -addr 127.0.0.1:8080
cd rbac-revision-qwen3.8-27b     && go test ./... && go run . -addr 127.0.0.1:8080
```

Tokens, users and API paths are different in each folder, because none of the agents received a common API contract.
See the agent's own README (GPT-6.1-Sol, Qwen) or the seed data in the code (Flint).

## What we measured

- Does the code build, pass `go vet`, `gofmt` and its own tests, also with the race detector.
- Time, mistakes and speed of each agent, taken from the session logs.
- A black-box security probe against each service through its own API: the full permission matrix
  (10 resources x 3 roles x 4 actions), authentication, tenant isolation, ownership, role management,
  concurrency and input handling.
- Manual code review for vulnerabilities, structure and how easy the code is to extend.
- Load tests with `wrk` at `GOMAXPROCS=10`.

## Results

| | GPT-6.1-Sol max | Flint 64k | Qwen3.8 27B |
| --- | --- | --- | --- |
| Session time | 26.5 min | 35.5 min | 118 min |
| Runs where code did not compile | 0 | 5 | 6 |
| Runs with failing tests | 0 | 3 | 2 |
| Security checks passed | 186 / 186 | 165 / 172 | 166 / 172 |
| Permission matrix | 120 / 120 | 120 / 120 | 120 / 120 |
| Critical or high findings | 0 | 4 | 4 (1 critical) |
| Data races under load | 0 | 15 reports | 13 reports |
| Server crash under load | no | no | yes |
| Unit test coverage | 89% | 27% | 70% |
| Code / test lines | 1,203 / 990 | 2,315 / 212 | 1,756 / 681 |

Main problems we found:

- **Flint:** a manager can remove other members, even admins; data races; a new customer overwrites a seeded one;
  tokens can be built from a user name; order ownership is taken from the request body.
- **Qwen:** two normal users can crash the whole process (`concurrent map iteration and map write`), which also
  deletes all in-memory data; the last admin can be removed through `POST /members`; no request size limit;
  tokens can be built from a user name; order ownership is taken from the request body.
- **GPT-6.1-Sol:** no security bug found; lists get slow on very large data.

## Conclusion

1. **GPT-6.1-Sol max.** A complete, clean solution that passed every check, in under half an hour, with no failed
   build or test along the way. You can run it, review it and ship it.
2. **Flint 64k.** Fast and stable on a long session with a big context, on a laptop with no internet. It made many
   small tool mistakes inside OpenCode, and on the first attempt it failed security and concurrency, like Qwen.
   But it finished more than three times faster, so with the same time budget it would have room to catch up.
   Mixture-of-experts models make long local agent sessions realistic.
3. **Qwen3.8 27B.** A smart start, but the growing context slowed it down a lot. It finished, barely, after two
   hours of a laptop at full load. That defeats the idea of working offline on the road. Good for small tasks
   and reviews.

**Local models can already build a working service. They cannot secure it yet.**
Please do not let local models write your access control.

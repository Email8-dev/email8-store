# Sentin8 Email8:Store - Mail & Collaboration Data Core

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
[![Built with Rust](https://img.shields.io/badge/Built%20with-Rust-orange.svg)](https://www.rust-lang.org/)
[![Docs](https://img.shields.io/badge/docs/read-3aa757.svg)](https://email8.dev/docs/products/store)
[![Website](https://img.shields.io/badge/website-email8.dev-1a73e8.svg)](https://email8.dev)

## 1. Summary

Email8:Store is the mail plane's data core: mailboxes, messages,
folders, contacts, calendars (the `email8` schema), plus the JMAP
API - the authenticated read/write surface for the other mail
services and user clients.

## 2. Architecture

```mermaid
graph TD
    MTA[Email8:Mta] -- blobs --> STORE[Store<br/>email8 schema + JMAP]
    ACCESS[Email8:Access] -- M2M data API --> STORE
    STORE -- message blobs --> OSS[Sentin8:Storage]
    STORE -- domain events --> OB[(store.outbox)] -- 8b relay --> BUS[Sentin8:Bus
    POST /v1/produce]
```

## 3. Key Traits

- Owns the `email8` database schema (mailboxes, messages, groupware)
  with standard RLS discipline: account-scoped tables
  (holder-or-admin tier), env-scoped config tables, `principals` as
  the env-tier root (writes service-layer-gated; SELECT admits the
  auth-user holder-match), and `domains` as the NO-RLS mail-domain→env
  discovery catalog (the MTA resolves recipient domains pre-tenant -
  the bank8-fdx `provider_profiles` precedent; design
  `../../design/sentin8-provisioned-rls-and-telemetry-design.md`).
  The tenant context is transaction-local: every stamp + query
  sequence runs inside ONE explicit transaction on ONE connection.
- The local outbox lives in the `store` leaf schema (`store.outbox`,
  OUTBOX-EMAIL8 - the DBX producer path; the shell's 8b relay drains
  it to Bus `POST /v1/produce`, idempotency_key = row id).
- Audit journal (AUDJOUR-1, architecture-principles §6.8): the
  `store.audit_journal` leaf-schema table (migration v4 - the 15-column
  `sentin8_audit::audit_journal_sql` contract) is drained to Sys
  `POST /v1/audit` by the shell's boot-8c pusher, presenting the
  `store-audit` workload certificate (`sentin8:sys:audit:write`).
- Message blobs go to Sentin8:Storage; Store keeps the metadata +
  indexes.
- M2M: certificate identity (CERTFREE-4V) - internal callers present
  their workload certs; bus events via the local outbox →
  produce API (inbox-first).

See the vertical group docs (`email8/README.md`) for the plane
overview.

---

**Design attribution:** email8:store and its underlying concepts were designed by Hamid Jahanzad <Hamid@Jahanzad.com>.

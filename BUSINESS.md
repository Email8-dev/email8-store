# Email8:Store - Business Requirements & Functionality

> Audience: product owners, business analysts, and anyone evaluating what
> Email8:Store **does for the business**. For architecture read `README.md`;
> for wire-level detail read `DESIGN.md`.

## 1. Business Purpose

Email8:Store is the **system of record for mail and collaboration
data**. It delivers:

- **One source of truth for mailboxes** - every message, folder,
  thread, contact, calendar event, and file that a user owns lives in
  Store's schema, so any client (webmail, IMAP, POP3, migration tools)
  sees the same truth.
- **A modern protocol surface** - JMAP gives web and mobile clients
  efficient, state-token-based sync (no poll-and-diff guessing), plus
  push via SSE and JMAP-over-WebSocket.
- **A protocol-neutral core** - IMAP UIDs, JMAP state strings, and DAV
  sync tokens all derive from one changelog, so adding a new protocol
  never forks the data.
- **Automatic account readiness** - the moment a platform user exists,
  the mail account (principal + standard folders + identity) exists
  too - within seconds, idempotently, with no manual step.
- **Safe sharing and quotas** - 16-bit ACL rights on shared folders
  and collections, and account quotas enforced before any write.

## 2. Business Scope (What the Service Provides)

| # | Capability area | What the business gets |
|---|---|---|
| 1 | Principals & addresses | Mail account registry bound to platform identities; aliases, sub-addressing, catch-all, group membership |
| 2 | Mailboxes | Folder tree with special-use bootstrap (INBOX, Trash, Junk, Drafts, Sent, Archive), per-mailbox UIDs |
| 3 | Messages | Message metadata, keywords, threads, per-folder membership, full-text search readiness |
| 4 | JMAP core | RFC 8620 batch API (`Mailbox`, `Email`, `Thread`, `Identity`, `PushSubscription`, `EmailSubmission`, changes) |
| 5 | JMAP groupware | `Calendar`, `CalendarEvent`, `AddressBook`, `ContactCard` methods |
| 6 | Attachments/blobs | Upload/download endpoints; content-addressed storage; blob quota checks |
| 7 | Push | SSE EventSource (per-account Email/Mailbox state), RFC 8887 JMAP-over-WebSocket |
| 8 | Submission bridge | `EmailSubmission/set` stores the draft then hands off to the MTA via its internal submit |
| 9 | Internal data API | The typed surface IMAP/POP3/Sieve/DAV/MTA consume (resolve, ingest, lists, changes, ACL, sieve CRUD, quota, email fetch) |
| 10 | Sieve backing store | Script storage + activation (bytes in Storage) |
| 11 | ACL sharing | 16-bit rights, grant/revoke, effective-rights evaluation, share events |
| 12 | Provisioning | Bus consumer provision principals + folders on `sentin8:auth:user:created` |
| 13 | Quotas | Per-account byte/object counters + env policy defaults; blob-quota verdicts |
| 14 | Grouping & domains | Mailing-list groups, domain registry incl. catch-all and relay flags, per-env DNSBL zones |
| 15 | Admin console | Five admin pages (overview, users, domains, groups, quotas) rendered in the platform dashboard |
| 16 | Health | Service health endpoint for fleet supervision |

**What the service does NOT own (business boundary):**

| Out of scope | Owned by |
|---|---|
| Sending/delivering mail (queue, retries, screening) | Email8:Mta (Store proxies submissions to it) |
| Protocol session state machines (IMAP/POP3/Sieve dialects) | Email8:Access (consumes Store's data API) |
| Client ports (25/465/587/143/...) | Email8:Gate |
| Message/blob bytes | Sentin8:Storage (Store keeps metadata + indexes + reference ledger) |
| Identity, credentials | Sentin8:Auth (principals link to auth users; provisioning reacts to auth events) |
| Calendar/contact *client* sync semantics | Email8:Access (DAV layer) - Store owns the objects |
| Event transport | Sentin8:Bus (local outbox → produce; SSE consumption for provisioning) |
| Blob storage infra | Sentin8:Storage |

## 3. Business Capabilities

### 3.1 Accounts and addressing

| Capability | Business rule |
|---|---|
| Auto-provision | Every `sentin8:auth:user:created` provisions a principal + 6 bootstrap folders within seconds; redelivery never duplicates (idempotent) |
| Identity binding | Exactly one auth user per principal (`sentin8_auth_user_id` unique per env); the binding is what protocols and JMAP use to authorize |
| Aliases | Multiple addresses per account with one primary; case-insensitive uniqueness |
| Sub-addressing | `user+tag@domain` resolves by stripping the tag when enabled per domain |
| Catch-all | A domain may route unmatched addresses to one account |
| Groups | A group address fans mail out to members; resolution prefers groups before accounts |
| Time zone & locale | Per-account locale/time-zone drives client display defaults |

### 3.2 Mail data

| Capability | Business rule |
|---|---|
| Folder bootstrap | INBOX, Trash, Junk, Drafts, Sent, Archive created at provisioning with fixed special-use roles |
| Message filing | One message (deduplicated by blob hash) can live in several folders; per-folder IMAP UIDs are stable |
| Threading | Thread keys group related messages; merges are possible when late references appear |
| Keywords/flags | Keywords drive both protocol flags and behavior (junk keywords file to Junk and insert training samples for the spam model) |
| Search | `search_text` (parsed body/subject) indexed for full-text queries; keywords GIN-indexed |
| Changelog | Every mutation appends a changelog entry: JMAP state tokens, IMAP CONDSTORE/QRESYNC, and DAV sync tokens all derive from it |
| Spam-aware filing | Ingest carries a spam score; high scores file to Junk per policy threshold |

### 3.3 JMAP surface

| Capability | Business rule |
|---|---|
| Batch protocol | RFC 8620 `POST /jmap` with method call chains, `#reference` resolution, capability gating per `using` |
| Core + mail methods | `Core/echo`; `Mailbox/get,set,changes`; `Email/get,query,set,changes`; `Thread/get,changes`; `Identity/get` |
| Push subscriptions | `PushSubscription/get,set` manage per-account push endpoints |
| Submission | `EmailSubmission/set` stores the message then proxies to MTA `/v1/internal/submit` |
| Vacation | `VacationResponse/get` shape available |
| Groupware | `Calendar/get`, `CalendarEvent/get`, `AddressBook/get`, `ContactCard/get` |
| Session | `GET /jmap/session` advertises capabilities (`core, mail, submission, vacationresponse, sieve, blob, quota`) and endpoint URLs |
| Blobs | `POST /jmap/upload/{account}` uploads; `GET /jmap/download/{account}/{blob}/{name}` downloads with quota verdicts |
| Push transports | `GET /jmap/eventsource` (SSE, 1 Hz changelog poll → `event: state`) and `GET /jmap/ws` (RFC 8887 with 30 s StateChange push) |

### 3.4 Internal data API (the vertical's contract)

| Capability | Business rule |
|---|---|
| Resolve | Address → Account/Group/External verdict with alias/sub-address/catch-all precedence |
| Ingest | MTA/local-delivery filing with spam score, thread-key computation, iMIP calendar filing, changelog append, `email8:mail:email:ingested` events |
| Folders & listings | Create/list mailboxes; list mailbox emails in UID order |
| Changes | `changes_since` returns deltas per collection (the sync basis for every protocol) |
| Fetch/destroy/copy | Single email fetch (raw + metadata), email destruction, cross-folder copy |
| Keywords | Set keywords (junk moves seed training samples) |
| APPEND ingest | `ingest/append` for IMAP APPEND and client-sent copies |
| ACL | Grant/revoke 16-bit rights; effective rights query; share events emitted |
| Sieve CRUD | list/get/put/setactive/delete/rename scripts (compile checks done at the Access layer; storage here) |
| Blob quota | Pre-check verdicts before bytes are stored |

### 3.5 Sharing, quotas, and tenancy

| Capability | Business rule |
|---|---|
| 16-bit ACL | Documented rights (READ→MODIFY_RSVP) grantable per (collection, document) - shared-mailbox business flows |
| Quotas | Per-account byte/object counters; env policy defaults (10 GiB default account quota, 1 GiB outbound queue cap); writes beyond quota refused with mapped error codes |
| Tenancy | Everything is env-scoped; account tables additionally holder-scoped; the changelog is owner-only |
| Domain registry | Per-env domains with relay/report addresses; DNSBL zones per env |

## 4. Business Events (Outbound)

| Event | Fires when | Carries |
|---|---|---|
| `email8:mail:email:ingested` | a message is filed by ingest/append | mailbox + email ids, user_id (BFF filters subscriptions per session) |
| `email8:mail:thread:merge` | thread merge on late references | thread ids |
| `email8:mail:share:granted` / `email8:mail:share:revoked` | ACL grant/revoke | owner, grantee, rights |
| `email8:groupware:event:created/updated/cancelled` | iMIP calendar filing or calendar mutations | event ids |

**Inbound (consumed):**

| Event | Consumer | Effect |
|---|---|---|
| `sentin8:auth:user:created` | provisioning consumer (group `email8:store:provisioner`, stream family `auth`) | provision principal + bootstrap folders idempotently; explicit ACK; NACK-with-delay on failure |

| Channel | Content |
|---|---|
| Audit journal → Sentin8:Sys `POST /v1/audit` | Mutation audit per AUDJOUR contract |
| Telemetry → platform stat property `store` | Service counters (hourly frames) |

## 5. Business Rules & Invariants

1. **Single writer**: all mail/collaboration data is written here and
   nowhere else; Access/MTA mutate only through this service.
2. **Auto-provisioning is idempotent and prompt**: a redelivered
   `sentin8:auth:user:created` never duplicates a principal or folder;
   provisioning completes within seconds of sign-up.
3. **One changelog to sync them all**: JMAP states, IMAP UIDs/modseq
   and DAV sync tokens derive from the same changelog rows - protocol
   views cannot diverge.
4. **Blob economics**: bytes are content-addressed and stored once in
   Sentin8:Storage; reference-ledger rows keep them alive; GC only
   reclaims blobs with no live links.
5. **Quota before write**: account/blob quota checks happen before
   mutations commit; exceeded quotas produce mapped error codes, never
   silent truncation.
6. **Sharing is explicit**: no data is visible across accounts without
   an ACL grant; effective-rights checks gate every cross-account
   read.
7. **Every mutation is audited** and emits its changelog entry in the
   same transaction.
8. **Domain catalog is open for discovery**: the `domains` table is the
   pre-tenant mail-domain→env routing catalog (no RLS by design) - the
   MTA resolves recipient domains before any user context exists.

## 6. Target-User Roles & Use Cases

| Persona | What they do with Email8:Store |
|---|---|
| End users (webmail) | Read/send/mail-over-JMAP: mailbox trees, message lists, compose, search, calendar, contacts |
| Desktop/mobile clients | Sync their data through IMAP/POP3/DAV backed by Store |
| Mail administrators | Manage users, domains, groups, quotas in the dashboard |
| Email engineers / integrators | Consume the internal data API to build mailbox tooling; integrate JMAP clients |
| Spam-learning pipeline | Receives keyword-driven training samples and hands them to the MTA's learner |
| Platform onboarding | New sign-up → mail-ready account automatically (no manual provisioning) |
| Compliance/audit | Reads the audit stream for mailbox mutations |

## 7. KPIs / Success Criteria

| Category | Target |
|---|---|
| Consistency | One changelog as the sync basis for JMAP/IMAP/DAV - zero protocol-view divergence |
| Provisioning | Principal + folders live ≤ seconds after sign-up; duplicate events are no-ops |
| Sync efficiency | `changes_since` returns only deltas; push streams deliver state changes within ~1s |
| Data safety | Blob dedupe + reference ledger mean content is never orphaned while linked; quotas never over-committed |
| Search | Full-text and keyword queries use indexes (GIN/tsvector) with predictable latency |
| Sharing | ACL decisions enforced server-side on every cross-account access |
| Auditability | 100% of mutations journalled |

## 8. Dependencies & Reliance on Other Services

| Relied on | For |
|---|---|
| Sentin8:Auth | Identity linkage (principal ↔ user binding); provisioning event source |
| Sentin8:Bus | Event production (local outbox → produce) and provisioning consumption (SSE) |
| Sentin8:Storage | Message bytes, sieve script bytes (metadata + reference ledger local) |
| Email8:Mta | Outbound submission execution (proxy-back on `EmailSubmission/set`) |
| Email8:Gate | Client-facing ports for JMAP HTTPS + all downstream protocol services |
| Shield (Sentin8:Policy) | Per-request decisions; hot reload via the `-policy` workload |
| Sentin8:Sys | Audit journal drain |
| Sentin8:Stat | Telemetry property + metric ingest |

## 9. Acceptance Criteria

1. A new platform user with an email address gets a principal, the six
   bootstrap folders, and can receive mail without any manual step;
   duplicate create events are no-ops.
2. JMAP batch requests resolve `#references`, enforce capability
   gating, and return per-method results/errors per RFC 8620.
3. `EmailSubmission/set` enqueues through the MTA and the sent copy is
   filable into Sent.
4. Upload/download obey quotas; over-quota uploads are refused with
   mapped errors.
5. Ingest resolves sub-addressing, aliases, catch-all, and groups in
   the documented precedence, files with thread grouping and spam
   re-filing, and appends changelog entries.
6. `changes_since` returns complete deltas per collection; the SSE and
   WebSocket push surfaces report the same state.
7. ACL grant/revoke is effective immediately and audited; effective
   rights reflect grants.
8. Sieve scripts round-trip through the internal API with activation
   semantics.
9. The admin pages (overview/users/domains/groups/quotas) render
   live data with proper gating.
10. `make build`, `make test` (policy suite, OpenAPI drift floor), and
    `make lint` pass.

## 10. Open Business Questions

- VacationResponse is currently a get-only shape - activation rules
  (auto-reply generation) are a future business decision.
- File-node (WebDAV) quotas and per-collection sharing UX details.
- Cross-env mailbox sharing (today sharing is intra-env).

---

**Design attribution:** email8:store and its underlying concepts were designed by Hamid Jahanzad <Hamid@Jahanzad.com>.
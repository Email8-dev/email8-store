-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Email8:Store
-- SPDX-License-Identifier: Apache-2.0

-- Email8:Store — mail/collaboration data core.
--
-- Replaces the legacy KV subspaces (p/i/l/n/a/t/k/d/s/b/g) with real
-- relational tables. Every tenant table carries env_id + account_id and
-- gets FORCE RLS with the standard isolation policy (store design §2).
--
-- Design: email8/design/sentin8-email8-store-technical-design.md.

CREATE SCHEMA IF NOT EXISTS email8;

-- ── Principals ──────────────────────────────────────────────────────────
-- One row per Sentin8:Auth user holding mail in this env. Provisioned by
-- the `sentin8:auth:user:created` consumer (event-driven env-init).
CREATE TABLE IF NOT EXISTS email8.principals (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id              UUID NOT NULL,
    sentin8_auth_user_id UUID NOT NULL,
    name                TEXT NOT NULL,                -- primary email address
    display_name        TEXT,
    locale              TEXT,
    time_zone           TEXT,
    quota_bytes         BIGINT NOT NULL DEFAULT 0,   -- personal override (0 = env default)
    active_script_id    UUID,
    default_calendar_id UUID,
    default_addressbook_id UUID,
    is_group            BOOLEAN NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, sentin8_auth_user_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS email8_principals_name
    ON email8.principals (env_id, lower(name));

-- Address aliases (RCPT sub-addressing targets + MAIL FROM sender binding)
CREATE TABLE IF NOT EXISTS email8.principal_addresses (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id      UUID NOT NULL,
    account_id  UUID NOT NULL REFERENCES email8.principals(id) ON DELETE CASCADE,
    address     TEXT NOT NULL,
    is_primary  BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE UNIQUE INDEX IF NOT EXISTS email8_pa_uniq_addr
    ON email8.principal_addresses (env_id, lower(address));

-- ── Domains (mail domains served by this tenant) ────────────────────────
CREATE TABLE IF NOT EXISTS email8.domains (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id        UUID NOT NULL,
    name          TEXT NOT NULL,
    description   TEXT,
    is_enabled    BOOLEAN NOT NULL DEFAULT TRUE,
    catch_all_account_id UUID REFERENCES email8.principals(id) ON DELETE SET NULL,
    sub_addressing_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    allow_relaying BOOLEAN NOT NULL DEFAULT FALSE,
    report_address TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS email8_domains_uniq_name
    ON email8.domains (env_id, lower(name));

-- ── Groups / mailing lists ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS email8.groups (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id      UUID NOT NULL,
    address     TEXT NOT NULL,
    description TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS email8_groups_uniq_addr
    ON email8.groups (env_id, lower(address));
CREATE TABLE IF NOT EXISTS email8.group_members (
    group_id      UUID NOT NULL REFERENCES email8.groups(id) ON DELETE CASCADE,
    env_id        UUID NOT NULL,
    member_address TEXT NOT NULL,
    PRIMARY KEY (group_id, member_address)
);

-- ── Mailboxes ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS email8.mailboxes (
    id            UUID NOT NULL DEFAULT gen_random_uuid(),
    env_id        UUID NOT NULL,
    account_id    UUID NOT NULL REFERENCES email8.principals(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    role          TEXT,                          -- inbox|trash|junk|drafts|sent|archive|…
    parent_id     UUID,
    sort_order    INT NOT NULL DEFAULT 0,
    uid_validity  BIGINT NOT NULL,
    uid_next      BIGINT NOT NULL DEFAULT 1,
    is_subscribed BOOLEAN NOT NULL DEFAULT TRUE,
    version       BIGINT NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, id),
    UNIQUE (account_id, name)
);

-- ── Emails ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS email8.emails (
    id            UUID NOT NULL DEFAULT gen_random_uuid(),
    env_id        UUID NOT NULL,
    account_id    UUID NOT NULL REFERENCES email8.principals(id) ON DELETE CASCADE,
    blob_hash     TEXT NOT NULL,                 -- Storage content-address key
    thread_id     UUID NOT NULL,
    size          BIGINT NOT NULL,
    received_at   TIMESTAMPTZ NOT NULL,
    sent_at       TIMESTAMPTZ,
    message_id    TEXT,
    subject       TEXT,
    preview       TEXT,
    keywords      TEXT[] NOT NULL DEFAULT '{}',
    has_attachment BOOLEAN NOT NULL DEFAULT FALSE,
    is_spam_score REAL,
    deleted_at    TIMESTAMPTZ,
    metadata      JSONB NOT NULL DEFAULT '{}',   -- body offset, raw header span, MIME ids
    thread_key    BIGINT,
    search_text   TEXT,                          -- pre-tokenized search corpus
    PRIMARY KEY (account_id, id)
);
CREATE INDEX IF NOT EXISTS email8_emails_thread
    ON email8.emails (account_id, thread_id);
CREATE INDEX IF NOT EXISTS email8_emails_received
    ON email8.emails (account_id, received_at DESC);
CREATE INDEX IF NOT EXISTS email8_emails_keywords
    ON email8.emails USING GIN (keywords);
CREATE INDEX IF NOT EXISTS email8_emails_threadkey
    ON email8.emails (account_id, thread_key);
CREATE INDEX IF NOT EXISTS email8_emails_search
    ON email8.emails USING GIN (to_tsvector('simple', coalesce(search_text, '')));
CREATE INDEX IF NOT EXISTS email8_emails_message_id
    ON email8.emails (account_id, lower(message_id));

-- Email↔mailbox membership + IMAP UID (legacy UidMailbox list)
CREATE TABLE IF NOT EXISTS email8.email_mailboxes (
    account_id    UUID NOT NULL,
    env_id        UUID NOT NULL,
    email_id      UUID NOT NULL,
    mailbox_id    UUID NOT NULL,
    imap_uid      BIGINT NOT NULL,
    PRIMARY KEY (account_id, email_id, mailbox_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS email8_email_mailboxes_uid
    ON email8.email_mailboxes (account_id, mailbox_id, imap_uid);
CREATE INDEX IF NOT EXISTS email8_email_mailboxes_by_mailbox
    ON email8.email_mailboxes (account_id, mailbox_id, imap_uid DESC);

-- ── Threads ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS email8.threads (
    id            UUID NOT NULL DEFAULT gen_random_uuid(),
    env_id        UUID NOT NULL,
    account_id    UUID NOT NULL,
    subject       TEXT,
    version       BIGINT NOT NULL DEFAULT 0,     -- merge counter
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, id)
);
CREATE TABLE IF NOT EXISTS email8.thread_members (
    account_id   UUID NOT NULL,
    env_id       UUID NOT NULL,
    thread_id    UUID NOT NULL,
    email_id     UUID NOT NULL,
    PRIMARY KEY (account_id, thread_id, email_id)
);

-- Email8-specific RLS helpers (extend the standard context with the
-- mail account binding; store design §2.1). Defined BEFORE the policies
-- that call them (fresh-DB ordering bug: the principals policy below
-- references sentin8_current_account_id()).
DO $$
BEGIN
    CREATE OR REPLACE FUNCTION public.sentin8_current_account_id() RETURNS UUID
    LANGUAGE sql STABLE AS
        $g$ SELECT NULLIF(current_setting('app.account_id', true), '')::UUID $g$;
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'account helper skip: %', SQLERRM;
END $$;

DO $$
BEGIN
    CREATE OR REPLACE FUNCTION sentin8_is_env_admin() RETURNS BOOLEAN
    LANGUAGE sql STABLE AS
        $g$ SELECT COALESCE(NULLIF(current_setting('app.is_env_admin', true), '')::BOOLEAN, FALSE) $g$;
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'admin helper skip: %', SQLERRM;
END $$;

-- Principals: the account root row — scoped by env + own id (the row
-- IS the account, so `id = sentin8_current_account_id()` is the holder
-- test; env admins see all principals in their env).
ALTER TABLE email8.principals ENABLE ROW LEVEL SECURITY;
ALTER TABLE email8.principals FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS email8_principals_tenant ON email8.principals;
CREATE POLICY email8_principals_tenant ON email8.principals FOR ALL USING (
    sentin8_context_initialized()
    AND (sentin8_bypass_rls()
         OR (env_id = sentin8_current_env_id()
             AND (id = sentin8_current_account_id() OR sentin8_is_env_admin())))
) WITH CHECK (
    sentin8_context_initialized()
    AND (sentin8_bypass_rls()
         OR (env_id = sentin8_current_env_id()
             AND (id = sentin8_current_account_id() OR sentin8_is_env_admin())))
);

-- ── Change log (JMAP state tokens, IMAP HIGHESTMODSEQ/VANISHED, DAV sync) ─
CREATE TABLE IF NOT EXISTS email8.changelog (
    account_id   UUID NOT NULL,
    env_id       UUID NOT NULL,
    collection   SMALLINT NOT NULL,
    change_id    BIGINT NOT NULL,
    changes      JSONB NOT NULL,                 -- [{op, id, container?}]
    change_type  TEXT,                           -- convenience: ins/upd/destroyed
    record_id    UUID,                           -- convenience: the touched row
    mailbox_id   UUID,                           -- convenience: mailbox scope
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, collection, change_id)
);

-- ── ACL grants (shared rights; legacy 16-bit Acl bitset) ──────────────────
CREATE TABLE IF NOT EXISTS email8.acl_grants (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id           UUID NOT NULL,
    account_id       UUID NOT NULL,              -- owner
    collection       SMALLINT NOT NULL,
    document_id      UUID NOT NULL,
    grantee_account_id UUID NOT NULL,
    rights           INT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (account_id, collection, document_id, grantee_account_id)
);
CREATE INDEX IF NOT EXISTS email8_acl_grants_grantee
    ON email8.acl_grants (grantee_account_id, collection);

-- ── Blob link ledger (blob bytes live in Sentin8:Storage) ────────────────
CREATE TABLE IF NOT EXISTS email8.blob_links (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    owner_account_id UUID,                        -- NULL while blob lives only in the queue (no owning account yet)
    blob_hash       TEXT NOT NULL,
    ref_kind        TEXT NOT NULL CHECK (ref_kind IN ('reserved', 'linked', 'queue')),
    ref_id          UUID,                        -- email id / queue message id
    collection      SMALLINT,
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS email8_blob_links_hash
    ON email8.blob_links (env_id, blob_hash);
CREATE INDEX IF NOT EXISTS email8_blob_links_owner
    ON email8.blob_links (env_id, owner_account_id);

-- ── Quota counters ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS email8.quota_counters (
    env_id        UUID NOT NULL,
    account_id    UUID NOT NULL,
    used_bytes    BIGINT NOT NULL DEFAULT 0,
    used_objects  BIGINT NOT NULL DEFAULT 0,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (env_id, account_id)
);

-- ── Id sequences (legacy DocumentId/ChangeId counters) ────────────────────
CREATE TABLE IF NOT EXISTS email8.sequences (
    account_id UUID NOT NULL,
    env_id     UUID NOT NULL,
    kind       TEXT NOT NULL,                    -- 'email' | 'mailbox' | 'thread' | 'change:0' | …
    next_id    BIGINT NOT NULL DEFAULT 1,
    PRIMARY KEY (account_id, kind)
);

-- ── Identities (JMAP Identity) ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS email8.identities (
    id            UUID NOT NULL DEFAULT gen_random_uuid(),
    env_id        UUID NOT NULL,
    account_id    UUID NOT NULL REFERENCES email8.principals(id) ON DELETE CASCADE,
    address       TEXT NOT NULL,
    name          TEXT,
    reply_to      TEXT,
    bcc_to        TEXT,
    text_signature TEXT,
    html_signature TEXT,
    PRIMARY KEY (account_id, id)
);

-- ── Sieve scripts ────────────────────────────────────────────────────────

-- ── DNSBL zone config (story 5.2 — per-env zone set for the MTA gate) ─────
CREATE TABLE IF NOT EXISTS email8.dnsbl_zones (
    env_id        UUID NOT NULL,
    zone          TEXT NOT NULL,
    scopes        TEXT NOT NULL,
    max_checks    INTEGER NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (env_id, zone)
);

CREATE TABLE IF NOT EXISTS email8.sieve_scripts (
    id            UUID NOT NULL DEFAULT gen_random_uuid(),
    env_id        UUID NOT NULL,
    account_id    UUID NOT NULL REFERENCES email8.principals(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    blob_hash     TEXT NOT NULL,                 -- raw script bytes in Storage
    is_active     BOOLEAN NOT NULL DEFAULT FALSE,
    size          BIGINT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, id)
);
CREATE UNIQUE INDEX IF NOT EXISTS email8_sieve_uniq_name
    ON email8.sieve_scripts (account_id, lower(name));

-- ── Push subscriptions (JMAP PushSubscription) ────────────────────────────
CREATE TABLE IF NOT EXISTS email8.push_subscriptions (
    id              UUID NOT NULL DEFAULT gen_random_uuid(),
    env_id        UUID NOT NULL,
    account_id    UUID NOT NULL REFERENCES email8.principals(id) ON DELETE CASCADE,
    types           SMALLINT[] NOT NULL,
    endpoint        TEXT NOT NULL,
    keys            JSONB NOT NULL DEFAULT '{}',
    verification_code TEXT NOT NULL,
    verified        BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at      TIMESTAMPTZ,
    PRIMARY KEY (account_id, id)
);

-- ── Groupware: calendars, events, addressbooks, contacts, files ───────────
CREATE TABLE IF NOT EXISTS email8.calendars (
    id            UUID NOT NULL DEFAULT gen_random_uuid(),
    env_id        UUID NOT NULL,
    account_id    UUID NOT NULL REFERENCES email8.principals(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    color         TEXT,
    description   TEXT,
    sort_order    INT NOT NULL DEFAULT 0,
    time_zone     TEXT,
    supported_components TEXT[] NOT NULL DEFAULT '{VEVENT}',
    dead_properties JSONB NOT NULL DEFAULT '{}',
    version       BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (account_id, id)
);

CREATE TABLE IF NOT EXISTS email8.calendar_events (
    id            UUID NOT NULL DEFAULT gen_random_uuid(),
    env_id        UUID NOT NULL,
    account_id    UUID NOT NULL,
    calendar_id   UUID NOT NULL,
    uid           TEXT NOT NULL,                  -- iCalendar UID
    display_name  TEXT,
    data          JSONB NOT NULL DEFAULT '{}',
    occurrences   JSONB NOT NULL DEFAULT '[]',
    schedule_tag  TEXT,
    search_text   TEXT,
    size          BIGINT NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, id),
    UNIQUE (account_id, uid)
);

CREATE TABLE IF NOT EXISTS email8.addressbooks (
    id            UUID NOT NULL DEFAULT gen_random_uuid(),
    env_id        UUID NOT NULL,
    account_id    UUID NOT NULL REFERENCES email8.principals(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    description   TEXT,
    dead_properties JSONB NOT NULL DEFAULT '{}',
    version       BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (account_id, id)
);

CREATE TABLE IF NOT EXISTS email8.contact_cards (
    id            UUID NOT NULL DEFAULT gen_random_uuid(),
    env_id        UUID NOT NULL,
    account_id    UUID NOT NULL,
    addressbook_id UUID NOT NULL,
    display_name  TEXT,
    card          JSONB NOT NULL DEFAULT '{}',
    emails        TEXT[] NOT NULL DEFAULT '{}',   -- ham-override lookups
    search_text   TEXT,
    size          BIGINT NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, id)
);
CREATE INDEX IF NOT EXISTS email8_contact_cards_emails
    ON email8.contact_cards USING GIN (emails);

CREATE TABLE IF NOT EXISTS email8.file_nodes (
    id            UUID NOT NULL DEFAULT gen_random_uuid(),
    env_id        UUID NOT NULL,
    account_id    UUID NOT NULL,
    parent_id     UUID,
    name          TEXT NOT NULL,
    node_type     TEXT NOT NULL CHECK (node_type IN ('file', 'directory', 'symlink')),
    blob_hash     TEXT,
    media_type    TEXT,
    file_size     BIGINT,
    dead_properties JSONB NOT NULL DEFAULT '{}',
    PRIMARY KEY (account_id, id)
);

-- ── Policy rows (env-scoped config; admin via RFW) ────────────────────────
CREATE TABLE IF NOT EXISTS email8.quota_policy (
    env_id        UUID PRIMARY KEY,
    default_account_quota_bytes BIGINT NOT NULL DEFAULT 10737418240, -- 10 GiB
    max_outbound_queue_bytes BIGINT NOT NULL DEFAULT 1073741824,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS email8.spam_policy (
    env_id         UUID PRIMARY KEY,
    enabled        BOOLEAN NOT NULL DEFAULT TRUE,
    reject_threshold   REAL NOT NULL DEFAULT 15.0,
    discard_threshold  REAL NOT NULL DEFAULT 10.0,
    spam_threshold     REAL NOT NULL DEFAULT 5.0,
    greylist_expiry_secs INT NOT NULL DEFAULT 300,
    auto_learn_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    dnsbl_zones    JSONB NOT NULL DEFAULT '[]',
    trusted_domains TEXT[] NOT NULL DEFAULT '{}',
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── Spam training samples (worker input) ─────────────────────────────────
CREATE TABLE IF NOT EXISTS email8.spam_samples (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id        UUID NOT NULL,
    account_id    UUID,
    blob_hash     TEXT NOT NULL,
    class         TEXT NOT NULL CHECK (class IN ('spam', 'ham')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── RLS: tenant isolation (env_id + account_id holder pattern) ────────────
-- Applied per table with DROP POLICY IF EXISTS for idempotent re-runs.
-- (Helpers sentin8_current_account_id()/sentin8_is_env_admin() are created
-- at the top of this file, before the first policy.)
DO $$
DECLARE
    -- Account-scoped tables: owner row OR shared-in via ACL grants.
    acct_tables CONSTANT text[] := ARRAY[
        'principal_addresses', 'mailboxes',
        'emails', 'email_mailboxes', 'threads', 'thread_members',
        'identities', 'sieve_scripts', 'push_subscriptions',
        'calendars', 'calendar_events', 'addressbooks',
        'contact_cards', 'file_nodes'
    ];
    -- Env-scoped tables (no per-account holder): admin/config surfaces.
    env_tables CONSTANT text[] := ARRAY[
        'domains', 'groups', 'group_members',
        'quota_policy', 'spam_policy', 'spam_samples',
        'blob_links', 'acl_grants', 'quota_counters',
        'dnsbl_zones', 'sequences'
    ];
    t text;
BEGIN
    FOREACH t IN ARRAY acct_tables LOOP
        BEGIN
            EXECUTE format('ALTER TABLE email8.%I ENABLE ROW LEVEL SECURITY', t);
            EXECUTE format('ALTER TABLE email8.%I FORCE ROW LEVEL SECURITY', t);
            EXECUTE format('DROP POLICY IF EXISTS %I ON email8.%I', t || '_tenant', t);
            EXECUTE format($f$
                CREATE POLICY %I ON email8.%I FOR ALL USING (
                    sentin8_context_initialized()
                    AND (
                        sentin8_bypass_rls()
                        OR (env_id = sentin8_current_env_id()
                            AND (
                                account_id = sentin8_current_account_id()
                                OR sentin8_is_env_admin()
                            ))
                    )
                ) WITH CHECK (
                    sentin8_context_initialized()
                    AND (
                        sentin8_bypass_rls()
                        OR (env_id = sentin8_current_env_id()
                            AND (
                                account_id = sentin8_current_account_id()
                                OR sentin8_is_env_admin()
                            ))
                    )
                )$f$,
                t || '_tenant', t);
        EXCEPTION WHEN OTHERS THEN
            RAISE NOTICE 'RLS skip %: %', t, SQLERRM;
        END;
    END LOOP;

    FOREACH t IN ARRAY env_tables LOOP
        BEGIN
            EXECUTE format('ALTER TABLE email8.%I ENABLE ROW LEVEL SECURITY', t);
            EXECUTE format('ALTER TABLE email8.%I FORCE ROW LEVEL SECURITY', t);
            EXECUTE format('DROP POLICY IF EXISTS %I ON email8.%I', t || '_tenant', t);
            EXECUTE format($f$
                CREATE POLICY %I ON email8.%I FOR ALL USING (
                    sentin8_context_initialized()
                    AND (sentin8_bypass_rls() OR env_id = sentin8_current_env_id())
                ) WITH CHECK (
                    sentin8_context_initialized()
                    AND (sentin8_bypass_rls() OR env_id = sentin8_current_env_id())
                )$f$,
                t || '_tenant', t);
        EXCEPTION WHEN OTHERS THEN
            RAISE NOTICE 'RLS skip %: %', t, SQLERRM;
        END;
    END LOOP;
END $$;

-- The change log is readable by its owner only (no admin broadening needed
-- for hot-path sync).
ALTER TABLE email8.changelog ENABLE ROW LEVEL SECURITY;
ALTER TABLE email8.changelog FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS email8_changelog_tenant ON email8.changelog;
CREATE POLICY email8_changelog_tenant ON email8.changelog FOR ALL USING (
    sentin8_context_initialized()
    AND (sentin8_bypass_rls()
         OR (account_id = sentin8_current_account_id() AND env_id = sentin8_current_env_id()))
) WITH CHECK (
    sentin8_context_initialized()
    AND (sentin8_bypass_rls()
         OR (account_id = sentin8_current_account_id() AND env_id = sentin8_current_env_id()))
);



-- Per-service grants (enrollment also creates these roles; the local dev
-- flow re-runs this SQL idempotently).
DO $$
BEGIN
    EXECUTE 'GRANT USAGE ON SCHEMA email8 TO email8_store_service';
    EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA email8 TO email8_store_service';
    EXECUTE 'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA email8 TO email8_store_service';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'store grants skip: %', SQLERRM;
END $$;
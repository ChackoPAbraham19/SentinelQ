-- Only the trusted Node backend may read these tables. Browser roles have no
-- grants and no RLS policies. Application encryption keys live outside Supabase.
create table public.sentinelq_cases (
  id text primary key check (id ~ '^CASE-[A-Za-z0-9-]{4,96}$'),
  payload jsonb not null check (jsonb_typeof(payload) = 'object' and payload->>'id' = id),
  revision bigint not null default 1 check (revision > 0),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create table public.sentinelq_authorities (
  username text primary key,
  role text not null check (role in ('ADMIN', 'CASE_MANAGER', 'INVESTIGATOR', 'AUDITOR')),
  password_hash text not null check (password_hash ~ '^pbkdf2\$[0-9]+\$[a-f0-9]+\$[a-f0-9]+$'),
  enabled boolean not null default true,
  created_at timestamptz not null default now()
);
create table public.sentinelq_log_entries (
  stream text not null check (stream in ('audit', 'ledger')),
  sequence bigint not null,
  line text not null check (jsonb_typeof(line::jsonb) = 'object'),
  created_at timestamptz not null default now(),
  primary key (stream, sequence)
);
create table public.sentinelq_config (
  id text primary key,
  value text not null
);
alter table public.sentinelq_cases enable row level security;
alter table public.sentinelq_authorities enable row level security;
alter table public.sentinelq_log_entries enable row level security;
alter table public.sentinelq_config enable row level security;
revoke all on public.sentinelq_cases, public.sentinelq_authorities, public.sentinelq_log_entries, public.sentinelq_config from public, anon, authenticated;
grant select, insert, update on public.sentinelq_cases to service_role;
grant select, insert, update on public.sentinelq_authorities to service_role;
grant select, insert on public.sentinelq_log_entries to service_role;
grant select, insert on public.sentinelq_config to service_role;

-- Optimistic concurrency: a stale reviewer cannot overwrite a newer message.
create function public.sentinelq_save_case(p_id text, p_payload jsonb, p_revision bigint)
returns bigint language plpgsql security invoker set search_path = '' as $$
declare next_revision bigint;
begin
  if p_revision = 0 then
    insert into public.sentinelq_cases(id, payload) values (p_id, p_payload)
    on conflict (id) do nothing returning revision into next_revision;
  else
    update public.sentinelq_cases set payload = p_payload, revision = revision + 1, updated_at = now()
    where id = p_id and revision = p_revision returning revision into next_revision;
  end if;
  if next_revision is null then raise sqlstate 'PT409' using message = 'Case revision conflict'; end if;
  return next_revision;
end;
$$;

-- Serialize log append transactions and compare the exact signed predecessor.
-- The application verifies the HMAC chain and signs the next entry itself.
create function public.sentinelq_append_log(p_stream text, p_previous_line text, p_line text)
returns boolean language plpgsql security invoker set search_path = '' as $$
declare last_line text; last_sequence bigint;
begin
  if p_stream not in ('audit', 'ledger') then raise exception 'Invalid stream'; end if;
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('sentinelq:' || p_stream));
  select line, sequence into last_line, last_sequence from public.sentinelq_log_entries
  where stream = p_stream order by sequence desc limit 1;
  if last_line is distinct from p_previous_line then return false; end if;
  insert into public.sentinelq_log_entries(stream, sequence, line)
  values (p_stream, coalesce(last_sequence, 0) + 1, p_line);
  return true;
end;
$$;
revoke all on function public.sentinelq_save_case(text, jsonb, bigint) from public, anon, authenticated;
revoke all on function public.sentinelq_append_log(text, text, text) from public, anon, authenticated;
grant execute on function public.sentinelq_save_case(text, jsonb, bigint) to service_role;
grant execute on function public.sentinelq_append_log(text, text, text) to service_role;

insert into storage.buckets(id, name, public, file_size_limit, allowed_mime_types)
values ('sentinelq-evidence', 'sentinelq-evidence', false, 9437184, array['application/octet-stream']);
-- No storage.objects policy is granted to browser roles. Ciphertext only.

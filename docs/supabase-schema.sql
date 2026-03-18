-- etui Supabase v1 schema for authenticated ciphertext sync.
-- Apply in Supabase SQL editor.

create extension if not exists "pgcrypto";

create table if not exists public.vault_changes (
  user_id uuid not null,
  vault_id uuid not null,
  change_id uuid not null,
  entry_id uuid not null,
  device_id uuid,
  logical_ts bigint,
  updated_at timestamptz not null,
  tombstone boolean not null default false,
  nonce_b64 text not null,
  ciphertext_b64 text not null,
  server_seq bigint generated always as identity,
  created_at timestamptz not null default timezone('utc', now()),
  primary key (user_id, vault_id, change_id)
);

create index if not exists idx_vault_changes_pull
  on public.vault_changes (user_id, vault_id, server_seq);

create index if not exists idx_vault_changes_entry
  on public.vault_changes (user_id, vault_id, entry_id);

alter table public.vault_changes enable row level security;

drop policy if exists vault_changes_isolation on public.vault_changes;
create policy vault_changes_isolation
  on public.vault_changes
  for all
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

create or replace function public.etui_push_changes(
  p_vault_id uuid,
  p_changes jsonb
)
returns jsonb
language plpgsql
security invoker
as $$
declare
  v_user_id uuid;
begin
  v_user_id := auth.uid();
  if v_user_id is null then
    raise exception 'unauthorized';
  end if;

  insert into public.vault_changes (
    user_id,
    vault_id,
    change_id,
    entry_id,
    updated_at,
    nonce_b64,
    ciphertext_b64,
    tombstone,
    logical_ts,
    device_id
  )
  select
    v_user_id,
    p_vault_id,
    (item->>'change_id')::uuid,
    (item->>'entry_id')::uuid,
    (item->>'updated_at')::timestamptz,
    item->>'nonce_b64',
    item->>'ciphertext_b64',
    coalesce((item->>'tombstone')::boolean, false),
    nullif(item->>'logical_ts', '')::bigint,
    nullif(item->>'device_id', '')::uuid
  from jsonb_array_elements(p_changes) item
  on conflict (user_id, vault_id, change_id) do nothing;

  return jsonb_build_object('ok', true);
end;
$$;

create or replace function public.etui_pull_changes(
  p_vault_id uuid,
  p_since_cursor text default null,
  p_limit integer default 500
)
returns jsonb
language plpgsql
security invoker
as $$
declare
  v_user_id uuid;
  v_since bigint;
  v_next bigint;
  v_changes jsonb;
begin
  v_user_id := auth.uid();
  if v_user_id is null then
    raise exception 'unauthorized';
  end if;

  v_since := nullif(p_since_cursor, '')::bigint;

  with rows as (
    select
      change_id,
      entry_id,
      updated_at,
      nonce_b64,
      ciphertext_b64,
      server_seq
    from public.vault_changes
    where user_id = v_user_id
      and vault_id = p_vault_id
      and (v_since is null or server_seq > v_since)
    order by server_seq asc
    limit greatest(1, least(coalesce(p_limit, 500), 1000))
  )
  select
    coalesce(
      jsonb_agg(
        jsonb_build_object(
          'change_id', change_id,
          'entry_id', entry_id,
          'updated_at', updated_at,
          'nonce_b64', nonce_b64,
          'ciphertext_b64', ciphertext_b64
        )
        order by server_seq
      ),
      '[]'::jsonb
    ),
    max(server_seq)
  into v_changes, v_next
  from rows;

  return jsonb_build_object(
    'changes', v_changes,
    'next_cursor', case when v_next is null then p_since_cursor else v_next::text end
  );
end;
$$;

grant usage on schema public to authenticated;
grant select, insert on table public.vault_changes to authenticated;
grant execute on function public.etui_push_changes(uuid, jsonb) to authenticated;
grant execute on function public.etui_pull_changes(uuid, text, integer) to authenticated;

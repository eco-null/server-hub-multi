-- server-hub: çok kullanıcılı şema (Supabase Auth ile)
-- auth.users (Supabase builtin) → profiles ek
-- Her kullanıcının kendi layout/ayarları, servisleri, bookmark'ları, logları

-- 0) Required extensions (pgcrypto provides crypt/gen_salt/gen_random_uuid)
create extension if not exists pgcrypto with schema extensions;

-- 1) Profiller — auth.users ile 1:1
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text unique not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- 2) Kullanıcı ayarları/layout (jsonb — esnek; index.html'deki HubSettings karşılığı)
create table if not exists public.user_settings (
  user_id uuid primary key references auth.users(id) on delete cascade,
  settings jsonb not null default '{}'::jsonb,
  layout jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

-- 3) Kullanıcıya özel servisler (eski global services.json → per-user)
create table if not exists public.user_services (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  name text not null,
  url text not null,
  description text default '',
  icon text default 'box',
  ping boolean default true,
  category_override text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- 4) Kullanıcıya özel bookmark'lar
create table if not exists public.user_bookmarks (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  name text not null,
  url text not null,
  icon text default 'link',
  color text,
  created_at timestamptz not null default now()
);

-- 5) Kullanıcıya özel loglar — SADECE hata/çakışma (kullanıcı isteği)
create table if not exists public.user_logs (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  level text not null default 'ERROR' check (level in ('ERROR','WARN','CONFLICT')),
  source text not null default 'server',
  message text not null,
  details jsonb,
  created_at timestamptz not null default now()
);
create index if not exists user_logs_user_idx on public.user_logs (user_id, created_at desc);
-- performance: covering indexes for FKs (fixes unindexed_foreign_keys lint)
-- bloat fix: drop redundant single-column FK indexes (composite covers them)
drop index if exists public.user_services_user_id_idx;
drop index if exists public.user_bookmarks_user_id_idx;
drop index if exists user_services_user_id_idx;
drop index if exists user_bookmarks_user_id_idx;
create index if not exists user_services_user_created_idx on public.user_services (user_id, created_at);
create index if not exists user_bookmarks_user_created_idx on public.user_bookmarks (user_id, created_at);
drop index if exists auth.auth_users_username_meta_idx;
drop index if exists public.auth_users_username_meta_idx;
drop index if exists auth_users_username_meta_idx;
create index if not exists auth_users_username_meta_idx on auth.users ((lower(raw_user_meta_data->>'username'))) where raw_user_meta_data->>'username' is not null;

-- ---------------------------------------------------------------------------
-- Validation CHECKs (prevents oversized / malformed rows)
-- ---------------------------------------------------------------------------
-- profiles.username format
do $$ begin
  alter table public.profiles add constraint profiles_username_chk check (username ~ '^[a-zA-Z0-9_]{3,20}$');
exception when duplicate_object then null; end $$;

-- user_services constraints
do $$ begin
  alter table public.user_services add constraint user_services_name_chk check (char_length(name) between 1 and 200);
exception when duplicate_object then null; end $$;
do $$ begin
  alter table public.user_services add constraint user_services_url_chk check (char_length(url) <= 2000 and url ~ '^https?://');
exception when duplicate_object then null; end $$;
do $$ begin
  alter table public.user_services add constraint user_services_desc_chk check (description is null or char_length(description) <= 500);
exception when duplicate_object then null; end $$;
do $$ begin
  alter table public.user_services add constraint user_services_icon_chk check (icon is null or char_length(icon) <= 50);
exception when duplicate_object then null; end $$;

-- user_bookmarks constraints
do $$ begin
  alter table public.user_bookmarks add constraint user_bookmarks_name_chk check (char_length(name) between 1 and 200);
exception when duplicate_object then null; end $$;
do $$ begin
  alter table public.user_bookmarks add constraint user_bookmarks_url_chk check (char_length(url) <= 2000 and url ~ '^https?://');
exception when duplicate_object then null; end $$;
do $$ begin
  alter table public.user_bookmarks add constraint user_bookmarks_color_chk check (color is null or color ~ '^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$');
exception when duplicate_object then null; end $$;

-- user_settings size (64 KiB limit)
do $$ begin
  alter table public.user_settings add constraint user_settings_settings_size_chk check (octet_length(settings::text) < 64*1024);
exception when duplicate_object then null; end $$;
do $$ begin
  alter table public.user_settings add constraint user_settings_layout_size_chk check (octet_length(layout::text) < 64*1024);
exception when duplicate_object then null; end $$;

-- user_logs message length
do $$ begin
  alter table public.user_logs add constraint user_logs_message_chk check (char_length(message) between 1 and 2000);
exception when duplicate_object then null; end $$;

-- Secrets storage note: currently plaintext. For sensitive fields consider
-- pgsodium (pgcrypto successor) / Supabase Vault encryption. No code change
-- required in this fix set, but future migration should move secrets to
-- encrypted storage (e.g., vault secrets or pgsodium column encryption).
-- TODO: encrypt secrets with pgsodium (or Supabase Vault) - replace plaintext storage; see pgsodium column encryption / vault.

-- ---------------------------------------------------------------------------
-- RLS: her kullanıcı SADECE kendi satırlarını görür/düzenler
-- performans: auth.uid() -> (select auth.uid()) ile sargı (auth_rls_initplan)
-- ---------------------------------------------------------------------------
alter table public.profiles enable row level security;
alter table public.user_settings enable row level security;
alter table public.user_services enable row level security;
alter table public.user_bookmarks enable row level security;
alter table public.user_logs enable row level security;

-- profiles: kullanıcı kendi profilini oku/güncelle; signup'ta insert (service_role ile)
drop policy if exists "profiles_select_own" on public.profiles;
create policy "profiles_select_own" on public.profiles
  for select using ((select auth.uid()) = id);
drop policy if exists "profiles_update_own" on public.profiles;
create policy "profiles_update_own" on public.profiles
  for update using ((select auth.uid()) = id) with check ((select auth.uid()) = id);
drop policy if exists "profiles_no_insert" on public.profiles;
create policy "profiles_no_insert" on public.profiles
  for insert with check (false);

-- user_settings: own read/write
drop policy if exists "settings_select_own" on public.user_settings;
create policy "settings_select_own" on public.user_settings
  for select using ((select auth.uid()) = user_id);
drop policy if exists "settings_insert_own" on public.user_settings;
create policy "settings_insert_own" on public.user_settings
  for insert with check ((select auth.uid()) = user_id);
drop policy if exists "settings_update_own" on public.user_settings;
create policy "settings_update_own" on public.user_settings
  for update using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);

drop policy if exists "settings_delete_own" on public.user_settings;
create policy "settings_delete_own" on public.user_settings
  for delete using ((select auth.uid()) = user_id);

-- user_services: own read/write
drop policy if exists "services_select_own" on public.user_services;
create policy "services_select_own" on public.user_services
  for select using ((select auth.uid()) = user_id);
drop policy if exists "services_insert_own" on public.user_services;
create policy "services_insert_own" on public.user_services
  for insert with check ((select auth.uid()) = user_id);
drop policy if exists "services_update_own" on public.user_services;
create policy "services_update_own" on public.user_services
  for update using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
drop policy if exists "services_delete_own" on public.user_services;
create policy "services_delete_own" on public.user_services
  for delete using ((select auth.uid()) = user_id);

-- user_bookmarks: own read/write
drop policy if exists "bookmarks_select_own" on public.user_bookmarks;
create policy "bookmarks_select_own" on public.user_bookmarks
  for select using ((select auth.uid()) = user_id);
drop policy if exists "bookmarks_insert_own" on public.user_bookmarks;
create policy "bookmarks_insert_own" on public.user_bookmarks
  for insert with check ((select auth.uid()) = user_id);
drop policy if exists "bookmarks_update_own" on public.user_bookmarks;
create policy "bookmarks_update_own" on public.user_bookmarks
  for update using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
drop policy if exists "bookmarks_delete_own" on public.user_bookmarks;
create policy "bookmarks_delete_own" on public.user_bookmarks
  for delete using ((select auth.uid()) = user_id);

-- user_logs: own read + insert (insert servis tarafından kullanıcı adına — auth.uid ile)
drop policy if exists "logs_select_own" on public.user_logs;
create policy "logs_select_own" on public.user_logs
  for select using ((select auth.uid()) = user_id);
drop policy if exists "logs_insert_own" on public.user_logs;
create policy "logs_insert_own" on public.user_logs
  for insert with check ((select auth.uid()) = user_id);

-- İlk ayar satırı signup sonrası otomatik: trigger (auto-confirm email for dashboard)
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  update auth.users set email_confirmed_at = coalesce(email_confirmed_at, now()) where id = new.id and email_confirmed_at is null;
  insert into public.profiles (id, username)
  values (new.id, coalesce(new.raw_user_meta_data->>'username', split_part(new.email, '@', 1)))
  on conflict (id) do nothing;
  insert into public.user_settings (user_id, settings, layout)
  values (new.id, '{}'::jsonb, '{}'::jsonb)
  on conflict (user_id) do nothing;
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- security: trigger functions must not be callable via PostgREST RPC (anon/auth)
revoke execute on function public.handle_new_user() from anon, authenticated, public;
do $$ begin
  if exists (select 1 from pg_proc where proname='rls_auto_enable' and pronamespace='public'::regnamespace) then
    execute 'revoke execute on function public.rls_auto_enable() from anon, authenticated, public';
  end if;
end $$;

-- Bypass for email rate limit: create user directly with email_confirmed_at = now() (SECURITY DEFINER, service_role only)
create or replace function public.signup_bypass(email text, password text, username text default null)
returns json language plpgsql security definer set search_path = public, auth, extensions, pg_catalog as $$
declare new_id uuid := gen_random_uuid(); enc text; uname text;
begin
  if email is null or email !~ '^[^@]+@[^@]+\.[^@]+$' then return json_build_object('error','invalid email'); end if;
  if password is null or length(password) < 8 then return json_build_object('error','unable to create account'); end if;
  if exists (select 1 from auth.users where auth.users.email = signup_bypass.email) then return json_build_object('error','unable to create account'); end if;
  uname := coalesce(nullif(trim(username),''), split_part(email,'@',1));
  -- username uniqueness check (also via profiles unique, but give friendly error) - generic error to prevent enumeration
  if exists (select 1 from public.profiles where username = uname) then return json_build_object('error','unable to create account'); end if;
  enc := extensions.crypt(password, extensions.gen_salt('bf',10));
  insert into auth.users (instance_id, id, aud, role, email, encrypted_password, email_confirmed_at, raw_app_meta_data, raw_user_meta_data, created_at, updated_at, confirmation_token, recovery_token)
  values ('00000000-0000-0000-0000-000000000000'::uuid, new_id, 'authenticated','authenticated', email, enc, now(), jsonb_build_object('provider','email','providers',array['email']), jsonb_build_object('username',uname), now(), now(), '', '') ;
  -- CRIT-04: GoTrue requires identities row for email provider
  insert into auth.identities (id, user_id, identity_data, provider, provider_id, last_sign_in_at, created_at, updated_at)
  values (gen_random_uuid(), new_id, jsonb_build_object('sub', new_id::text, 'email', email), 'email', email, now(), now(), now());
  insert into public.profiles (id, username) values (new_id, uname) on conflict (id) do nothing;
  insert into public.user_settings (user_id, settings, layout) values (new_id, '{}'::jsonb, '{}'::jsonb) on conflict (user_id) do nothing;
  return json_build_object('id', new_id, 'email', email, 'username', uname);
exception when others then return json_build_object('error', SQLERRM);
end; $$;
revoke all on function public.signup_bypass(text, text, text) from public;
revoke all on function public.signup_bypass(text, text, text) from anon, authenticated;
grant execute on function public.signup_bypass(text, text, text) to service_role;

-- HIGH-02: RPCs for username login (SECURITY DEFINER, bypass RLS)
create or replace function public.get_email_by_username(uname text)
returns text language sql security definer set search_path = public, auth, pg_catalog as $$
  select email from auth.users where raw_user_meta_data->>'username' = get_email_by_username.uname limit 1;
$$;
revoke all on function public.get_email_by_username(text) from public;
revoke all on function public.get_email_by_username(text) from anon;
grant execute on function public.get_email_by_username(text) to authenticated, service_role;

create or replace function public.username_exists(uname text)
returns boolean language sql security definer set search_path = public, auth, pg_catalog as $$
  select exists(
    select 1 from auth.users where raw_user_meta_data->>'username' = username_exists.uname
    union all
    select 1 from public.profiles where username = username_exists.uname
  );
$$;
revoke all on function public.username_exists(text) from public;
revoke all on function public.username_exists(text) from anon;
grant execute on function public.username_exists(text) to authenticated, service_role;

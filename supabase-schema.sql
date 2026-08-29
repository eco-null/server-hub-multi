-- server-hub: çok kullanıcılı şema (Supabase Auth ile)
-- auth.users (Supabase builtin) → profiles ek
-- Her kullanıcının kendi layout/ayarları, servisleri, bookmark'ları, logları

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
create index if not exists user_services_user_id_idx on public.user_services (user_id);
create index if not exists user_bookmarks_user_id_idx on public.user_bookmarks (user_id);

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
  for update using ((select auth.uid()) = id);

-- user_settings: own read/write
drop policy if exists "settings_select_own" on public.user_settings;
create policy "settings_select_own" on public.user_settings
  for select using ((select auth.uid()) = user_id);
drop policy if exists "settings_insert_own" on public.user_settings;
create policy "settings_insert_own" on public.user_settings
  for insert with check ((select auth.uid()) = user_id);
drop policy if exists "settings_update_own" on public.user_settings;
create policy "settings_update_own" on public.user_settings
  for update using ((select auth.uid()) = user_id);

-- user_services: own read/write
drop policy if exists "services_select_own" on public.user_services;
create policy "services_select_own" on public.user_services
  for select using ((select auth.uid()) = user_id);
drop policy if exists "services_insert_own" on public.user_services;
create policy "services_insert_own" on public.user_services
  for insert with check ((select auth.uid()) = user_id);
drop policy if exists "services_update_own" on public.user_services;
create policy "services_update_own" on public.user_services
  for update using ((select auth.uid()) = user_id);
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
  for update using ((select auth.uid()) = user_id);
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
returns trigger language plpgsql security definer set search_path = public as $$
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

-- Bypass for email rate limit: create user directly with email_confirmed_at = now() (SECURITY DEFINER, anon can call)
create or replace function public.signup_bypass(email text, password text, username text default null)
returns json language plpgsql security definer set search_path = public, auth, extensions, pg_catalog as $$
declare new_id uuid := gen_random_uuid(); enc text; uname text;
begin
  if email is null or email !~ '^[^@]+@[^@]+\.[^@]+$' then return json_build_object('error','invalid email'); end if;
  if password is null or length(password) < 8 then return json_build_object('error','weak password'); end if;
  if exists (select 1 from auth.users where auth.users.email = signup_bypass.email) then return json_build_object('error','email exists'); end if;
  uname := coalesce(username, split_part(email,'@',1));
  enc := extensions.crypt(password, extensions.gen_salt('bf',6));
  insert into auth.users (instance_id, id, aud, role, email, encrypted_password, email_confirmed_at, raw_app_meta_data, raw_user_meta_data, created_at, updated_at, confirmation_token, recovery_token)
  values ('00000000-0000-0000-0000-000000000000'::uuid, new_id, 'authenticated','authenticated', email, enc, now(), jsonb_build_object('provider','email','providers',array['email']), jsonb_build_object('username',uname), now(), now(), '', '') ;
  insert into public.profiles (id, username) values (new_id, uname) on conflict (id) do nothing;
  insert into public.user_settings (user_id, settings, layout) values (new_id, '{}'::jsonb, '{}'::jsonb) on conflict (user_id) do nothing;
  return json_build_object('id', new_id, 'email', email, 'username', uname);
exception when others then return json_build_object('error', SQLERRM);
end; $$;
revoke all on function public.signup_bypass(text, text, text) from public;
grant execute on function public.signup_bypass(text, text, text) to anon, authenticated, service_role;
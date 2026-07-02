-- ScamShield schema — run against the provisioned Supabase project.
-- RLS is ON for every table. The service-role key (server-only) bypasses RLS;
-- the anon key is public and constrained by these policies.

-- ------------------------------------------------------------------ scans ---
create table if not exists public.scans (
  id           uuid primary key default gen_random_uuid(),
  user_id      uuid references auth.users(id) on delete cascade,   -- nullable: anon scans
  content_hash text not null,                                       -- sha256, NOT raw content
  raw_content  text,                                                -- populated ONLY on opt-in
  type         text not null check (type in ('message','link','email','qr')),
  score        int  not null check (score between 0 and 100),
  verdict      text not null check (verdict in ('safe','suspicious','scam')),
  signals      jsonb not null default '[]'::jsonb,
  language     text not null default 'en',
  created_at   timestamptz not null default now()
);
create index if not exists scans_user_created_idx on public.scans (user_id, created_at desc);
alter table public.scans enable row level security;

drop policy if exists "scans_select_own" on public.scans;
create policy "scans_select_own" on public.scans
  for select using (auth.uid() = user_id);
drop policy if exists "scans_insert_own" on public.scans;
create policy "scans_insert_own" on public.scans
  for insert with check (auth.uid() = user_id);
drop policy if exists "scans_delete_own" on public.scans;
create policy "scans_delete_own" on public.scans
  for delete using (auth.uid() = user_id);

-- ---------------------------------------------------------------- reports ---
create table if not exists public.reports (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid references auth.users(id) on delete cascade,
  pattern    text not null,                                         -- PII-redacted before insert
  category   text not null default 'other',
  upvotes    int  not null default 0,
  status     text not null default 'pending' check (status in ('pending','approved','rejected')),
  created_at timestamptz not null default now()
);
create index if not exists reports_status_idx on public.reports (status, upvotes desc);
alter table public.reports enable row level security;

-- Approved reports are readable by any authenticated user; owners manage their own.
drop policy if exists "reports_select_approved" on public.reports;
create policy "reports_select_approved" on public.reports
  for select to authenticated using (status = 'approved' or auth.uid() = user_id);
drop policy if exists "reports_insert_own" on public.reports;
create policy "reports_insert_own" on public.reports
  for insert to authenticated with check (auth.uid() = user_id);
drop policy if exists "reports_delete_own" on public.reports;
create policy "reports_delete_own" on public.reports
  for delete using (auth.uid() = user_id);

-- NOTE: `profiles` already exists (RLS on) in the provisioned project — reused for roles.

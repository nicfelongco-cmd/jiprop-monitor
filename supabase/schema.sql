-- ============================================================
-- JIPROP J Tower Title Monitor — Supabase Schema
-- Safe to re-run: uses IF NOT EXISTS / DROP IF EXISTS guards
-- ============================================================

-- ──────────────────────────────────────────────
-- TABLES
-- ──────────────────────────────────────────────

create table if not exists public.units (
  id text primary key,
  seq numeric, code text, floor text, unit_no text, unit_code text,
  sale_status text default 'for_transfer',
  unit_type text default '',
  present_buyer text default '', previous_buyer text default '',
  tin_number text default '', financial_institution text default '',
  date_loan_credited text default '', total_contract_price text default '',
  doas_notarial_date text default '', cct_under_developer text default '',
  tax_dec_under_developer text default '', bank_remarks text default '',
  sp_endorsed_date text default '', _doas_uploaded boolean default false,
  cwt_final_fees text default '', cwt_check_no text default '', cwt_date_paid text default '',
  dst_fees text default '', dst_check_no text default '', dst_date_paid text default '',
  bir_entry_date text default '', bir_status text default '',
  bir_representation_amt text default '', ecar_release_date text default '',
  transfer_charge_amt text default '', transfer_tax_date_paid text default '',
  transfer_tax_status text default '', rod_entry_date text default '',
  epeb_fees text default '', epeb_date_paid text default '',
  epeb_representation_amt text default '', epeb_status text default '',
  new_cct_under_buyer text default '', cct_released_date text default '',
  rpt_fees text default '', rpt_date_paid text default '',
  tax_clearance_fees text default '', tax_clearance_date_paid text default '',
  taxdec_entry_date text default '', taxdec_inspection_fees text default '',
  taxdec_representation_amt text default '', taxdec_status text default '',
  converted_taxdec_buyer text default '', taxdec_released_date text default '',
  cct_forwarded_to text default '', cct_forwarded_date text default '',
  td_forwarded_to text default '', td_forwarded_date text default '',
  remarks text default '',
  ecar_checklist jsonb default '{}',
  updated_at timestamptz default now(),
  updated_by text default ''
);

create table if not exists public.user_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  username text unique not null,
  role text not null default 'viewer',
  display_name text default '',
  first_name text default '',
  last_name text default '',
  email text default '',
  contact text default '',
  photo_url text default '',
  assigned_fi text default '',
  status text default 'active',
  last_login timestamptz
);

-- Add new columns to existing tables (safe to re-run)
alter table public.user_profiles add column if not exists first_name text default '';
alter table public.user_profiles add column if not exists last_name text default '';
alter table public.user_profiles add column if not exists contact text default '';
alter table public.user_profiles add column if not exists last_login timestamptz;

create table if not exists public.app_settings (
  key text primary key,
  value jsonb not null default 'null',
  updated_at timestamptz default now()
);

create table if not exists public.reversal_requests (
  id text primary key,
  unit_id text not null,
  field_key text not null,
  old_value text default '',
  new_value text default '',
  requested_by text not null,
  status text default 'pending',
  created_at timestamptz default now()
);

create table if not exists public.documents (
  id text primary key,
  unit_id text not null,
  doc_type text not null,
  file_name text not null,
  file_size bigint default 0,
  file_type text default '',
  storage_path text not null,
  uploaded_at timestamptz default now(),
  uploaded_by text default ''
);

-- ──────────────────────────────────────────────
-- HELPER FUNCTIONS
-- ──────────────────────────────────────────────

create or replace function public.my_role()
returns text language sql security definer stable as $$
  select coalesce(
    (select role from public.user_profiles where user_id = auth.uid()),
    'viewer'
  );
$$;

create or replace function public.my_username()
returns text language sql security definer stable as $$
  select username from public.user_profiles where user_id = auth.uid();
$$;

-- ──────────────────────────────────────────────
-- ROW LEVEL SECURITY
-- ──────────────────────────────────────────────

alter table public.units              enable row level security;
alter table public.user_profiles      enable row level security;
alter table public.app_settings       enable row level security;
alter table public.reversal_requests  enable row level security;
alter table public.documents          enable row level security;

-- units
drop policy if exists "units_read"   on public.units;
drop policy if exists "units_write"  on public.units;
drop policy if exists "units_update" on public.units;
create policy "units_read"   on public.units for select to authenticated using (true);
create policy "units_write"  on public.units for insert to authenticated
  with check (public.my_role() in ('user','client_admin','sp_admin','super_admin'));
create policy "units_update" on public.units for update to authenticated
  using (public.my_role() in ('user','client_admin','sp_admin','super_admin'));

-- user_profiles
drop policy if exists "profiles_read"  on public.user_profiles;
drop policy if exists "profiles_own"   on public.user_profiles;
drop policy if exists "profiles_admin" on public.user_profiles;
create policy "profiles_read"   on public.user_profiles for select to authenticated using (true);
create policy "profiles_own"    on public.user_profiles for update to authenticated
  using (user_id = auth.uid());
create policy "profiles_admin"  on public.user_profiles for all to authenticated
  using (public.my_role() in ('sp_admin','super_admin'));

-- app_settings
drop policy if exists "settings_read"  on public.app_settings;
drop policy if exists "settings_write" on public.app_settings;
create policy "settings_read"  on public.app_settings for select to authenticated using (true);
create policy "settings_write" on public.app_settings for all to authenticated
  using (public.my_role() in ('user','client_admin','sp_admin','super_admin'));

-- reversal_requests
drop policy if exists "reversals_read"   on public.reversal_requests;
drop policy if exists "reversals_insert" on public.reversal_requests;
drop policy if exists "reversals_update" on public.reversal_requests;
create policy "reversals_read"   on public.reversal_requests for select to authenticated using (true);
create policy "reversals_insert" on public.reversal_requests for insert to authenticated
  with check (public.my_role() in ('user','client_admin','sp_admin','super_admin'));
create policy "reversals_update" on public.reversal_requests for update to authenticated
  using (public.my_role() in ('sp_admin','super_admin'));

-- documents
drop policy if exists "docs_read"   on public.documents;
drop policy if exists "docs_insert" on public.documents;
drop policy if exists "docs_delete" on public.documents;
create policy "docs_read"   on public.documents for select to authenticated using (true);
create policy "docs_insert" on public.documents for insert to authenticated
  with check (public.my_role() in ('user','client_admin','sp_admin','super_admin'));
create policy "docs_delete" on public.documents for delete to authenticated
  using (public.my_role() in ('sp_admin','super_admin') or uploaded_by = public.my_username());

-- ──────────────────────────────────────────────
-- STORAGE BUCKET
-- ──────────────────────────────────────────────

insert into storage.buckets (id, name, public, file_size_limit)
values ('documents', 'documents', false, 52428800)
on conflict (id) do nothing;

drop policy if exists "storage_read"   on storage.objects;
drop policy if exists "storage_insert" on storage.objects;
drop policy if exists "storage_delete" on storage.objects;
create policy "storage_read"   on storage.objects for select to authenticated
  using (bucket_id = 'documents');
create policy "storage_insert" on storage.objects for insert to authenticated
  with check (bucket_id = 'documents' and
    public.my_role() in ('user','client_admin','sp_admin','super_admin'));
create policy "storage_delete" on storage.objects for delete to authenticated
  using (bucket_id = 'documents' and
    public.my_role() in ('sp_admin','super_admin'));

-- ──────────────────────────────────────────────
-- REALTIME
-- ──────────────────────────────────────────────

do $$
begin
  if not exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime' and tablename = 'units'
  ) then
    alter publication supabase_realtime add table public.units;
  end if;
  if not exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime' and tablename = 'reversal_requests'
  ) then
    alter publication supabase_realtime add table public.reversal_requests;
  end if;
end $$;

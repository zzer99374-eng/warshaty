-- =========================================================
-- تحصين لوحة مدير المنصة — ملف واحد مرتب (النسخة الكاملة).
-- يحل محل كل الملفات السابقة. شغّل هذا الملف فقط، على نسخة تجريبية أولًا.
-- آمن لإعادة التشغيل.
-- يفترض وجود: public.workshops, public.profiles, public.platform_admins(user_id),
--             public.workshop_records (الجداول اللي التطبيق بيستخدمها فعلًا)
-- =========================================================

-- ---------- 1) جدول المدراء مقفول على الـ API ----------
alter table public.platform_admins enable row level security;
revoke all on public.platform_admins from anon, authenticated;

-- ---------- 2) is_platform_admin ----------
-- بيجيب فقط على "هل أنا أدمن؟" ولا يسمح بفحص uuid لمستخدم آخر
create or replace function public.is_platform_admin(uid uuid default auth.uid())
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select auth.uid() is not null
     and uid is not distinct from auth.uid()
     and exists (select 1 from public.platform_admins where user_id = uid);
$$;
revoke all on function public.is_platform_admin(uuid) from public, anon;
grant  execute on function public.is_platform_admin(uuid) to authenticated;

-- ---------- 3) تحويل تواريخ الاشتراك إلى date (لو كانت timestamptz) ----------
do $$
declare c text;
begin
  for c in
    select column_name from information_schema.columns
    where table_schema = 'public' and table_name = 'workshops'
      and column_name in ('subscription_start', 'subscription_end')
      and data_type like 'timestamp%'
  loop
    execute format('alter table public.workshops alter column %I type date using %I::date', c, c);
  end loop;
end $$;

-- ---------- 4) سياسات وصلاحيات workshops ----------
alter table public.workshops enable row level security;

drop policy if exists "workshops_admin_read"   on public.workshops;
drop policy if exists "workshops_owner_read"   on public.workshops;
drop policy if exists "workshops_owner_update" on public.workshops;

create policy "workshops_admin_read"
  on public.workshops for select
  using (public.is_platform_admin());

create policy "workshops_owner_read"
  on public.workshops for select
  using (exists (
    select 1 from public.profiles p
    where p.id = auth.uid() and p.workshop_id = workshops.id
  ));

-- لا كتابة على workshops من الـ API: الكتابة عبر دوال SECURITY DEFINER فقط
revoke insert, update, delete, truncate on public.workshops from anon, authenticated;

-- إخفاء admin_notes عن أصحاب الورش: select على كل الأعمدة ما عدا admin_notes.
-- (أي عمود جديد تضيفه لاحقًا لازم تديله grant select يدويًا لـ authenticated)
do $$
declare cols text;
begin
  select string_agg(quote_ident(column_name), ', ')
    into cols
  from information_schema.columns
  where table_schema = 'public' and table_name = 'workshops'
    and column_name <> 'admin_notes';

  execute 'revoke select on public.workshops from anon, authenticated';
  execute format('grant select (%s) on public.workshops to authenticated', cols);
end $$;

-- Trigger احتياطي: حتى لو تسرّبت صلاحية كتابة، الأعمدة الحساسة محمية
create or replace function public.protect_workshop_admin_columns()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  -- بدون مستخدم (service_role / SQL Editor / ويب هوك الدفع) أو أدمن: مسموح
  if auth.uid() is null or public.is_platform_admin() then
    return new;
  end if;

  if new.status             is distinct from old.status
  or new.subscription_start is distinct from old.subscription_start
  or new.subscription_end   is distinct from old.subscription_end
  or new.suspended_reason   is distinct from old.suspended_reason
  or new.admin_notes        is distinct from old.admin_notes then
    raise exception 'protected_columns' using errcode = '42501';
  end if;

  return new;
end;
$$;

drop trigger if exists trg_protect_workshop_admin on public.workshops;
create trigger trg_protect_workshop_admin
  before update on public.workshops
  for each row
  execute function public.protect_workshop_admin_columns();

-- ---------- 5) سجل عمليات المنصة (append-only) ----------
create table if not exists public.platform_audit (
  id           bigserial primary key,
  actor_id     uuid references auth.users(id) on delete set null,
  actor_email  text,
  action       text not null,
  workshop_id  uuid,
  before       jsonb,
  after        jsonb,
  created_at   timestamptz not null default now()
);

create index if not exists pa_created_idx  on public.platform_audit(created_at desc);
create index if not exists pa_workshop_idx on public.platform_audit(workshop_id);

alter table public.platform_audit enable row level security;
revoke all on public.platform_audit from anon, authenticated;
grant select on public.platform_audit to authenticated;

drop policy if exists "pa_audit_admin_read" on public.platform_audit;
create policy "pa_audit_admin_read"
  on public.platform_audit for select
  using (public.is_platform_admin());

create or replace function public.platform_audit_append_only()
returns trigger
language plpgsql
as $$
begin
  raise exception 'platform_audit_is_append_only' using errcode = '42501';
end;
$$;

drop trigger if exists pa_no_update_delete on public.platform_audit;
create trigger pa_no_update_delete
  before update or delete on public.platform_audit
  for each row execute function public.platform_audit_append_only();

-- ---------- 6) admin_update_workshop ----------
create or replace function public.admin_update_workshop(
  p_workshop_id  uuid,
  p_status       text,
  p_start        date,
  p_end          date,
  p_reason       text,
  p_notes        text
)
returns void
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_before jsonb;
  v_after  jsonb;
  v_email  text;
begin
  if not public.is_platform_admin() then
    raise exception 'not_authorized' using errcode = '42501';
  end if;

  if p_status not in ('active','pending','suspended','expired') then
    raise exception 'invalid_status' using errcode = '22023';
  end if;

  if p_start is not null and p_end is not null and p_end < p_start then
    raise exception 'end_before_start' using errcode = '22023';
  end if;

  -- for update: قفل الصف ليكون "قبل/بعد" دقيقين لو أدمنين عدّلوا معًا
  select jsonb_build_object(
    'status',             status,
    'subscription_start', subscription_start::date,
    'subscription_end',   subscription_end::date,
    'suspended_reason',   suspended_reason,
    'admin_notes',        admin_notes
  )
  into v_before
  from public.workshops
  where id = p_workshop_id
  for update;

  if v_before is null then
    raise exception 'workshop_not_found' using errcode = 'P0002';
  end if;

  update public.workshops
     set status             = p_status,
         subscription_start = p_start,
         subscription_end   = p_end,
         suspended_reason   = nullif(p_reason, ''),
         admin_notes        = nullif(p_notes, '')
   where id = p_workshop_id;

  v_after := jsonb_build_object(
    'status',             p_status,
    'subscription_start', p_start,
    'subscription_end',   p_end,
    'suspended_reason',   nullif(p_reason, ''),
    'admin_notes',        nullif(p_notes, '')
  );

  if v_before is distinct from v_after then
    select email into v_email from auth.users where id = auth.uid();
    insert into public.platform_audit
      (actor_id, actor_email, action, workshop_id, before, after)
    values
      (auth.uid(), v_email, 'update_workshop', p_workshop_id, v_before, v_after);
  end if;
end;
$$;
revoke all on function public.admin_update_workshop(uuid,text,date,date,text,text) from public, anon;
grant  execute on function public.admin_update_workshop(uuid,text,date,date,text,text) to authenticated;

-- ---------- 7) قراءة السجل ----------
create or replace function public.admin_list_audit(
  p_limit       int  default 200,
  p_workshop_id uuid default null
)
returns table (
  id            bigint,
  actor_email   text,
  action        text,
  workshop_id   uuid,
  workshop_name text,
  before        jsonb,
  after         jsonb,
  created_at    timestamptz
)
language plpgsql
stable
security definer
set search_path = public, pg_temp
as $$
begin
  if not public.is_platform_admin() then
    raise exception 'not_authorized' using errcode = '42501';
  end if;

  return query
  select a.id, a.actor_email, a.action, a.workshop_id, w.name::text,
         a.before, a.after, a.created_at
  from public.platform_audit a
  left join public.workshops w on w.id = a.workshop_id
  where (p_workshop_id is null or a.workshop_id = p_workshop_id)
  order by a.created_at desc
  limit greatest(1, least(coalesce(p_limit, 200), 500));
end;
$$;
revoke all on function public.admin_list_audit(int, uuid) from public, anon;
grant  execute on function public.admin_list_audit(int, uuid) to authenticated;

-- ---------- 8) إيقاف/انتهاء الورشة يتطبق على مستوى قاعدة البيانات ----------
create or replace function public.workshop_is_active(wid uuid)
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select exists (
    select 1 from public.workshops w
    where w.id = wid
      and w.status = 'active'
      and (w.subscription_end is null or w.subscription_end::date >= current_date)
  );
$$;
revoke all on function public.workshop_is_active(uuid) from public, anon;
grant  execute on function public.workshop_is_active(uuid) to authenticated;

-- ورشة المستخدم الحالي نشطة؟ (بتتحسب مرة واحدة في الاستعلام عند استخدامها داخل (select ...))
create or replace function public.my_workshop_active()
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select coalesce(
    (select public.workshop_is_active(p.workshop_id)
       from public.profiles p where p.id = auth.uid()),
    false);
$$;
revoke all on function public.my_workshop_active() from public, anon;
grant  execute on function public.my_workshop_active() to authenticated;

-- سياسة RESTRICTIVE: بتتجمع بـ AND مع السياسات الحالية بدون ما نحتاج نعدّلها.
-- ورشة موقوفة/منتهية/بانتظار التفعيل = لا قراءة ولا كتابة للسجلات (إلا لمدير المنصة).
drop policy if exists "records_require_active_workshop" on public.workshop_records;
create policy "records_require_active_workshop"
  on public.workshop_records
  as restrictive
  for all
  to authenticated
  using      ((select public.is_platform_admin()) or (select public.my_workshop_active()))
  with check ((select public.is_platform_admin()) or (select public.my_workshop_active()));

-- ---------- 9) admin_stats و admin_list_workshops (بفحص أدمن صريح) ----------
-- نحذف أي نسخ قديمة (بأي توقيع) عشان ما يحصلش تداخل overloads
do $$
declare r record;
begin
  for r in
    select p.oid::regprocedure::text as sig
    from pg_proc p
    where p.pronamespace = 'public'::regnamespace
      and p.proname in ('admin_stats', 'admin_list_workshops')
  loop
    execute 'drop function ' || r.sig;
  end loop;
end $$;

-- الحالة الفعلية: "نشطة" لكن تاريخها انتهى = منتهية
create function public.admin_stats()
returns jsonb
language plpgsql
stable
security definer
set search_path = public, pg_temp
as $$
begin
  if not public.is_platform_admin() then
    raise exception 'not_authorized' using errcode = '42501';
  end if;

  return (
    select jsonb_build_object(
      'total',     count(*),
      'active',    count(*) filter (where e.st = 'active'),
      'pending',   count(*) filter (where e.st = 'pending'),
      'suspended', count(*) filter (where e.st = 'suspended'),
      'expired',   count(*) filter (where e.st = 'expired')
    )
    from (
      select case
               when w.status = 'active'
                and w.subscription_end is not null
                and w.subscription_end::date < current_date then 'expired'
               else w.status::text
             end as st
      from public.workshops w
    ) e
  );
end;
$$;
revoke all on function public.admin_stats() from public, anon;
grant  execute on function public.admin_stats() to authenticated;

create function public.admin_list_workshops(p_search text default null)
returns table (
  workshop_id      uuid,
  workshop_name    text,
  owner_name       text,
  owner_email      text,
  workshop_status  text,
  sub_start        date,
  sub_end          date,
  created_at       timestamptz,
  suspended_reason text,
  admin_notes      text
)
language plpgsql
stable
security definer
set search_path = public, pg_temp
as $$
declare
  v_q text := nullif(left(btrim(coalesce(p_search, '')), 100), '');
begin
  if not public.is_platform_admin() then
    raise exception 'not_authorized' using errcode = '42501';
  end if;

  -- تهريب محارف LIKE حتى لا يتحول البحث لنمط
  if v_q is not null then
    v_q := '%' || replace(replace(replace(v_q, '\', '\\'), '%', '\%'), '_', '\_') || '%';
  end if;

  return query
  select w.id::uuid,
         w.name::text,
         o.owner_name::text,
         o.owner_email::text,
         (case
            when w.status = 'active'
             and w.subscription_end is not null
             and w.subscription_end::date < current_date then 'expired'
            else w.status::text
          end)::text,
         w.subscription_start::date,
         w.subscription_end::date,
         w.created_at::timestamptz,
         w.suspended_reason::text,
         w.admin_notes::text
  from public.workshops w
  left join lateral (
    select p.name as owner_name, u.email as owner_email
    from public.profiles p
    join auth.users u on u.id = p.id
    where p.workshop_id = w.id and p.role = 'owner'
    order by p.created_at asc
    limit 1
  ) o on true
  where v_q is null
     or w.name ilike v_q
     or w.id::text ilike v_q
     or o.owner_email ilike v_q
     or o.owner_name ilike v_q
  order by w.created_at desc
  limit 1000;
end;
$$;
revoke all on function public.admin_list_workshops(text) from public, anon;
grant  execute on function public.admin_list_workshops(text) to authenticated;

-- ---------- 10) حماية profiles و workshop_features ----------
-- مستخدم عادي ما يقدرش يغيّر دوره أو ورشته أو ربطه بفني
create or replace function public.protect_profile_columns()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  if auth.uid() is null or public.is_platform_admin() then
    return new;
  end if;

  if new.id            is distinct from old.id
  or new.role          is distinct from old.role
  or new.workshop_id   is distinct from old.workshop_id
  or new.technician_id is distinct from old.technician_id then
    raise exception 'protected_columns' using errcode = '42501';
  end if;

  return new;
end;
$$;

drop trigger if exists trg_protect_profile on public.profiles;
create trigger trg_protect_profile
  before update on public.profiles
  for each row
  execute function public.protect_profile_columns();

-- ميزات الورشة بتتحكم فيها المنصة فقط: لا كتابة من الـ API
do $$
begin
  if to_regclass('public.workshop_features') is not null then
    execute 'revoke insert, update, delete, truncate on public.workshop_features from anon, authenticated';
  end if;
end $$;

-- =========================================================
-- بعد التشغيل: اختبارات سريعة (من حساب مالك عادي، مش أدمن)
--   1) update workshops set status='active'      -> لازم يفشل
--   2) select admin_notes from workshops          -> لازم يفشل (permission denied)
--   3) select * from admin_list_workshops()       -> لازم يفشل (not_authorized)
--   4) ورشة status='suspended': قراءة workshop_records -> صفر صفوف
-- =========================================================

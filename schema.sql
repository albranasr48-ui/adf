-- عيادة سرت المركزية: مخطط قاعدة بيانات Supabase
-- نفّذ في Supabase > SQL Editor. لا تضع service_role key في الموقع.
create extension if not exists pgcrypto;

create table if not exists public.departments (
 id uuid primary key default gen_random_uuid(),
 name text not null unique,
 created_at timestamptz not null default now()
);
create table if not exists public.doctors (
 id uuid primary key default gen_random_uuid(),
 name text not null,
 department_id uuid not null references public.departments(id) on delete restrict,
 room_number text not null,
 case_duration_minutes integer not null default 20 check(case_duration_minutes between 1 and 240),
 days text not null default '',
 start_time time not null default '09:00',
 end_time time not null default '17:00',
 is_available boolean not null default true,
 created_at timestamptz not null default now()
);
create table if not exists public.bookings (
 id uuid primary key default gen_random_uuid(),
 doctor_id uuid not null references public.doctors(id) on delete restrict,
 department_id uuid not null references public.departments(id) on delete restrict,
 patient_name text not null,
 phone text not null,
 gender text check(gender in ('ذكر','أنثى') or gender is null),
 age integer check(age between 0 and 120 or age is null),
 notes text,
 case_number integer not null check(case_number > 0),
 status text not null default 'waiting' check(status in ('waiting','in_progress','completed','cancelled')),
 created_at timestamptz not null default now()
);
create index if not exists bookings_doctor_status_idx on public.bookings(doctor_id,status,case_number);
create index if not exists bookings_phone_idx on public.bookings(phone,created_at desc);
create table if not exists public.clinic_settings (
 id integer primary key check(id=1),
 name text not null default 'عيادة سرت المركزية',
 logo_url text,
 updated_at timestamptz not null default now()
);
insert into public.clinic_settings(id,name) values(1,'عيادة سرت المركزية') on conflict(id) do nothing;

-- الملف الشخصي يحدد صلاحيات حسابات الإدارة فقط.
create table if not exists public.staff_profiles (
 user_id uuid primary key references auth.users(id) on delete cascade,
 role text not null check(role in ('admin','doctor')),
 display_name text,
 created_at timestamptz not null default now()
);

-- Views تعرض بيانات الأطباء العامة دون أي معلومات دخول.
create or replace view public.doctors_public with (security_invoker=true) as
 select id,name,department_id,room_number,case_duration_minutes,days,start_time,end_time,is_available from public.doctors;
create or replace view public.bookings_public with (security_invoker=true) as
 select b.id,b.phone,b.case_number,b.status,b.created_at,d.name as doctor_name,d.room_number,dep.name as department_name
 from public.bookings b join public.doctors d on d.id=b.doctor_id join public.departments dep on dep.id=b.department_id;

-- View الإدارة: الوصول مقيد بسياسات الجداول الأساسية.
create or replace view public.bookings_admin with (security_invoker=true) as
 select b.*,d.name as doctor_name,d.room_number,dep.name as department_name
 from public.bookings b join public.doctors d on d.id=b.doctor_id join public.departments dep on dep.id=b.department_id;

alter table public.departments enable row level security;
alter table public.doctors enable row level security;
alter table public.bookings enable row level security;
alter table public.clinic_settings enable row level security;
alter table public.staff_profiles enable row level security;

create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path=public
as $$ select exists(select 1 from public.staff_profiles where user_id=auth.uid() and role='admin'); $$;

-- سياسات القراءة العامة للأقسام والأطباء والإعدادات.
drop policy if exists "public read departments" on public.departments;
create policy "public read departments" on public.departments for select using (true);
drop policy if exists "admin manage departments" on public.departments;
create policy "admin manage departments" on public.departments for all using (public.is_admin()) with check (public.is_admin());

drop policy if exists "public read doctors" on public.doctors;
create policy "public read doctors" on public.doctors for select using (true);
drop policy if exists "admin manage doctors" on public.doctors;
create policy "admin manage doctors" on public.doctors for all using (public.is_admin()) with check (public.is_admin());

drop policy if exists "public read clinic settings" on public.clinic_settings;
create policy "public read clinic settings" on public.clinic_settings for select using (true);
drop policy if exists "admin manage clinic settings" on public.clinic_settings;
create policy "admin manage clinic settings" on public.clinic_settings for all using (public.is_admin()) with check (public.is_admin());

drop policy if exists "admin manage bookings" on public.bookings;
create policy "admin manage bookings" on public.bookings for all using (public.is_admin()) with check (public.is_admin());
drop policy if exists "public create booking" on public.bookings;
create policy "public create booking" on public.bookings for insert with check (
 length(trim(patient_name)) between 2 and 100
 and length(trim(phone)) between 5 and 30
 and case_number > 0
 and status='waiting'
);
drop policy if exists "public read queue" on public.bookings;
create policy "public read queue" on public.bookings for select using (status in ('waiting','in_progress'));

drop policy if exists "read own staff profile" on public.staff_profiles;
create policy "read own staff profile" on public.staff_profiles for select using (user_id=auth.uid());
drop policy if exists "admin manage staff profiles" on public.staff_profiles;
create policy "admin manage staff profiles" on public.staff_profiles for all using (public.is_admin()) with check (public.is_admin());

-- إلغاء المراجع: يتحقق من رقم الهاتف في دالة محدودة الصلاحية.
create or replace function public.cancel_booking(booking_id uuid, patient_phone text)
returns boolean language plpgsql security definer set search_path=public
as $$
declare changed integer;
begin
 update public.bookings set status='cancelled'
 where id=booking_id and phone=patient_phone and status='waiting';
 get diagnostics changed = row_count;
 return changed=1;
end; $$;
revoke all on function public.cancel_booking(uuid,text) from public;
grant execute on function public.cancel_booking(uuid,text) to anon,authenticated;

grant select on public.doctors_public to anon,authenticated;
grant select on public.bookings_public to anon,authenticated;
grant select on public.bookings_admin to authenticated;
grant select,insert on public.bookings to anon,authenticated;
grant update,delete on public.bookings to authenticated;
grant select on public.departments,public.doctors,public.clinic_settings to anon,authenticated;
grant insert,update,delete on public.departments,public.doctors,public.clinic_settings to authenticated;
grant select on public.staff_profiles to authenticated;

-- ملاحظة أمنية:
-- للنسخة المنشورة فعلياً، لا تعتمد على رقم الهاتف كوسيلة تحقق قوية.
-- هذه النسخة أولية؛ استكمل حماية إلغاء الحجوزات بمكالمة تحقق OTP/بوابة وسيطة،
-- وحدّ معدل الحجوزات (rate limiting) لمنع الحجز الآلي.

-- ===== تحديثات شاشة الطبيب والبحث باسم المراجع ورقم هاتفه =====
alter table public.staff_profiles add column if not exists doctor_id uuid references public.doctors(id) on delete set null;

create or replace function public.is_doctor_for(target_doctor uuid)
returns boolean language sql stable security definer set search_path=public
as $$ select exists(select 1 from public.staff_profiles where user_id=auth.uid() and role='doctor' and doctor_id=target_doctor); $$;

-- الطبيب يرى الحالات التابعة لعيادته فقط، ويستطيع تحديث حالة تلك الحالات.
drop policy if exists "doctor read own bookings" on public.bookings;
create policy "doctor read own bookings" on public.bookings for select to authenticated using (public.is_doctor_for(doctor_id));
drop policy if exists "doctor update own bookings" on public.bookings;
create policy "doctor update own bookings" on public.bookings for update to authenticated using (public.is_doctor_for(doctor_id)) with check (public.is_doctor_for(doctor_id));
drop policy if exists "doctor update own availability" on public.doctors;
create policy "doctor update own availability" on public.doctors for update to authenticated using (public.is_doctor_for(id)) with check (public.is_doctor_for(id));

-- لا يعرض البحث بيانات المراجع إلا عند تطابق الاسم ورقم الهاتف معاً.
create or replace function public.lookup_my_bookings(patient_name_input text, patient_phone_input text)
returns table(id uuid, case_number integer, status text, created_at timestamptz, doctor_name text, room_number text, department_name text)
language sql stable security definer set search_path=public
as $$
  select b.id,b.case_number,b.status,b.created_at,d.name,d.room_number,dep.name
  from public.bookings b
  join public.doctors d on d.id=b.doctor_id
  join public.departments dep on dep.id=b.department_id
  where lower(trim(b.patient_name))=lower(trim(patient_name_input))
    and regexp_replace(b.phone,'[[:space:]]','','g')=regexp_replace(trim(patient_phone_input),'[[:space:]]','','g')
    and b.status <> 'cancelled'
  order by b.created_at desc;
$$;
revoke all on function public.lookup_my_bookings(text,text) from public;
grant execute on function public.lookup_my_bookings(text,text) to anon,authenticated;

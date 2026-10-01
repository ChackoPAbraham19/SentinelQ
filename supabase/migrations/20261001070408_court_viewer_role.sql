-- Keep all existing role permissions and RLS; add court logins managed by the backend.
alter table public.sentinelq_authorities drop constraint sentinelq_authorities_role_check;
alter table public.sentinelq_authorities add constraint sentinelq_authorities_role_check
  check (role in ('ADMIN', 'CASE_MANAGER', 'INVESTIGATOR', 'AUDITOR', 'COURT'));

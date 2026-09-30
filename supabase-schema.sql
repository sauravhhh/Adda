-- Adda backend schema — mirrors the live Supabase project (mosycrhrpdaqcbfqolhq).
-- Safe to re-run: every statement is idempotent (IF NOT EXISTS / DROP IF EXISTS guards).
-- Run in Supabase SQL Editor (Database → SQL → New query).
--
-- Security model (verified by end-to-end tests 2026-10-01):
--  * Every table has RLS; users can only touch their own rows (auth.uid() checks).
--  * DMs are private: only conversation members can read/insert messages or add members.
--  * Storage: anyone can read images; authenticated users may only write inside
--    their own "<user-uuid>/" folder in each bucket.

-- ============ TABLES ============
create table if not exists profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text unique not null,
  name text not null default '',
  bio text not null default '',
  avatar_url text,
  created_at timestamptz not null default now()
);

create table if not exists posts (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references profiles(id) on delete cascade,
  image_url text,
  caption text not null default '',
  created_at timestamptz not null default now()
);

create table if not exists likes (
  post_id uuid not null references posts(id) on delete cascade,
  user_id uuid not null references profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (post_id, user_id)
);

create table if not exists comments (
  id uuid primary key default gen_random_uuid(),
  post_id uuid not null references posts(id) on delete cascade,
  user_id uuid not null references profiles(id) on delete cascade,
  body text not null,
  created_at timestamptz not null default now()
);

create table if not exists follows (
  follower_id uuid not null references profiles(id) on delete cascade,
  following_id uuid not null references profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (follower_id, following_id),
  check (follower_id <> following_id)
);

create table if not exists conversations (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now()
);

create table if not exists conversation_members (
  conversation_id uuid not null references conversations(id) on delete cascade,
  user_id uuid not null references profiles(id) on delete cascade,
  primary key (conversation_id, user_id)
);

create table if not exists messages (
  id uuid primary key default gen_random_uuid(),
  conversation_id uuid not null references conversations(id) on delete cascade,
  sender_id uuid not null references profiles(id) on delete cascade,
  body text not null,
  created_at timestamptz not null default now()
);

-- ============ STORAGE BUCKETS ============
insert into storage.buckets (id, name, public)
values ('post-images', 'post-images', true),
       ('avatars', 'avatars', true)
on conflict (id) do nothing;

-- ============ AUTO-CREATE PROFILE ON SIGNUP ============
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path to 'public'
as $function$
begin
  insert into public.profiles (id, username, name, avatar_url)
  values (
    new.id,
    coalesce(nullif(new.raw_user_meta_data->>'username',''), split_part(new.email,'@',1)),
    coalesce(nullif(new.raw_user_meta_data->>'name',''), split_part(new.email,'@',1)),
    'https://i.pravatar.cc/150?img=' || (abs(hashtext(new.id::text)) % 70 + 1)
  )
  on conflict (id) do nothing;
  return new;
end;
$function$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ============ RLS ============
alter table profiles enable row level security;
alter table posts enable row level security;
alter table likes enable row level security;
alter table comments enable row level security;
alter table follows enable row level security;
alter table conversations enable row level security;
alter table conversation_members enable row level security;
alter table messages enable row level security;

-- drop current + legacy policy names so re-runs converge
drop policy if exists "profiles readable" on profiles;
drop policy if exists "profiles insert own" on profiles;
drop policy if exists "profiles update own" on profiles;
drop policy if exists "posts readable" on posts;
drop policy if exists "posts insert own" on posts;
drop policy if exists "posts delete own" on posts;
drop policy if exists "likes readable" on likes;
drop policy if exists "likes insert own" on likes;
drop policy if exists "likes delete own" on likes;
drop policy if exists "comments readable" on comments;
drop policy if exists "comments insert own" on comments;
drop policy if exists "comments delete own" on comments;
drop policy if exists "follows readable" on follows;
drop policy if exists "follows insert own" on follows;
drop policy if exists "follows delete own" on follows;
drop policy if exists "conversations readable by members" on conversations;
drop policy if exists "conversations insert" on conversations;
drop policy if exists "members readable" on conversation_members;
drop policy if exists "members insert self" on conversation_members;  -- legacy, replaced below
drop policy if exists "members insert" on conversation_members;
drop policy if exists "messages readable by members" on messages;
drop policy if exists "messages insert own" on messages;
drop policy if exists "public read post-images" on storage.objects;
drop policy if exists "upload post-images" on storage.objects;        -- legacy broad policy
drop policy if exists "public read avatars" on storage.objects;
drop policy if exists "upload avatars" on storage.objects;            -- legacy broad policy
drop policy if exists "upload own post-images" on storage.objects;
drop policy if exists "upload own avatars" on storage.objects;
drop policy if exists "delete own post-images" on storage.objects;
drop policy if exists "delete own avatars" on storage.objects;
drop policy if exists "update own post-images" on storage.objects;
drop policy if exists "update own avatars" on storage.objects;

-- profiles: anyone authenticated can read; users manage their own row
create policy "profiles readable" on profiles for select to authenticated using (true);
create policy "profiles insert own" on profiles for insert to authenticated with check (auth.uid() = id);
create policy "profiles update own" on profiles for update to authenticated using (auth.uid() = id);

-- posts: readable by all authenticated; users manage their own
create policy "posts readable" on posts for select to authenticated using (true);
create policy "posts insert own" on posts for insert to authenticated with check (auth.uid() = user_id);
create policy "posts delete own" on posts for delete to authenticated using (auth.uid() = user_id);

-- likes: readable by all; users manage their own
create policy "likes readable" on likes for select to authenticated using (true);
create policy "likes insert own" on likes for insert to authenticated with check (auth.uid() = user_id);
create policy "likes delete own" on likes for delete to authenticated using (auth.uid() = user_id);

-- comments: readable by all; users manage their own
create policy "comments readable" on comments for select to authenticated using (true);
create policy "comments insert own" on comments for insert to authenticated with check (auth.uid() = user_id);
create policy "comments delete own" on comments for delete to authenticated using (auth.uid() = user_id);

-- follows: readable by all; users manage their own
create policy "follows readable" on follows for select to authenticated using (true);
create policy "follows insert own" on follows for insert to authenticated with check (auth.uid() = follower_id);
create policy "follows delete own" on follows for delete to authenticated using (auth.uid() = follower_id);

-- conversations: members can read; any authenticated user can create one
create policy "conversations readable by members" on conversations for select to authenticated
  using (exists (select 1 from conversation_members m where m.conversation_id = conversations.id and m.user_id = auth.uid()));
create policy "conversations insert" on conversations for insert to authenticated with check (true);

-- conversation_members: readable by all authenticated.
-- Insert: an existing member may add anyone (used by the app to add the chat peer
-- right after the creator takes the first seat); anyone may take the first seat of
-- an otherwise empty conversation (chat-creation bootstrap). Strangers can never
-- join an existing conversation.
create policy "members readable" on conversation_members for select to authenticated using (true);
create policy "members insert" on conversation_members for insert to authenticated
  with check (
    exists (select 1 from conversation_members m where m.conversation_id = conversation_members.conversation_id and m.user_id = auth.uid())
    or (
      auth.uid() = user_id
      and not exists (select 1 from conversation_members m where m.conversation_id = conversation_members.conversation_id)
    )
  );

-- messages: only members of the conversation can read; only a member can send as themselves
create policy "messages readable by members" on messages for select to authenticated
  using (exists (select 1 from conversation_members m where m.conversation_id = messages.conversation_id and m.user_id = auth.uid()));
create policy "messages insert own" on messages for insert to authenticated
  with check (
    auth.uid() = sender_id
    and exists (select 1 from conversation_members m where m.conversation_id = messages.conversation_id and m.user_id = auth.uid())
  );

-- storage: public reads; writes restricted to the user's own "<uuid>/" folder
create policy "public read post-images" on storage.objects for select using (bucket_id = 'post-images');
create policy "public read avatars" on storage.objects for select using (bucket_id = 'avatars');
create policy "upload own post-images" on storage.objects for insert to authenticated
  with check (bucket_id = 'post-images' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "upload own avatars" on storage.objects for insert to authenticated
  with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "update own post-images" on storage.objects for update to authenticated
  using (bucket_id = 'post-images' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "update own avatars" on storage.objects for update to authenticated
  using (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "delete own post-images" on storage.objects for delete to authenticated
  using (bucket_id = 'post-images' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "delete own avatars" on storage.objects for delete to authenticated
  using (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);

-- ============ REALTIME (live feed + live chat), idempotent ============
do $$
begin
  if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and tablename = 'posts') then
    alter publication supabase_realtime add table posts;
  end if;
  if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and tablename = 'likes') then
    alter publication supabase_realtime add table likes;
  end if;
  if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and tablename = 'comments') then
    alter publication supabase_realtime add table comments;
  end if;
  if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and tablename = 'follows') then
    alter publication supabase_realtime add table follows;
  end if;
  if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and tablename = 'messages') then
    alter publication supabase_realtime add table messages;
  end if;
end $$;

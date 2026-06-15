import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const SUPABASE_URL          = Deno.env.get('SUPABASE_URL')!;
const SUPABASE_SERVICE_ROLE = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'authorization, content-type, apikey',
    }});
  }

  try {
    const authHeader = req.headers.get('Authorization');
    if (!authHeader) return json({ error: 'Unauthorized' }, 401);

    const token = authHeader.replace('Bearer ', '');
    const adminClient = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE);

    // Verify caller using admin client (no anon key needed)
    const { data: { user }, error: userErr } = await adminClient.auth.getUser(token);
    if (userErr || !user) return json({ error: 'Unauthorized' }, 401);

    const { data: callerProfile } = await adminClient
      .from('user_profiles').select('role').eq('user_id', user.id).single();
    // Only Super Admin may permanently delete accounts.
    if (callerProfile?.role !== 'super_admin') {
      return json({ error: 'Forbidden: only a Super Admin can delete accounts' }, 403);
    }

    const { username } = await req.json();
    if (!username) return json({ error: 'Username required' }, 400);

    // Resolve the target account
    const { data: target } = await adminClient
      .from('user_profiles').select('user_id').eq('username', username).single();
    if (!target) return json({ error: 'Account not found' }, 404);

    // Never allow deleting your own signed-in account
    if (target.user_id === user.id) {
      return json({ error: 'You cannot delete your own account' }, 400);
    }

    // Delete the auth user. The user_profiles row is removed automatically
    // via the `on delete cascade` foreign key, but we also delete it
    // explicitly as a safeguard in case the cascade is ever dropped.
    const { error: delErr } = await adminClient.auth.admin.deleteUser(target.user_id);
    if (delErr) return json({ error: delErr.message }, 400);

    await adminClient.from('user_profiles').delete().eq('user_id', target.user_id);

    return json({ success: true });
  } catch (e) {
    return json({ error: String(e) }, 500);
  }
});

function json(data: object, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'authorization, content-type, apikey',
    },
  });
}

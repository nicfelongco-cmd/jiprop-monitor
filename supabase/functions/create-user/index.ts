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

    const { data: profile } = await adminClient
      .from('user_profiles').select('role').eq('user_id', user.id).single();
    if (!['sp_admin', 'super_admin'].includes(profile?.role)) {
      return json({ error: 'Forbidden: insufficient role' }, 403);
    }

    const { username, password, role, assignedFi } = await req.json();
    if (!username || !password) return json({ error: 'Username and password required' }, 400);

    const { data: created, error: createErr } = await adminClient.auth.admin.createUser({
      email: `${username}@jiprop.app`,
      password,
      email_confirm: true,
    });
    if (createErr) return json({ error: createErr.message }, 400);

    const { error: profileErr } = await adminClient.from('user_profiles').insert({
      user_id: created.user.id,
      username,
      role: role || 'viewer',
      assigned_fi: assignedFi || '',
      status: 'active',
    });
    if (profileErr) return json({ error: profileErr.message }, 400);

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

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const SUPABASE_URL            = Deno.env.get('SUPABASE_URL')!;
const SUPABASE_ANON_KEY       = Deno.env.get('SUPABASE_ANON_KEY')!;
const SUPABASE_SERVICE_ROLE   = Deno.env.get('SERVICE_ROLE_KEY')!;

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'authorization, content-type',
    }});
  }

  try {
    // Verify caller is sp_admin or super_admin
    const authHeader = req.headers.get('Authorization');
    if (!authHeader) return json({ error: 'Unauthorized' }, 401);

    const callerClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      global: { headers: { Authorization: authHeader } },
    });
    const { data: { user } } = await callerClient.auth.getUser();
    if (!user) return json({ error: 'Unauthorized' }, 401);

    const { data: profile } = await callerClient
      .from('user_profiles').select('role').eq('user_id', user.id).single();
    if (!['sp_admin', 'super_admin'].includes(profile?.role)) {
      return json({ error: 'Forbidden: insufficient role' }, 403);
    }

    const { username, password, role } = await req.json();
    if (!username || !password) return json({ error: 'Username and password required' }, 400);

    // Create user via admin API — no email sent
    const adminClient = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE);
    const { data: created, error: createErr } = await adminClient.auth.admin.createUser({
      email: `${username}@jiprop.app`,
      password,
      email_confirm: true,
    });
    if (createErr) return json({ error: createErr.message }, 400);

    // Insert profile
    const { error: profileErr } = await adminClient.from('user_profiles').insert({
      user_id: created.user.id,
      username,
      role: role || 'viewer',
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
    },
  });
}

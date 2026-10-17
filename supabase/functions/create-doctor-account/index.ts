import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type', 'Access-Control-Allow-Methods': 'POST, OPTIONS' }
Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors })
  try {
    const url = Deno.env.get('SUPABASE_URL')!, anon = Deno.env.get('SUPABASE_ANON_KEY')!, service = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
    const authHeader = req.headers.get('Authorization') || ''
    const caller = createClient(url, anon, { global: { headers: { Authorization: authHeader } } })
    const { data: { user }, error: userError } = await caller.auth.getUser()
    if (userError || !user) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: { ...cors, 'Content-Type': 'application/json' } })
    const { data: profile } = await caller.from('staff_profiles').select('role').eq('user_id', user.id).maybeSingle()
    if (profile?.role !== 'admin') return new Response(JSON.stringify({ error: 'Admin only' }), { status: 403, headers: { ...cors, 'Content-Type': 'application/json' } })
    const { doctor_id, email, password, display_name } = await req.json()
    if (!doctor_id || !email || typeof password !== 'string' || password.length < 8) return new Response(JSON.stringify({ error: 'doctor_id, email and password (8+ chars) required' }), { status: 400, headers: { ...cors, 'Content-Type': 'application/json' } })
    const admin = createClient(url, service)
    const { data: doctor, error: doctorError } = await admin.from('doctors').select('id,name').eq('id', doctor_id).single()
    if (doctorError || !doctor) return new Response(JSON.stringify({ error: 'Doctor not found' }), { status: 404, headers: { ...cors, 'Content-Type': 'application/json' } })
    const { data: created, error: createError } = await admin.auth.admin.createUser({ email, password, email_confirm: true, user_metadata: { role: 'doctor', display_name: display_name || doctor.name } })
    if (createError || !created.user) return new Response(JSON.stringify({ error: createError?.message || 'Could not create user' }), { status: 400, headers: { ...cors, 'Content-Type': 'application/json' } })
    const { error: profileError } = await admin.from('staff_profiles').upsert({ user_id: created.user.id, role: 'doctor', display_name: display_name || doctor.name, doctor_id })
    if (profileError) { await admin.auth.admin.deleteUser(created.user.id); return new Response(JSON.stringify({ error: profileError.message }), { status: 400, headers: { ...cors, 'Content-Type': 'application/json' } }) }
    return new Response(JSON.stringify({ ok: true, user_id: created.user.id }), { headers: { ...cors, 'Content-Type': 'application/json' } })
  } catch (e) { return new Response(JSON.stringify({ error: String(e) }), { status: 500, headers: { ...cors, 'Content-Type': 'application/json' } }) }
})

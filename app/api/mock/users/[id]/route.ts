import { NextRequest } from "next/server";

export const runtime = "nodejs";

function makeUser(id: string) {
  return {
    id,
    email: `user${id}@example.com`,
    name: `User ${id}`,
    role: id === '1001' ? 'customer' : 'customer',
    created: new Date().toISOString(),
    profile: {
      address: `${id} Main St`,
      phone: `+1-555-${id}`
    }
  };
}

// Intentionally vulnerable: returns requested user by id regardless of authenticated user header
export async function GET(req: NextRequest, { params }: { params: { id: string } }) {
  const id = params.id;
  const authUser = req.headers.get('x-user-id') || 'anonymous';

  // Simulate some processing
  await new Promise((r) => setTimeout(r, 50));

  // This simulates an IDOR: any user can fetch any user's data via URL id
  const body = makeUser(id);
  return new Response(JSON.stringify({ ok: true, requestedBy: authUser, user: body }), {
    headers: { 'content-type': 'application/json' }
  });
}

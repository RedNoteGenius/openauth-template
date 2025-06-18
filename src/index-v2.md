import { issuer } from "@openauthjs/openauth";
import { CloudflareStorage } from "@openauthjs/openauth/storage/cloudflare";
import { PasswordProvider } from "@openauthjs/openauth/provider/password";
import { PasswordUI } from "@openauthjs/openauth/ui/password";
import { GoogleProvider } from "@openauthjs/openauth/provider/google";
import { GithubProvider } from "@openauthjs/openauth/provider/github";
import { createSubjects } from "@openauthjs/openauth/subject";
import { object, string } from "valibot";
import { Stripe } from "stripe";

// =================================================================
// 1. TYPE DEFINITIONS & CONFIGURATION
// =================================================================

interface Env {
  // Bindings
  AUTH_DB: D1Database;
  AUTH_STORAGE: KVNamespace;

  // Secrets
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
  STRIPE_API_KEY: string;
  STRIPE_WEBHOOK_SECRET: string;
}

const subjects = createSubjects({
  user: object({
    id: string(),
    email: string(),
  }),
});

const allowedOrigins = [
  'http://localhost:3000',       // For local development
  'https://your-frontend-app.com', // IMPORTANT: Replace with your production frontend URL
];

// =================================================================
// 2. DATABASE INITIALIZATION
// =================================================================

let isDbInitialized = false;

async function initializeDatabase(d1: D1Database) {
  console.log("Checking and initializing database schema if necessary...");
  const statements = [
    d1.prepare(`
      CREATE TABLE IF NOT EXISTS user (
        id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
        email TEXT NOT NULL UNIQUE,
        name TEXT,
        avatar_url TEXT,
        role TEXT NOT NULL DEFAULT 'free', -- e.g., 'free', 'pro'
        stripe_customer_id TEXT UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `),
    d1.prepare(`
      CREATE TABLE IF NOT EXISTS subscriptions (
        id TEXT PRIMARY KEY, -- Stripe Subscription ID (sub_xxxxxxxx)
        user_id TEXT NOT NULL,
        status TEXT NOT NULL, -- e.g., 'active', 'canceled', 'past_due'
        plan_id TEXT NOT NULL, -- Stripe Price ID (price_xxxxxxxx)
        current_period_end INTEGER NOT NULL, -- Unix timestamp
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES user(id) ON DELETE CASCADE
      );
    `),
    d1.prepare(`CREATE INDEX IF NOT EXISTS idx_user_email ON user(email);`),
    d1.prepare(`CREATE INDEX IF NOT EXISTS idx_subscriptions_user_id ON subscriptions(user_id);`),
  ];
  await d1.batch(statements);
  console.log("Database schema is ready.");
}

// =================================================================
// 3. WORKER ENTRYPOINT & ROUTING
// =================================================================

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    if (!isDbInitialized) {
      ctx.waitUntil(initializeDatabase(env.AUTH_DB));
      isDbInitialized = true;
    }

    const url = new URL(request.url);
    const requestOrigin = request.headers.get('Origin');
    let corsHeaders: Record<string, string> = {};
    if (requestOrigin && allowedOrigins.includes(requestOrigin)) {
      corsHeaders = {
        'Access-Control-Allow-Origin': requestOrigin,
        'Access-Control-Allow-Methods': 'POST, GET, OPTIONS, PUT, DELETE',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      };
    }

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    const openAuthIssuer = issuer({
      storage: CloudflareStorage({ namespace: env.AUTH_STORAGE }),
      subjects,
      providers: {
        password: PasswordProvider(PasswordUI({ sendCode: async (email, code) => { console.log(`DEMO: Code for ${email} is ${code}`); } })),
        google: GoogleProvider({ clientID: env.GOOGLE_CLIENT_ID, clientSecret: env.GOOGLE_CLIENT_SECRET }),
        github: GithubProvider({ clientID: env.GITHUB_CLIENT_ID, clientSecret: env.GITHUB_CLIENT_SECRET }),
      },
      success: async (issuerCtx, value) => {
        if (!value.email) throw new Error("Email not provided by auth provider.");
        const { id, email } = await getOrCreateUser(env, value.email, value.name, value.picture);
        return issuerCtx.subject("user", { id, email });
      },
      theme: { title: "Your App Name", logo: { /* Add your logo URLs here */ } },
    });

    let response;
    if (url.pathname.startsWith('/api/')) {
      response = await handleApiRequest(request, env, openAuthIssuer);
    } else {
      response = await openAuthIssuer.fetch(request, env, ctx);
    }
    
    const newResponse = new Response(response.body, response);
    Object.entries(corsHeaders).forEach(([key, value]) => newResponse.headers.set(key, value));
    
    return newResponse;
  },
} satisfies ExportedHandler<Env>;

// =================================================================
// 4. API HANDLER
// =================================================================

async function handleApiRequest(request: Request, env: Env, issuer: any): Promise<Response> {
  const { pathname } = new URL(request.url);
  const jsonHeaders = { 'Content-Type': 'application/json' };

  let userSubject: { id: string; email: string; } | undefined;
  if (!pathname.startsWith('/api/webhooks')) {
    try {
      userSubject = await issuer.getSubject("user", request);
      if (!userSubject) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: jsonHeaders });
    } catch (e) {
      return new Response(JSON.stringify({ error: 'Invalid or expired token' }), { status: 401, headers: jsonHeaders });
    }
  }

  try {
    if (pathname === '/api/user/me' && request.method === 'GET') {
      return handleGetUserMe(env, userSubject!);
    }
    if (pathname === '/api/subscriptions/checkout-session' && request.method === 'POST') {
      return handleCreateCheckoutSession(request, env, userSubject!);
    }
    if (pathname === '/api/subscriptions/portal-session' && request.method === 'POST') {
      return handleCreatePortalSession(request, env, userSubject!);
    }
    if (pathname === '/api/webhooks/stripe' && request.method === 'POST') {
      return handleStripeWebhook(request, env);
    }
  } catch (e: any) {
    console.error("API Error:", e);
    return new Response(JSON.stringify({ error: e.message || "An internal server error occurred." }), { status: 500, headers: jsonHeaders });
  }

  return new Response(JSON.stringify({ error: 'API route not found' }), { status: 404, headers: jsonHeaders });
}

// =================================================================
// 5. API IMPLEMENTATIONS
// =================================================================

async function handleGetUserMe(env: Env, userSubject: { id: string }) {
  const user = await env.AUTH_DB.prepare(
      `SELECT id, email, name, avatar_url, role, stripe_customer_id FROM user WHERE id = ?`
  ).bind(userSubject.id).first();
  if (!user) throw new Error("User not found.");

  const subscription = await env.AUTH_DB.prepare(
      `SELECT id, status, plan_id, current_period_end FROM subscriptions WHERE user_id = ? AND status IN ('active', 'trialing')`
  ).bind(userSubject.id).first();

  return Response.json({ ...user, subscription: subscription || null });
}

async function handleCreateCheckoutSession(request: Request, env: Env, userSubject: { id: string }) {
  const stripe = new Stripe(env.STRIPE_API_KEY, { apiVersion: '2023-10-16' });
  const { priceId, successUrl, cancelUrl } = await request.json<{ priceId: string; successUrl: string; cancelUrl: string; }>();

  const user = await env.AUTH_DB.prepare(`SELECT id, email, stripe_customer_id FROM user WHERE id = ?`).bind(userSubject.id).first<{ id: string; email: string; stripe_customer_id: string | null; }>();
  if (!user) throw new Error("User not found.");

  let stripeCustomerId = user.stripe_customer_id;
  if (!stripeCustomerId) {
      const customer = await stripe.customers.create({ email: user.email, name: user.email, metadata: { userId: user.id } });
      stripeCustomerId = customer.id;
      await env.AUTH_DB.prepare(`UPDATE user SET stripe_customer_id = ? WHERE id = ?`).bind(stripeCustomerId, user.id).run();
  }

  const session = await stripe.checkout.sessions.create({
      customer: stripeCustomerId,
      line_items: [{ price: priceId, quantity: 1 }],
      mode: 'subscription',
      allow_promotion_codes: true,
      success_url: successUrl,
      cancel_url: cancelUrl,
  });

  return Response.json({ url: session.url });
}

async function handleCreatePortalSession(request: Request, env: Env, userSubject: { id: string }) {
  const stripe = new Stripe(env.STRIPE_API_KEY, { apiVersion: '2023-10-16' });
  const { returnUrl } = await request.json<{ returnUrl: string }>();

  const user = await env.AUTH_DB.prepare(`SELECT stripe_customer_id FROM user WHERE id = ?`).bind(userSubject.id).first<{ stripe_customer_id: string | null }>();
  if (!user || !user.stripe_customer_id) throw new Error("Stripe customer not found for this user.");
  
  const portalSession = await stripe.billingPortal.sessions.create({
      customer: user.stripe_customer_id,
      return_url: returnUrl,
  });

  return Response.json({ url: portalSession.url });
}

async function handleStripeWebhook(request: Request, env: Env) {
  const stripe = new Stripe(env.STRIPE_API_KEY, { apiVersion: '2023-10-16' });
  const signature = request.headers.get('stripe-signature');
  if (!signature) throw new Error("Stripe signature missing from header.");

  const body = await request.text();
  const event = await stripe.webhooks.constructEventAsync(body, signature, env.STRIPE_WEBHOOK_SECRET);
  
  const subscription = event.data.object as Stripe.Subscription;
  const customerId = subscription.customer as string;
  const user = await env.AUTH_DB.prepare(`SELECT id FROM user WHERE stripe_customer_id = ?`).bind(customerId).first<{ id: string }>();
  if (!user) throw new Error(`Webhook Error: User not found for Stripe customer ${customerId}`);

  const isSubscriptionActive = ['active', 'trialing'].includes(subscription.status);

  if (event.type.startsWith('customer.subscription.')) {
      await env.AUTH_DB.prepare(
          `INSERT INTO subscriptions (id, user_id, status, plan_id, current_period_end) VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET status=excluded.status, plan_id=excluded.plan_id, current_period_end=excluded.current_period_end, updated_at=CURRENT_TIMESTAMP`
      ).bind(subscription.id, user.id, subscription.status, subscription.items.data[0].price.id, subscription.current_period_end).run();

      const newRole = isSubscriptionActive ? 'pro' : 'free';
      await env.AUTH_DB.prepare(`UPDATE user SET role = ? WHERE id = ?`).bind(newRole, user.id).run();
  }
  
  return Response.json({ received: true });
}

// =================================================================
// 6. DATABASE HELPER FUNCTIONS
// =================================================================

async function getOrCreateUser(env: Env, email: string, name?: string, avatarUrl?: string): Promise<{ id: string, email: string }> {
  if (!email) throw new Error(`Invalid email provided.`);
  
  const normalizedName = name || email.split('@')[0];
  const normalizedAvatar = avatarUrl || null;

  const result = await env.AUTH_DB.prepare(
      `INSERT INTO user (email, name, avatar_url) VALUES (?, ?, ?)
       ON CONFLICT(email) DO UPDATE SET
         name = excluded.name,
         avatar_url = excluded.avatar_url,
         updated_at = CURRENT_TIMESTAMP
       RETURNING id, email`
  ).bind(email, normalizedName, normalizedAvatar).first<{ id: string, email: string }>();

  if (!result) throw new Error(`Failed to create or retrieve user for email: ${email}`);
  
  console.log(`DB: Upserted user ${result.id} with email ${email}`);
  return result;
}

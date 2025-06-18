import { issuer } from "@openauthjs/openauth";
import { CloudflareStorage } from "@openauthjs/openauth/storage/cloudflare";
import { PasswordProvider } from "@openauthjs/openauth/provider/password";
import { PasswordUI } from "@openauthjs/openauth/ui/password";
import { GoogleProvider } from "@openauthjs/openauth/provider/google";
import { MicrosoftProvider } from "@openauthjs/openauth/provider/microsoft";
import { AppleProvider } from "@openauthjs/openauth/provider/apple";
import { GithubProvider } from "@openauthjs/openauth/provider/github";
import { createSubjects } from "@openauthjs/openauth/subject";
import { object, string } from "valibot";

// Define your Env interface based on your worker's bindings
interface Env {
  AUTH_STORAGE: KVNamespace;
  AUTH_DB: D1Database;
  // Add OAuth client secrets here if you prefer to use environment variables
  // GOOGLE_CLIENT_SECRET: string;
  // MICROSOFT_CLIENT_SECRET: string;
  // APPLE_CLIENT_SECRET: string; // This would be more complex due to Apple's private key requirements
  // GITHUB_CLIENT_SECRET: string;
}

const subjects = createSubjects({
  user: object({
    id: string(),
    // email: string([email()]), // Optional: if you want to validate email format via valibot
  }),
});

// Define your allowed origins - IMPORTANT: Update this list
const allowedOrigins = [
  'https://47biaa75s8oj1xrfci68ilrjmuoptrc2uwq34e2jtztho5psof-h769614562.scf.usercontent.goog', // Your provided frontend origin
  // 'http://localhost:3000', // Example for local development
  // Add any other origins your frontend might be served from
];

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const requestOrigin = request.headers.get('Origin');
    let corsHeaders: Record<string, string> = {};

    if (requestOrigin && allowedOrigins.includes(requestOrigin)) {
      corsHeaders = {
        'Access-Control-Allow-Origin': requestOrigin,
        'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization', // Ensure 'Authorization' is included if you use Bearer tokens for /me
      };
    }

    // Handle CORS preflight requests
    if (request.method === 'OPTIONS') {
      if (requestOrigin && allowedOrigins.includes(requestOrigin)) {
        return new Response(null, { headers: corsHeaders });
      } else {
        return new Response('CORS preflight check failed for this origin.', { status: 403 });
      }
    }

    const url = new URL(request.url);

    // Demo redirect logic (if you keep it)
    if (url.pathname === "/") {
      url.searchParams.set("redirect_uri", url.origin + "/callback");
      url.searchParams.set("client_id", "your-client-id"); // Match this with your React app's OAUTH_CLIENT_ID
      url.searchParams.set("response_type", "token"); // For implicit flow, SPA typically uses 'token'
      url.pathname = "/authorize"; // Or a specific provider like /google/authorize
      
      // Redirects themselves don't typically need CORS headers for browser navigation,
      // but if fetched via JS, the initial request might.
      // However, this path is for user navigation, so direct redirect is fine.
      return Response.redirect(url.toString());
    } else if (url.pathname === "/callback") {
      // This callback is likely for server-side handling in more complex OAuth flows (e.g. auth code).
      // For implicit flow (token in hash), the frontend handles the hash directly.
      // If this /callback is hit by the OpenAuth server itself after a provider redirect,
      // and then it redirects *back* to your SPA's redirect_uri, that's part of OpenAuth's internal flow.
      // If your SPA's redirect_uri is this /callback, it needs to return something the SPA can use.
      // For now, returning JSON with CORS.
      let callbackResponse = Response.json({
        message: "OAuth flow server-side callback hit. This is usually for code exchange.",
        params: Object.fromEntries(url.searchParams.entries()),
      });
      // Add CORS headers to this response
      const newHeaders = new Headers(callbackResponse.headers);
      Object.entries(corsHeaders).forEach(([key, value]) => newHeaders.set(key, value));
      return new Response(callbackResponse.body, { ...callbackResponse, headers: newHeaders });
    }

    // Initialize OpenAuth issuer
    const openAuthIssuer = issuer({
      storage: CloudflareStorage({
        namespace: env.AUTH_STORAGE,
      }),
      subjects,
      providers: {
        password: PasswordProvider(
          PasswordUI({
            sendCode: async (email, code) => {
              console.log(`DEMO: Verification code for ${email} is ${code}. In production, send this via email.`);
            },
            copy: {
              input_code: "Code (check Worker logs)",
            },
          }),
        ),
        google: GoogleProvider({
          // clientID: env.GOOGLE_CLIENT_ID, // from environment variables
          // clientSecret: env.GOOGLE_CLIENT_SECRET, // from environment variables
          clientID: "YOUR_GOOGLE_CLIENT_ID", // Replace with your actual Google Client ID
          clientSecret: "YOUR_GOOGLE_CLIENT_SECRET", // Replace with your actual Google Client Secret
        }),
        microsoft: MicrosoftProvider({
          // clientID: env.MICROSOFT_CLIENT_ID,
          // clientSecret: env.MICROSOFT_CLIENT_SECRET,
          // tenant: "YOUR_MICROSOFT_TENANT_ID", // common, organizations, or specific tenant ID
          clientID: "YOUR_MICROSOFT_CLIENT_ID",
          clientSecret: "YOUR_MICROSOFT_CLIENT_SECRET",
          tenant: "common", // Or your specific tenant ID
        }),
        apple: AppleProvider({
          // clientID: env.APPLE_CLIENT_ID, // Usually your app's Bundle ID or Services ID
          // clientSecret: env.APPLE_CLIENT_SECRET_P8_KEY, // The .p8 key content
          // teamID: env.APPLE_TEAM_ID,
          // keyID: env.APPLE_KEY_ID,
          clientID: "YOUR_APPLE_CLIENT_ID_OR_SERVICE_ID",
          clientSecret: "YOUR_APPLE_P8_PRIVATE_KEY_CONTENT_AS_STRING", // Paste the content of your .p8 file here
          teamID: "YOUR_APPLE_TEAM_ID",
          keyID: "YOUR_APPLE_KEY_ID", // The Key ID for the .p8 private key
        }),
        github: GithubProvider({
          // clientID: env.GITHUB_CLIENT_ID,
          // clientSecret: env.GITHUB_CLIENT_SECRET,
          clientID: "YOUR_GITHUB_CLIENT_ID",
          clientSecret: "YOUR_GITHUB_CLIENT_SECRET",
        }),
      },
      theme: {
        title: "Novel Weaver AI Auth",
        primary: "#0EA5E9", // sky-500
        favicon: "https://workers.cloudflare.com/favicon.ico", // Replace with your favicon
        logo: { // Replace with your logos
          dark: "https://imagedelivery.net/wSMYJvS3Xw-n339CbDyDIA/db1e5c92-d3a6-4ea9-3e72-155844211f00/public",
          light:
            "https://imagedelivery.net/wSMYJvS3Xw-n339CbDyDIA/fa5a3023-7da9-466b-98a7-4ce01ee6c700/public",
        },
      },
      // The `success` handler is crucial for creating the user session (subject)
      // after successful authentication from any provider.
      success: async (issuerCtx, value) => {
        // `value.email` should be provided by OpenAuth after successful authentication
        // from password, Google, GitHub etc.
        if (!value.email) {
            // This case should ideally be handled by OpenAuth providers ensuring email is present
            // or by fetching it if necessary (e.g. from GitHub if not in initial scope)
            console.error("Email not provided by authentication provider for value:", value);
            throw new Error("User email could not be determined after authentication.");
        }
        const userId = await getOrCreateUser(env, value.email);
        return issuerCtx.subject("user", {
          id: userId,
          // email: value.email, // You can include email in the subject if needed by /me endpoint
        });
      },
       // Optional: configure /me endpoint if OpenAuth doesn't provide one by default
      // that returns id and email based on the 'user' subject.
      // If your `success` handler stores email in the subject, OpenAuth might provide it.
      // Otherwise, you might need a custom /me or adjust subject data.
      // me: async (meCtx) => {
      //   const subjectData = await meCtx.getSubject("user");
      //   if (!subjectData) return null;
      //   // Assuming your getOrCreateUser stores email somewhere or can retrieve it by id
      //   // This part is highly dependent on how your user data is structured and accessed
      //   const userEmail = await getEmailForUser(env, subjectData.id); // Implement getEmailForUser
      //   return { id: subjectData.id, email: userEmail };
      // }
    });

    // Process the request with OpenAuth
    const response = await openAuthIssuer.fetch(request, env, ctx);

    // Clone the response to add CORS headers
    const newResponse = new Response(response.body, response);
    if (requestOrigin && allowedOrigins.includes(requestOrigin)) {
      Object.entries(corsHeaders).forEach(([key, value]) => {
        newResponse.headers.set(key, value);
      });
    }
    
    return newResponse;
  },
} satisfies ExportedHandler<Env>;

async function getOrCreateUser(env: Env, email: string): Promise<string> {
  // Ensure email is not undefined or null before database operation
  if (!email || typeof email !== 'string') {
    throw new Error(`Invalid email provided for user creation: ${email}`);
  }

  const result = await env.AUTH_DB.prepare(
    `INSERT INTO user (email) VALUES (?) ON CONFLICT (email) DO UPDATE SET email = excluded.email RETURNING id;`
  )
    .bind(email)
    .first<{ id: string }>();

  if (!result || !result.id) {
    // This case should ideally not happen if the SQL is correct and DB is responsive
    throw new Error(`Failed to create or retrieve user ID for email: ${email}`);
  }
  console.log(`DB: Found or created user ${result.id} with email ${email}`);
  return result.id;
}

// Example: If you need to fetch email for the /me endpoint based on ID from subject
// async function getEmailForUser(env: Env, userId: string): Promise<string | undefined> {
//   if (!userId) return undefined;
//   const result = await env.AUTH_DB.prepare(
//     `SELECT email FROM user WHERE id = ?;`
//   )
//     .bind(userId)
//     .first<{ email: string }>();
//   return result?.email;
// }

// Ensure your D1 schema for 'user' table exists, e.g.:
// CREATE TABLE IF NOT EXISTS user (
//   id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))), -- Generates UUID
//   email TEXT NOT NULL UNIQUE,
//   created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
// );

// api/unlock.js
// Vercel serverless function. Checks the Drop 01 site password and the staff admin password
// on the server, so neither one ever ships in the page. Both live in Environment Variables
// set in the Vercel dashboard:
//   LUCENT_SITE_PASSWORD   turns the "Drop 01 is ready" gate on. Unset = no gate, the store is open.
//   LUCENT_ADMIN_PASSWORD  unlocks #/admin. Unset = admin stays locked.
//
// GET  /api/unlock?kind=site            -> { required: true|false }
// POST /api/unlock { kind, password }   -> 200 { ok: true } | 401 { ok: false } | 503 { ok: false, reason: "not-configured" }
//
// Note: the admin page only edits price and stock in the visitor's own browser session and
// exports a file, so this check keeps casual visitors out. It does not guard any server data.
import { createHash, timingSafeEqual } from "node:crypto";

const MAX_BODY_BYTES = 2 * 1024;
const LIMIT = 10; // attempts per minute per IP (best effort, resets with each new instance)
const hits = new Map();
function rateLimited(ip) {
  const now = Date.now();
  const recent = (hits.get(ip) || []).filter((t) => now - t < 60_000);
  recent.push(now);
  hits.set(ip, recent);
  if (hits.size > 5000) hits.clear();
  return recent.length > LIMIT;
}

function sameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  try {
    const host = req.headers["x-forwarded-host"] || req.headers.host;
    return new URL(origin).host === host;
  } catch {
    return false;
  }
}

function secretFor(kind) {
  if (kind === "site") return process.env.LUCENT_SITE_PASSWORD || "";
  if (kind === "admin") return process.env.LUCENT_ADMIN_PASSWORD || "";
  return null;
}

// Compare hashes so the check takes the same time whatever the guess is
function matches(guess, secret, caseless) {
  const norm = (s) => (caseless ? s.trim().toLowerCase() : s);
  const a = createHash("sha256").update(norm(guess)).digest();
  const b = createHash("sha256").update(norm(secret)).digest();
  return timingSafeEqual(a, b);
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");

  if (req.method === "GET") {
    const secret = secretFor(req.query && req.query.kind);
    if (secret === null) return res.status(400).json({ error: "Unknown kind" });
    return res.status(200).json({ required: secret.length > 0 });
  }
  if (req.method !== "POST") {
    res.setHeader("Allow", "GET, POST");
    return res.status(405).json({ error: "Method not allowed" });
  }
  if (!sameOrigin(req)) return res.status(403).json({ error: "Forbidden" });

  const ip = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim() || "unknown";
  if (rateLimited(ip)) return res.status(429).json({ ok: false, reason: "slow-down" });

  let body = req.body;
  if (typeof body === "string") {
    if (body.length > MAX_BODY_BYTES) return res.status(413).json({ ok: false });
    try { body = JSON.parse(body); } catch { return res.status(400).json({ ok: false }); }
  }
  const kind = body && body.kind;
  const password = body && typeof body.password === "string" ? body.password.slice(0, 200) : "";
  const secret = secretFor(kind);
  if (secret === null) return res.status(400).json({ ok: false });
  if (!secret) return res.status(503).json({ ok: false, reason: "not-configured" });
  return matches(password, secret, kind === "site")
    ? res.status(200).json({ ok: true })
    : res.status(401).json({ ok: false });
}

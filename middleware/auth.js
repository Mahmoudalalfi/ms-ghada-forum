const crypto = require("crypto");

const isProduction = process.env.NODE_ENV === "production";
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_SESSION_SECRET = process.env.ADMIN_SESSION_SECRET || crypto.randomBytes(32).toString("hex");

// ── Live password store (loaded from DB on init, falls back to .env) ──────────
let _currentPasswordHash = null; // bcrypt-style: we store sha256 hex of password
const ENV_PASSWORD = process.env.ADMIN_PASSWORD || "change-me";

// We use a simple SHA-256 hash (no bcrypt dependency needed — password is
// already high-entropy and the hash is stored server-side only, not user-facing)
function hashPassword(plain) {
  return crypto.createHash("sha256").update(plain).digest("hex");
}

async function loadPasswordFromDb() {
  try {
    const { pool } = require("../models/db");
    const result = await pool.query("SELECT password_hash FROM admin_credentials WHERE id = 1 LIMIT 1");
    if (result.rowCount) {
      _currentPasswordHash = result.rows[0].password_hash;
    } else {
      // Seed DB with current .env password
      _currentPasswordHash = hashPassword(ENV_PASSWORD);
      await pool.query(
        `INSERT INTO admin_credentials (id, password_hash) VALUES (1, $1)
         ON CONFLICT (id) DO NOTHING`,
        [_currentPasswordHash]
      );
    }
  } catch (err) {
    console.error("Could not load admin password from DB, falling back to .env:", err.message);
    _currentPasswordHash = hashPassword(ENV_PASSWORD);
  }
}

async function updatePasswordInDb(newPasswordHash) {
  const { pool } = require("../models/db");
  await pool.query(
    `INSERT INTO admin_credentials (id, password_hash, updated_at)
     VALUES (1, $1, NOW())
     ON CONFLICT (id) DO UPDATE SET password_hash = $1, updated_at = NOW()`,
    [newPasswordHash]
  );
  _currentPasswordHash = newPasswordHash;
}

function getCurrentPasswordHash() {
  return _currentPasswordHash || hashPassword(ENV_PASSWORD);
}

// ── Brute-force lockout ───────────────────────────────────────────────────────
const MAX_FAILURES  = 10;
const LOCKOUT_MS    = 15 * 60 * 1000;
const loginFailures = new Map();

function getClientIpForAuth(req) {
  const fwd = req.headers["x-forwarded-for"];
  if (typeof fwd === "string" && fwd) return fwd.split(",")[0].trim();
  return req.ip || "unknown";
}

function isLockedOut(ip) {
  const entry = loginFailures.get(ip);
  if (!entry) return false;
  if (entry.lockedUntil && Date.now() < entry.lockedUntil) return true;
  if (entry.lockedUntil && Date.now() >= entry.lockedUntil) loginFailures.delete(ip);
  return false;
}

function recordFailure(ip) {
  const entry = loginFailures.get(ip) || { count: 0, lockedUntil: null };
  entry.count += 1;
  if (entry.count >= MAX_FAILURES) {
    entry.lockedUntil = Date.now() + LOCKOUT_MS;
    console.warn(`Admin login locked for IP ${ip} until ${new Date(entry.lockedUntil).toISOString()}`);
  }
  loginFailures.set(ip, entry);
}

function recordSuccess(ip) {
  loginFailures.delete(ip);
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function timingSafeEqualStr(a, b) {
  const aBuf = Buffer.from(String(a || ""), "utf8");
  const bBuf = Buffer.from(String(b || ""), "utf8");
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

function getAdminSessionToken() {
  return crypto
    .createHmac("sha256", ADMIN_SESSION_SECRET)
    .update(`${ADMIN_USERNAME}:${getCurrentPasswordHash()}`)
    .digest("hex");
}

function parseCookieHeader(headerValue) {
  const output = {};
  if (!headerValue) return output;
  headerValue.split(";").forEach((part) => {
    const eqIndex = part.indexOf("=");
    if (eqIndex <= 0) return;
    output[part.slice(0, eqIndex).trim()] = decodeURIComponent(part.slice(eqIndex + 1).trim());
  });
  return output;
}

function setAdminSessionCookie(res) {
  const token = getAdminSessionToken();
  const cookieParts = [
    `admin_session=${encodeURIComponent(token)}`,
    "Path=/", "HttpOnly", "SameSite=Strict", "Max-Age=28800"
  ];
  if (isProduction) cookieParts.push("Secure");
  res.setHeader("Set-Cookie", cookieParts.join("; "));
}

function clearAdminSessionCookie(res) {
  const cookieParts = ["admin_session=", "Path=/", "HttpOnly", "SameSite=Strict", "Max-Age=0"];
  if (isProduction) cookieParts.push("Secure");
  res.setHeader("Set-Cookie", cookieParts.join("; "));
}

// ── Middleware ────────────────────────────────────────────────────────────────
function requireAdminAuth(req, res, next) {
  const ip = getClientIpForAuth(req);
  if (isLockedOut(ip)) {
    return res.status(429).send("Too many failed login attempts. Try again in 15 minutes.");
  }

  const cookies = parseCookieHeader(req.headers.cookie);
  if (cookies.admin_session && timingSafeEqualStr(cookies.admin_session, getAdminSessionToken())) {
    return next();
  }

  // No valid session — redirect to login page (or 401 for API calls)
  if (req.headers["x-requested-with"] === "XMLHttpRequest" || req.path.startsWith("/api/")) {
    return res.status(401).json({ error: "Authentication required." });
  }

  const loginPath = (process.env.ADMIN_DASHBOARD_PATH || "/teacher-portal-ghada").trim();
  return res.redirect(`/admin-login?next=${encodeURIComponent(req.path)}`);
}

function handleAdminLogin(req, res) {
  const ip = getClientIpForAuth(req);
  if (isLockedOut(ip)) {
    return res.status(429).send("Too many failed attempts. Try again in 15 minutes.");
  }

  const username = String(req.body.username || "");
  const password = String(req.body.password || "");
  const rawNext  = String(req.body.next || "/").replace(/[^a-zA-Z0-9/_-]/g, "");
  // Must start with exactly one "/" to prevent protocol-relative open redirects (//evil.com)
  const next     = rawNext.startsWith("/") && !rawNext.startsWith("//") ? rawNext : "/";

  const passwordHash = hashPassword(password);
  const usernameOk   = timingSafeEqualStr(username, ADMIN_USERNAME);
  const passwordOk   = timingSafeEqualStr(passwordHash, getCurrentPasswordHash());

  if (!usernameOk || !passwordOk) {
    recordFailure(ip);
    return res.redirect(`/admin-login?next=${encodeURIComponent(next)}&error=1`);
  }

  recordSuccess(ip);
  setAdminSessionCookie(res);
  return res.redirect(next);
}

function requireBrowserSafeRequest(req, res, next) {
  if (req.headers["transfer-encoding"] && req.headers["content-length"]) {
    return res.status(400).json({ error: "Invalid request framing." });
  }

  const methodNeedsProtection = ["POST", "PUT", "PATCH", "DELETE"].includes(req.method);
  if (!methodNeedsProtection) return next();

  const contentType = (req.headers["content-type"] || "").toLowerCase();
  if (req.method !== "DELETE" && !contentType.startsWith("application/json")) {
    return res.status(415).json({ error: "Only application/json is allowed." });
  }
  if (contentType.includes("xml") || contentType.includes("multipart/form-data")) {
    return res.status(415).json({ error: "Unsupported content type." });
  }
  if (req.headers["x-requested-with"] !== "XMLHttpRequest") {
    return res.status(403).json({ error: "Blocked by CSRF protection." });
  }

  const origin = req.headers.origin;
  if (origin) {
    try {
      const originHost = new URL(origin).host.toLowerCase();
      const requestHost = (req.headers.host || "").toLowerCase();
      if (originHost !== requestHost) {
        return res.status(403).json({ error: "Cross-origin requests are not allowed." });
      }
    } catch {
      return res.status(403).json({ error: "Invalid origin header." });
    }
  }

  next();
}

module.exports = {
  requireAdminAuth,
  handleAdminLogin,
  requireBrowserSafeRequest,
  clearAdminSessionCookie,
  setAdminSessionCookie,
  timingSafeEqualStr,
  hashPassword,
  getCurrentPasswordHash,
  loadPasswordFromDb,
  updatePasswordInDb,
};

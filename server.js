const express = require("express");
const path = require("path");
const crypto = require("crypto");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const isProduction = process.env.NODE_ENV === "production";
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "change-me";
const ADMIN_SESSION_SECRET = process.env.ADMIN_SESSION_SECRET || crypto.randomBytes(32).toString("hex");
const isVercel = Boolean(process.env.VERCEL);
const ADMIN_DASHBOARD_PATH = normalizeAdminPath(process.env.ADMIN_DASHBOARD_PATH || "/teacher-portal-ghada");
const allowedHosts = (process.env.ALLOWED_HOSTS || "")
  .split(",")
  .map((item) => item.trim().toLowerCase())
  .filter(Boolean);

function normalizeAdminPath(value) {
  const trimmed = String(value || "").trim();
  if (!trimmed) {
    return "/teacher-portal-ghada";
  }
  if (!trimmed.startsWith("/")) {
    return `/${trimmed}`;
  }
  return trimmed;
}

if (!DATABASE_URL) {
  console.error("Missing DATABASE_URL in environment.");
  console.error("Add it to your environment or .env file.");
  process.exit(1);
}

if ((!process.env.ADMIN_USERNAME || !process.env.ADMIN_PASSWORD) && !isProduction) {
  console.warn("Using default admin credentials for local development.");
  console.warn("Set ADMIN_USERNAME and ADMIN_PASSWORD in .env.");
}

if (isProduction && (!process.env.ADMIN_USERNAME || !process.env.ADMIN_PASSWORD)) {
  console.error("Missing ADMIN_USERNAME/ADMIN_PASSWORD in production environment.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.DB_SSL === "false" ? false : { rejectUnauthorized: false }
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS registrations (
      id SERIAL PRIMARY KEY,
      student_name TEXT NOT NULL,
      student_school TEXT NOT NULL,
      student_phone TEXT NOT NULL,
      parent_phone TEXT NOT NULL,
      course TEXT NOT NULL,
      discover_source TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}

const allowedCourses = new Set([
  "EDEXCEL ONLINE",
  "EDEXCEL PHYSICAL",
  "CAMB PHYSICAL",
  "CAMB ONLINE",
  "PRE IG CAMB",
  "PRE IG EDEXCEL",
  "AS"
]);

const allowedDiscover = new Set([
  "INSTGRAM",
  "PARENTS",
  "WHATS APP GROUP"
]);

function normalizeText(value) {
  if (typeof value !== "string") {
    return "";
  }
  return value.replace(/[\x00-\x1F\x7F]/g, "").trim();
}

function isValidPhone(value) {
  return /^\+?[0-9\s\-()]{6,20}$/.test(value);
}

function isSafeLength(value, min, max) {
  return value.length >= min && value.length <= max;
}

function validatePayload(payload) {
  const studentName = normalizeText(payload.studentName);
  const studentSchool = normalizeText(payload.studentSchool);
  const studentPhone = normalizeText(payload.studentPhone);
  const parentPhone = normalizeText(payload.parentPhone);
  const course = normalizeText(payload.course);
  const discover = normalizeText(payload.discover);

  if (!studentName || !studentSchool || !studentPhone || !parentPhone || !course || !discover) {
    return { ok: false, message: "Please fill in all required fields." };
  }

  if (!isSafeLength(studentName, 2, 120) || !isSafeLength(studentSchool, 2, 160)) {
    return { ok: false, message: "Student name/school length is invalid." };
  }

  if (!isValidPhone(studentPhone) || !isValidPhone(parentPhone)) {
    return { ok: false, message: "Invalid phone number format." };
  }

  if (!allowedCourses.has(course)) {
    return { ok: false, message: "Invalid course selection." };
  }

  if (!allowedDiscover.has(discover)) {
    return { ok: false, message: "Invalid source selection." };
  }

  return {
    ok: true,
    data: { studentName, studentSchool, studentPhone, parentPhone, course, discover }
  };
}

function timingSafeEqualStr(a, b) {
  const aBuf = Buffer.from(String(a || ""), "utf8");
  const bBuf = Buffer.from(String(b || ""), "utf8");
  if (aBuf.length !== bBuf.length) {
    return false;
  }
  return crypto.timingSafeEqual(aBuf, bBuf);
}

function getAdminSessionToken() {
  return crypto
    .createHmac("sha256", ADMIN_SESSION_SECRET)
    .update(`${ADMIN_USERNAME}:${ADMIN_PASSWORD}`)
    .digest("hex");
}

function parseCookieHeader(headerValue) {
  const output = {};
  if (!headerValue) {
    return output;
  }

  const parts = headerValue.split(";");
  parts.forEach((part) => {
    const eqIndex = part.indexOf("=");
    if (eqIndex <= 0) {
      return;
    }
    const key = part.slice(0, eqIndex).trim();
    const value = part.slice(eqIndex + 1).trim();
    output[key] = decodeURIComponent(value);
  });
  return output;
}

function setAdminSessionCookie(res) {
  const token = getAdminSessionToken();
  const cookieParts = [
    `admin_session=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Strict",
    "Max-Age=28800"
  ];
  if (isProduction) {
    cookieParts.push("Secure");
  }
  res.setHeader("Set-Cookie", cookieParts.join("; "));
}

function requireAdminAuth(req, res, next) {
  const cookies = parseCookieHeader(req.headers.cookie);
  const sessionToken = cookies.admin_session;
  if (sessionToken && timingSafeEqualStr(sessionToken, getAdminSessionToken())) {
    next();
    return;
  }

  const authHeader = req.headers.authorization || "";
  if (!authHeader.startsWith("Basic ")) {
    res.set("WWW-Authenticate", 'Basic realm="Teacher Dashboard"');
    res.status(401).send("Authentication required.");
    return;
  }

  let decoded = "";
  try {
    decoded = Buffer.from(authHeader.slice(6), "base64").toString("utf8");
  } catch (_error) {
    res.status(401).send("Invalid authentication token.");
    return;
  }

  const separatorIndex = decoded.indexOf(":");
  const username = separatorIndex >= 0 ? decoded.slice(0, separatorIndex) : "";
  const password = separatorIndex >= 0 ? decoded.slice(separatorIndex + 1) : "";

  const userOk = timingSafeEqualStr(username, ADMIN_USERNAME);
  const passOk = timingSafeEqualStr(password, ADMIN_PASSWORD);

  if (!userOk || !passOk) {
    res.set("WWW-Authenticate", 'Basic realm="Teacher Dashboard"');
    res.status(401).send("Invalid username or password.");
    return;
  }

  setAdminSessionCookie(res);
  next();
}

function requireBrowserSafeRequest(req, res, next) {
  if (req.headers["transfer-encoding"] && req.headers["content-length"]) {
    res.status(400).json({ error: "Invalid request framing." });
    return;
  }

  const methodNeedsProtection = req.method === "POST" || req.method === "PUT" || req.method === "PATCH" || req.method === "DELETE";
  if (!methodNeedsProtection) {
    next();
    return;
  }

  const contentType = (req.headers["content-type"] || "").toLowerCase();
  if (req.method !== "DELETE" && !contentType.startsWith("application/json")) {
    res.status(415).json({ error: "Only application/json is allowed." });
    return;
  }

  if (contentType.includes("xml") || contentType.includes("multipart/form-data")) {
    res.status(415).json({ error: "Unsupported content type." });
    return;
  }

  const requestedWith = req.headers["x-requested-with"];
  if (requestedWith !== "XMLHttpRequest") {
    res.status(403).json({ error: "Blocked by CSRF protection." });
    return;
  }

  const origin = req.headers.origin;
  if (origin) {
    try {
      const originHost = new URL(origin).host.toLowerCase();
      const requestHost = (req.headers.host || "").toLowerCase();
      if (originHost !== requestHost) {
        res.status(403).json({ error: "Cross-origin requests are not allowed." });
        return;
      }
    } catch (_error) {
      res.status(403).json({ error: "Invalid origin header." });
      return;
    }
  }

  next();
}

app.disable("x-powered-by");
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));
app.use((req, res, next) => {
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  next();
});
app.use((req, res, next) => {
  if (!allowedHosts.length) {
    next();
    return;
  }
  const host = (req.headers.host || "").split(":")[0].toLowerCase();
  const hostAllowed = allowedHosts.some((allowedHost) => {
    if (allowedHost.startsWith(".")) {
      return host.endsWith(allowedHost);
    }
    return host === allowedHost;
  });
  if (!hostAllowed) {
    res.status(400).send("Invalid Host header.");
    return;
  }
  next();
});

const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 80,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests. Please try again later." }
});

const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 250,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many admin requests. Please try again later." }
});

app.use(express.json({ limit: "12kb", strict: true, type: "application/json" }));
app.use((req, res, next) => {
  if (
    req.path === ADMIN_DASHBOARD_PATH ||
    req.path === "/teacher" ||
    req.path === "/admin.html" ||
    req.path.startsWith("/api/registrations")
  ) {
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
  }
  next();
});

app.get("/student", (_req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.get(ADMIN_DASHBOARD_PATH, requireAdminAuth, (_req, res) => {
  res.sendFile(path.join(__dirname, "admin.html"));
});

app.get("/teacher", (_req, res) => {
  res.status(404).send("Not found.");
});

app.get("/admin.html", (_req, res) => {
  res.status(404).send("Not found.");
});

app.post("/api/admin/logout", (_req, res) => {
  const cookieParts = [
    "admin_session=",
    "Path=/",
    "HttpOnly",
    "SameSite=Strict",
    "Max-Age=0"
  ];
  if (isProduction) {
    cookieParts.push("Secure");
  }
  res.setHeader("Set-Cookie", cookieParts.join("; "));
  res.json({ message: "Logged out." });
});

app.get("/", (_req, res) => {
  res.redirect("/student");
});

app.get("/index.html", (_req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.use(express.static(__dirname, { index: false }));

app.post("/api/registrations", registerLimiter, requireBrowserSafeRequest, async (req, res) => {
  try {
    const validation = validatePayload(req.body || {});

    if (!validation.ok) {
      res.status(400).json({ error: validation.message });
      return;
    }

    const { studentName, studentSchool, studentPhone, parentPhone, course, discover } = validation.data;

    const result = await pool.query(
      `INSERT INTO registrations
       (student_name, student_school, student_phone, parent_phone, course, discover_source)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id`,
      [studentName, studentSchool, studentPhone, parentPhone, course, discover]
    );

    res.status(201).json({
      message: "Registration saved successfully.",
      registrationId: result.rows[0].id
    });
  } catch (error) {
    console.error("Failed to save registration:", error);
    res.status(500).json({ error: "Server error while saving registration." });
  }
});

app.get("/api/registrations", adminLimiter, requireAdminAuth, async (req, res) => {
  try {
    const search = normalizeText(req.query.search);
    const course = normalizeText(req.query.course);

    let query = `
      SELECT id, student_name, student_school, student_phone, parent_phone, course, discover_source, created_at
      FROM registrations
      WHERE 1 = 1
    `;
    const params = [];

    if (search) {
      query += `
        AND (
          student_name ILIKE $${params.length + 1}
          OR student_school ILIKE $${params.length + 2}
          OR student_phone ILIKE $${params.length + 3}
          OR parent_phone ILIKE $${params.length + 4}
        )
      `;
      const keyword = `%${search}%`;
      params.push(keyword, keyword, keyword, keyword);
    }

    if (course) {
      query += ` AND course = $${params.length + 1} `;
      params.push(course);
    }

    query += " ORDER BY id DESC";

    const result = await pool.query(query, params);
    const rows = result.rows;
    res.json(rows);
  } catch (error) {
    console.error("Failed to fetch registrations:", error);
    res.status(500).json({ error: "Server error while fetching registrations." });
  }
});

app.delete("/api/registrations/:id", adminLimiter, requireAdminAuth, requireBrowserSafeRequest, async (req, res) => {
  try {
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id) || id <= 0) {
      res.status(400).json({ error: "Invalid registration id." });
      return;
    }

    const result = await pool.query("DELETE FROM registrations WHERE id = $1", [id]);
    if (!result.rowCount) {
      res.status(404).json({ error: "Registration not found." });
      return;
    }

    res.json({ message: "Registration deleted successfully." });
  } catch (error) {
    console.error("Failed to delete registration:", error);
    res.status(500).json({ error: "Server error while deleting registration." });
  }
});

const initPromise = initDb();

if (!isVercel) {
  initPromise
    .then(() => {
      app.listen(PORT, () => {
        console.log(`Server running at http://localhost:${PORT}`);
        console.log("Database connected: PostgreSQL");
        if (allowedHosts.length) {
          console.log(`Allowed hosts: ${allowedHosts.join(", ")}`);
        }
      console.log(`Teacher dashboard path: ${ADMIN_DASHBOARD_PATH}`);
      });
    })
    .catch((error) => {
      console.error("Failed to initialize database:", error);
      process.exit(1);
    });
} else {
  initPromise.catch((error) => {
    console.error("Failed to initialize database:", error);
  });
}

module.exports = app;

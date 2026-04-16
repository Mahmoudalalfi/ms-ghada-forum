require("dotenv").config();

const express = require("express");
const path = require("path");
const helmet = require("helmet");

const { initDb } = require("./models/db");
const { loadPasswordFromDb } = require("./middleware/auth");
const studentRouter = require("./routes/student");
const adminRouter = require("./routes/admin");

// ── Production credential guard ───────────────────────────────────────────────
if (process.env.NODE_ENV === "production") {
  const missing = ["ADMIN_USERNAME", "ADMIN_PASSWORD", "ADMIN_SESSION_SECRET", "COURSE_LINK_SECRET"]
    .filter((k) => !process.env[k]);
  if (missing.length) {
    console.error(`FATAL: Missing required env vars in production: ${missing.join(", ")}`);
    process.exit(1);
  }
  if (process.env.ADMIN_PASSWORD === "change-me" || process.env.ADMIN_USERNAME === "admin") {
    console.error("FATAL: Default admin credentials must not be used in production.");
    process.exit(1);
  }
}

const app = express();
const PORT = process.env.PORT || 3000;
const isVercel = Boolean(process.env.VERCEL);

const allowedHosts = (process.env.ALLOWED_HOSTS || "")
  .split(",").map((h) => h.trim().toLowerCase()).filter(Boolean);

// ── Security headers ──────────────────────────────────────────────────────────
app.disable("x-powered-by");
app.use(helmet({
  crossOriginEmbedderPolicy: false,
  contentSecurityPolicy: {
    directives: {
      defaultSrc:     ["'self'"],
      scriptSrc:      ["'self'", "'unsafe-inline'"],
      styleSrc:       ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://unpkg.com"],
      fontSrc:        ["'self'", "https://fonts.gstatic.com", "https://unpkg.com", "data:"],
      imgSrc:         ["'self'", "data:"],
      connectSrc:     ["'self'"],
      formAction:     ["'self'"],
      frameAncestors: ["'none'"],
      objectSrc:      ["'none'"],
      baseUri:        ["'self'"],
    }
  }
}));
app.use((_req, res, next) => {
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader("X-Frame-Options", "DENY");
  next();
});

// ── Host allowlist ────────────────────────────────────────────────────────────
app.use((req, res, next) => {
  if (!allowedHosts.length) return next();
  const host = (req.headers.host || "").split(":")[0].toLowerCase();
  const allowed = allowedHosts.some((h) => h.startsWith(".") ? host.endsWith(h) : host === h);
  if (!allowed) return res.status(400).send("Invalid Host header.");
  next();
});

// ── No-cache for sensitive routes ─────────────────────────────────────────────
app.use((req, res, next) => {
  const noCache = ["/teacher-portal-ghada", "/admin-login", "/teacher", "/admin.html", "/api/registrations"];
  if (noCache.some((p) => req.path.startsWith(p))) {
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
  }
  next();
});

// ── Body parsing ──────────────────────────────────────────────────────────────
app.use(express.json({ limit: "12kb", strict: true, type: "application/json" }));

// ── Static assets ─────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// ── Routes ────────────────────────────────────────────────────────────────────
app.use(studentRouter);
app.use(adminRouter);

// ── Global error handler (must be last, 4-arg signature) ─────────────────────
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error("Unhandled error:", err);
  const status = (typeof err.status === "number" && err.status >= 400 && err.status < 600)
    ? err.status : 500;
  res.status(status).json({ error: "An unexpected error occurred." });
});

// ── DB init + server start ────────────────────────────────────────────────────
const initPromise = initDb().then(loadPasswordFromDb);

if (!isVercel) {
  initPromise
    .then(() => {
      app.listen(PORT, () => {
        console.log(`Server running at http://localhost:${PORT}`);
        console.log("Database connected: PostgreSQL");
      });
    })
    .catch((err) => {
      console.error("Failed to initialize database:", err);
      process.exit(1);
    });
} else {
  initPromise.catch((err) => console.error("Failed to initialize database:", err));
}

module.exports = app;

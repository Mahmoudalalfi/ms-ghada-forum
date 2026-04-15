const path = require("path");
const {
  clearAdminSessionCookie,
  setAdminSessionCookie,
  hashPassword,
  getCurrentPasswordHash,
  updatePasswordInDb,
  timingSafeEqualStr,
} = require("../middleware/auth");
const { createCourseLinkToken, courseSlugToName, COURSE_LINK_TTL_DAYS } = require("../utils/courseLinks");

const BASE_PUBLIC_URL = (process.env.BASE_PUBLIC_URL || "").replace(/\/+$/, "");

const SAFE_HOST_RE = /^[a-zA-Z0-9.\-]+(:\d{1,5})?$/;

function getPublicBaseUrl(req) {
  if (BASE_PUBLIC_URL) return BASE_PUBLIC_URL;

  // Only trust x-forwarded-proto values we recognise
  const rawProto = String(req.headers["x-forwarded-proto"] || req.protocol || "https");
  const proto = rawProto === "http" ? "http" : "https";

  // Prefer the actual Host header; only fall back to x-forwarded-host if it
  // passes a strict allowlist pattern (hostname + optional port, no path/query)
  const rawHost = req.headers.host || "";
  const fwdHost = String(req.headers["x-forwarded-host"] || "").split(",")[0].trim();
  const host = SAFE_HOST_RE.test(rawHost) ? rawHost
             : SAFE_HOST_RE.test(fwdHost) ? fwdHost
             : "localhost";

  return `${proto}://${host}`;
}

function serveAdminPanel(_req, res) {
  res.sendFile(path.join(__dirname, "../views/admin.html"));
}

function logout(req, res) {
  clearAdminSessionCookie(res);
  res.json({ message: "Logged out." });
}

function getCourseLinks(req, res) {
  const base = getPublicBaseUrl(req);
  const links = Object.entries(courseSlugToName).map(([slug, course]) => ({
    course,
    slug,
    link: `${base}/join/${slug}?t=${createCourseLinkToken(slug)}`
  }));
  res.json({ expiresInDays: COURSE_LINK_TTL_DAYS, links });
}

async function changePassword(req, res) {
  try {
    const currentPassword = String(req.body.currentPassword || "");
    const newPassword     = String(req.body.newPassword     || "");
    const confirmPassword = String(req.body.confirmPassword || "");

    if (!currentPassword || !newPassword || !confirmPassword) {
      return res.status(400).json({ error: "All fields are required." });
    }

    // Verify current password
    const currentHash = hashPassword(currentPassword);
    if (!timingSafeEqualStr(currentHash, getCurrentPasswordHash())) {
      return res.status(401).json({ error: "Current password is incorrect." });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ error: "New passwords do not match." });
    }

    // Enforce minimum strength: at least 12 chars, 1 uppercase, 1 digit, 1 special
    const strongEnough = newPassword.length >= 12
      && /[A-Z]/.test(newPassword)
      && /[0-9]/.test(newPassword)
      && /[^A-Za-z0-9]/.test(newPassword);
    if (!strongEnough) {
      return res.status(400).json({
        error: "Password must be at least 12 characters and include an uppercase letter, a number, and a special character."
      });
    }

    const newHash = hashPassword(newPassword);
    await updatePasswordInDb(newHash);

    // Reissue session cookie with new password hash baked in
    setAdminSessionCookie(res);

    res.json({ message: "Password changed successfully." });
  } catch (err) {
    console.error("Failed to change password:", err);
    res.status(500).json({ error: "Server error while changing password." });
  }
}

module.exports = { serveAdminPanel, logout, getCourseLinks, changePassword };

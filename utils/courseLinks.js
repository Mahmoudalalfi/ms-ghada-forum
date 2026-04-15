const crypto = require("crypto");

const COURSE_LINK_SECRET = process.env.COURSE_LINK_SECRET || crypto.randomBytes(32).toString("hex");
const COURSE_LINK_TTL_DAYS = Number.parseInt(process.env.COURSE_LINK_TTL_DAYS || "120", 10);

const courseSlugToName = {
  "edexcel-online": "EDEXCEL ONLINE",
  "edexcel-physical": "EDEXCEL PHYSICAL",
  "camb-physical": "CAMB PHYSICAL",
  "camb-online": "CAMB ONLINE",
  "pre-ig-camb": "PRE IG CAMB",
  "pre-ig-edexcel": "PRE IG EDEXCEL",
  "as": "AS"
};

const courseNameToSlug = Object.fromEntries(
  Object.entries(courseSlugToName).map(([slug, name]) => [name, slug])
);

function b64urlEncode(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input), "utf8");
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function b64urlDecodeToString(input) {
  const normalized = String(input).replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  return Buffer.from(padded, "base64").toString("utf8");
}

function signTokenPayload(payloadSegment) {
  return b64urlEncode(
    crypto.createHmac("sha256", COURSE_LINK_SECRET).update(payloadSegment).digest()
  );
}

function createCourseLinkToken(courseSlug) {
  const expUnix = Math.floor(Date.now() / 1000) + COURSE_LINK_TTL_DAYS * 24 * 60 * 60;
  const payloadSegment = b64urlEncode(JSON.stringify({ courseSlug, exp: expUnix }));
  return `${payloadSegment}.${signTokenPayload(payloadSegment)}`;
}

function verifyCourseLinkToken(token, expectedSlug) {
  const segments = String(token || "").split(".");
  if (segments.length !== 2) return { ok: false, reason: "Token format is invalid." };

  const [payloadSegment, signatureSegment] = segments;
  const expectedSig = signTokenPayload(payloadSegment);

  const aBuf = Buffer.from(String(signatureSegment || ""), "utf8");
  const bBuf = Buffer.from(String(expectedSig || ""), "utf8");
  if (aBuf.length !== bBuf.length || !crypto.timingSafeEqual(aBuf, bBuf)) {
    return { ok: false, reason: "Token signature mismatch." };
  }

  let payload;
  try { payload = JSON.parse(b64urlDecodeToString(payloadSegment)); }
  catch { return { ok: false, reason: "Token payload is invalid." }; }

  if (!payload || typeof payload !== "object") return { ok: false, reason: "Token payload is invalid." };
  // Timing-safe slug comparison to prevent enumeration attacks
  const slugA = Buffer.from(String(payload.courseSlug || "").padEnd(64), "utf8").slice(0, 64);
  const slugB = Buffer.from(String(expectedSlug   || "").padEnd(64), "utf8").slice(0, 64);
  if (!crypto.timingSafeEqual(slugA, slugB)) return { ok: false, reason: "Token is not valid for this course." };
  if (!Number.isFinite(payload.exp) || payload.exp <= Math.floor(Date.now() / 1000)) {
    return { ok: false, reason: "Token expired." };
  }

  return { ok: true, payload };
}

module.exports = { courseSlugToName, courseNameToSlug, createCourseLinkToken, verifyCourseLinkToken, COURSE_LINK_TTL_DAYS };

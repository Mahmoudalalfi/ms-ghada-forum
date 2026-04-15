const { pool } = require("../models/db");
const { verifyCourseLinkToken, courseNameToSlug } = require("../utils/courseLinks");

const MIN_SECONDS_BETWEEN_SUBMITS = Number.parseInt(process.env.MIN_SECONDS_BETWEEN_SUBMITS || "8", 10);
const lastSubmitByIp = new Map();

const allowedCourses = new Set([
  "EDEXCEL ONLINE", "EDEXCEL PHYSICAL", "CAMB PHYSICAL",
  "CAMB ONLINE", "PRE IG CAMB", "PRE IG EDEXCEL", "AS"
]);

const allowedDiscover = new Set(["INSTGRAM", "PARENTS", "WHATS APP GROUP"]);

function normalizeText(value) {
  if (typeof value !== "string") return "";
  return value.replace(/[\x00-\x1F\x7F]/g, "").trim();
}

function isValidPhone(value) {
  return /^\+?[0-9\s\-()]{6,20}$/.test(value);
}

function isSafeLength(value, min, max) {
  return value.length >= min && value.length <= max;
}

function hasSuspiciousText(value) {
  if (/(https?:\/\/|www\.|\.com|<script|<\/|--|;)/i.test(value)) return true;
  if (/(.)\1{5,}/.test(value)) return true;
  return false;
}

function hasSuspiciousPhone(value) {
  const digits = value.replace(/\D/g, "");
  if (digits.length < 6) return true;
  if (/^(\d)\1+$/.test(digits)) return true;
  if (/0123456|1234567|2345678|3456789/.test(digits)) return true;
  return false;
}

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded) return forwarded.split(",")[0].trim();
  return req.ip || "unknown";
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
  return { ok: true, data: { studentName, studentSchool, studentPhone, parentPhone, course, discover } };
}

async function createRegistration(req, res) {
  try {
    const validation = validatePayload(req.body || {});
    if (!validation.ok) return res.status(400).json({ error: validation.message });

    const { studentName, studentSchool, studentPhone, parentPhone, course, discover } = validation.data;
    const submittedCourseSlug = normalizeText(req.body.courseSlug).toLowerCase();
    const submittedToken = normalizeText(req.body.linkToken);
    const expectedCourseSlug = courseNameToSlug[course];

    if (!submittedCourseSlug || !submittedToken || !expectedCourseSlug) {
      return res.status(403).json({ error: "A valid course invite link is required." });
    }
    if (submittedCourseSlug !== expectedCourseSlug) {
      return res.status(403).json({ error: "Invite link does not match selected course." });
    }

    const tokenCheck = verifyCourseLinkToken(submittedToken, expectedCourseSlug);
    if (!tokenCheck.ok) {
      return res.status(403).json({ error: "Course invite link is invalid or expired." });
    }

    if (hasSuspiciousText(studentName) || hasSuspiciousText(studentSchool)) {
      return res.status(400).json({ error: "Suspicious text content detected." });
    }
    if (hasSuspiciousPhone(studentPhone) || hasSuspiciousPhone(parentPhone)) {
      return res.status(400).json({ error: "Suspicious phone pattern detected." });
    }

    const ip = getClientIp(req);
    const now = Date.now();
    const last = lastSubmitByIp.get(ip) || 0;
    if (now - last < MIN_SECONDS_BETWEEN_SUBMITS * 1000) {
      return res.status(429).json({ error: "Please wait a few seconds before submitting again." });
    }
    lastSubmitByIp.set(ip, now);

    const existing = await pool.query(
      `SELECT id FROM registrations WHERE course = $1 AND (student_phone = $2 OR parent_phone = $3) LIMIT 1`,
      [course, studentPhone, parentPhone]
    );
    if (existing.rowCount) {
      return res.status(409).json({ error: "This phone is already registered for the selected course." });
    }

    const result = await pool.query(
      `INSERT INTO registrations (student_name, student_school, student_phone, parent_phone, course, discover_source)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
      [studentName, studentSchool, studentPhone, parentPhone, course, discover]
    );

    res.status(201).json({ message: "Registration saved successfully.", registrationId: result.rows[0].id });
  } catch (error) {
    if (error && error.code === "23505") {
      return res.status(409).json({ error: "This phone is already registered for this course." });
    }
    console.error("Failed to save registration:", error);
    res.status(500).json({ error: "Server error while saving registration." });
  }
}

async function getRegistrations(req, res) {
  try {
    const search = normalizeText(req.query.search);
    const course = normalizeText(req.query.course);
    const pageSize = Math.min(Math.max(Number.parseInt(req.query.limit || "50", 10), 10), 200);
    const page = Math.max(Number.parseInt(req.query.page || "1", 10), 1);
    const offset = (page - 1) * pageSize;

    let whereClause = "WHERE 1 = 1";
    const params = [];

    if (search) {
      whereClause += ` AND (student_name ILIKE $${params.length + 1} OR student_school ILIKE $${params.length + 2} OR student_phone ILIKE $${params.length + 3} OR parent_phone ILIKE $${params.length + 4})`;
      const kw = `%${search}%`;
      params.push(kw, kw, kw, kw);
    }
    if (course) {
      whereClause += ` AND course = $${params.length + 1}`;
      params.push(course);
    }

    const countResult = await pool.query(`SELECT COUNT(*) AS total FROM registrations ${whereClause}`, params);
    const total = Number.parseInt(countResult.rows[0].total, 10);

    const dataParams = [...params, pageSize, offset];
    const dataResult = await pool.query(
      `SELECT id, student_name, student_school, student_phone, parent_phone, course, discover_source, created_at
       FROM registrations ${whereClause} ORDER BY id DESC
       LIMIT $${dataParams.length - 1} OFFSET $${dataParams.length}`,
      dataParams
    );

    res.json({ total, page, pageSize, totalPages: Math.ceil(total / pageSize), rows: dataResult.rows });
  } catch (error) {
    console.error("Failed to fetch registrations:", error);
    res.status(500).json({ error: "Server error while fetching registrations." });
  }
}

async function deleteRegistration(req, res) {
  try {
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({ error: "Invalid registration id." });
    }
    const result = await pool.query("DELETE FROM registrations WHERE id = $1", [id]);
    if (!result.rowCount) return res.status(404).json({ error: "Registration not found." });
    res.json({ message: "Registration deleted successfully." });
  } catch (error) {
    console.error("Failed to delete registration:", error);
    res.status(500).json({ error: "Server error while deleting registration." });
  }
}

module.exports = { createRegistration, getRegistrations, deleteRegistration };

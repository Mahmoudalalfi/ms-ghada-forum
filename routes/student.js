const express = require("express");
const path = require("path");
const { registerLimiter } = require("../middleware/rateLimiter");
const { requireBrowserSafeRequest } = require("../middleware/auth");
const { createRegistration } = require("../controllers/registrationController");
const { courseSlugToName, verifyCourseLinkToken } = require("../utils/courseLinks");

const router = express.Router();

router.get("/", (_req, res) => res.redirect("/student"));

router.get("/student", (_req, res) => {
  res.sendFile(path.join(__dirname, "../views/index.html"));
});

router.get("/index.html", (_req, res) => {
  res.sendFile(path.join(__dirname, "../views/index.html"));
});

router.get("/join/:courseSlug", (req, res) => {
  const courseSlug = req.params.courseSlug.toLowerCase().trim();
  if (!courseSlugToName[courseSlug]) return res.status(404).send("Invalid course link.");

  const token = (req.query.t || "").trim();
  if (!token) return res.status(403).send("Missing invite token.");

  const tokenCheck = verifyCourseLinkToken(token, courseSlug);
  if (!tokenCheck.ok) return res.status(403).send("Invalid or expired invite link.");

  res.sendFile(path.join(__dirname, "../views/index.html"));
});

router.post("/api/registrations", registerLimiter, requireBrowserSafeRequest, createRegistration);

module.exports = router;

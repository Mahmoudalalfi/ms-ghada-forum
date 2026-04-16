const express = require("express");
const path = require("path");
const { adminLimiter } = require("../middleware/rateLimiter");
const { requireAdminAuth, handleAdminLogin, requireBrowserSafeRequest } = require("../middleware/auth");
const { serveAdminPanel, logout, getCourseLinks, changePassword } = require("../controllers/adminController");
const { getRegistrations, deleteRegistration } = require("../controllers/registrationController");

const router = express.Router();

const ADMIN_DASHBOARD_PATH = (() => {
  const val = (process.env.ADMIN_DASHBOARD_PATH || "/teacher-portal-ghada").trim();
  return val.startsWith("/") ? val : `/${val}`;
})();

// Login page
router.get("/admin-login", (req, res) => {
  res.sendFile(path.join(__dirname, "../views/admin-login.html"));
});
router.post("/admin-login", adminLimiter, express.urlencoded({ extended: false }), handleAdminLogin);

router.get(ADMIN_DASHBOARD_PATH, requireAdminAuth, serveAdminPanel);

// Block direct access to old paths
router.get("/teacher", (_req, res) => res.status(404).send("Not found."));
router.get("/admin.html", (_req, res) => res.status(404).send("Not found."));

router.post("/api/admin/logout", requireBrowserSafeRequest, logout);
router.post("/api/admin/change-password", adminLimiter, requireAdminAuth, requireBrowserSafeRequest, changePassword);
router.get("/api/admin/course-links", adminLimiter, requireAdminAuth, getCourseLinks);

router.get("/api/registrations", adminLimiter, requireAdminAuth, getRegistrations);
router.delete("/api/registrations/:id", adminLimiter, requireAdminAuth, requireBrowserSafeRequest, deleteRegistration);

module.exports = router;

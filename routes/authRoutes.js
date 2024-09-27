const express = require("express");
const router = express.Router();
const authController = require("../controllers/authController");
const authenticateToken = require("../middlewares/authMiddleware");
const authorizeRole = require("../middlewares/roleMiddleware");
const upload = require("../config/multerConfig");

router.post("/register", authController.register);
router.post("/login", authController.login);
router.post("/token", authController.refreshToken);
router.post("/forgot-password", authController.forgotPassword);
router.post("/reset-password", authController.resetPassword);
router.delete("/logout", authController.logout);
router.post(
  "/profilemanagement",
  upload.single("profileImage"),
  authenticateToken,
  authController.profileManagement
);
router.get(
  "/admin",
  authenticateToken,
  authorizeRole(["admin"]),
  authController.adminRoute
);
router.get(
  "/user",
  authenticateToken,
  authorizeRole(["user", "admin"]),
  authController.userRoute
);

module.exports = router;

const express = require("express");
const {
  register,
  login,
  logout,
  forgotPassword,
  verifyEmail,
  resendVerificationOTP,
  resetPassword,
} = require("../controller/auth.js");

const emailIsVerified = require("../middleware/emailIsVerifed.js");

const router = express.Router();

router.post("/register", register);
router.post("/login", emailIsVerified, login);
router.post("/logout", logout);
router.post("/forgotpassword", forgotPassword);
router.post("/resetpassword", resetPassword);
router.post("/verifyemail", verifyEmail);
router.post("/resendverificationotp", resendVerificationOTP);

module.exports = router;

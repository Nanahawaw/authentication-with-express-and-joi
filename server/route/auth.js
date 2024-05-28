const express = require("express");
const { register, login } = require("../controller/auth.js");
const { isAuthenticated } = require("../middleware/isAuthenticated.js");

const router = express.Router();

router.post("/register", register);
router.post("/login", isAuthenticated, login);

module.exports = router;

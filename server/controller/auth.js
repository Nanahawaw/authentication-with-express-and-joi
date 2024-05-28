const { User } = require("../models");
const userSchema = require("../validation.js");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const sendEmail = require("../utils/sendEmail");
const { generateOTP, verifyOTP } = require("../utils/generateOtp");
const dotenv = require("dotenv");

dotenv.config();

//register
const register = async (req, res) => {
  const { error } = userSchema.validate(req.body);

  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }
  const { username, password } = req.body;
  try {
    const existingUser = await User.findOne({ where: { username } });
    if (existingUser) {
      return res.status(409).json({ error: "Username already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const otp = generateOTP();

    const newUser = await User.create({
      username,
      password: hashedPassword,
      emailVerificationOTP: otp,
    });
    // Remove the password field from the response
    const { password: _, ...userWithoutPassword } = newUser.toJSON();

    const message = `Your OTP for email verification is ${otp}`;
    await sendEmail(username, "Email Verification", message);

    res.status(201).json({
      message:
        "User registered successfully. Please check your email for the verification code.",
      user: userWithoutPassword,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: err.message });
  }
};

//verify email
const verifyEmail = async (req, res) => {
  const { email, otp } = req.body;
  try {
    const user = await User.findOne({ where: { username: email } });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const isValid = verifyOTP(otp);

    if (!isValid) {
      return res.status(400).json({ error: "Invalid OTP" });
    }

    user.isVerified = true;
    user.emailVerificationOTP = null;
    await user.save();

    res.status(200).json({ message: "Email verified successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Email verification failed" });
  }
};

//resend verification otp
const resendVerificationOTP = async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ where: { username: email } });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const otp = generateOTP();
    user.emailVerificationOTP = otp;
    await user.save();

    const message = `Your OTP for email verification is ${otp}`;
    await sendEmail(user.username, "Email Verification", message);

    res.status(200).json({ message: "OTP resent successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not resend OTP" });
  }
};

//login
const login = async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ where: { username } });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const isPasswordMatch = await bcrypt.compare(password, user.password);

    if (!isPasswordMatch) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    //store in cookies
    res.cookie("accessToken", token, {
      httpOnly: true,
      maxAge: 3600000,
    });

    res.status(200).json({ token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
};

//logout

const logout = (req, res) => {
  res.clearCookie("accessToken");
  res.status(200).json({ message: "Logged out successfully" });
};
//forget password
const forgotPassword = async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ where: { email } });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const resetToken = jwt.sign({ email }, process.env.JWT_SECRET, {
      expiresIn: "10m",
    });
    const resetUrl = `${req.protocol}://${req.get(
      "host"
    )}/api/auth/resetpassword/${resetToken}`;

    const message = `You requested a password reset. Please go to this link to reset your password: ${resetUrl}`;

    await sendEmail(user.email, "Password Reset Request", message);

    res.status(200).json({ message: "Email sent" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Email could not be sent" });
  }
};

const resetPassword = async (req, res) => {
  const { resetToken } = req.params;
  const { password } = req.body;

  try {
    const decoded = jwt.verify(resetToken, process.env.JWT_SECRET);
    const user = await User.findOne({ where: { email: decoded.email } });

    if (!user) {
      return res.status(400).json({ error: "Invalid token" });
    }

    user.password = await bcrypt.hash(password, 10);
    await user.save();

    res.status(200).json({ message: "Password reset successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Password reset failed" });
  }
};

module.exports = {
  register,
  login,
  logout,
  forgotPassword,
  resetPassword,
  verifyEmail,
  resendVerificationOTP,
};

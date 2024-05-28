const { User } = require("../models");
const userSchema = require("../validation.js");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const sendEmail = require("../utils/sendEmail");
const speakeasy = require("speakeasy");
const { generateOTP } = require("../utils/generateOtp");
const { Op } = require("sequelize");
const dotenv = require("dotenv");

dotenv.config();

//register
const register = async (req, res) => {
  const { error } = userSchema.validate(req.body);

  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }
  const { username, password } = req.body;
  const { otp, secret } = generateOTP();
  try {
    const existingUser = await User.findOne({ where: { username } });
    if (existingUser) {
      return res.status(409).json({ error: "Username already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await User.create({
      username,
      password: hashedPassword,
      otpSecret: secret,
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
    //verify the otp
    const isValid = speakeasy.totp.verify({
      secret: user.otpSecret,
      encoding: "base32",
      token: otp,
      window: 10, // 10-second clock drift window
    });

    if (!isValid) {
      return res.status(400).json({ error: "Invalid OTP" });
    }

    user.isVerified = true;
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

    const { otp, secret } = generateOTP();

    // Update the user's otpSecret
    await user.update({ otpSecret: secret });
    await user.save();

    const message = `Your OTP for email verification is ${otp}`;
    await sendEmail(email, "Email Verification", message);

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

    const { otp, secret } = generateOTP();

    await user.update({ otpSecret: secret });

    const subject = "Reset Password";
    const message = `You are receiving this because you (or someone else) have requested the reset of your password.\n\n
             Please use the following code to reset your password:\n\n
             ${otp}\n\n
             If you did not request this, please ignore this email and your password will remain unchanged.`;

    await sendEmail(email, subject, message);

    res.status(200).json({ message: "Password reset email sent" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Email could not be sent" });
  }
};

const resetPassword = async (req, res) => {
  const { otp, password, email } = req.body;

  try {
    const user = await User.findOne({
      where: {
        username: email,
        otpSecret: {
          [Op.not]: null, // Use the Op.not operator instead of $ne
        },
      },
    });

    if (!user) {
      return res.status(400).json({ error: "Invalid request" });
    }

    const isTokenValid = speakeasy.totp.verify({
      secret: user.otpSecret,
      encoding: "base32",
      token: otp,
      window: 10, // 10-second clock drift window,
    });

    if (!isTokenValid) {
      return res.status(400).json({ error: "Invalid or expired token" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await user.update({ password: hashedPassword, otpSecret: null });

    res.status(200).json({ message: "Password reset successful" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
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

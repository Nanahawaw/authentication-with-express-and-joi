const speakeasy = require("speakeasy");

const generateOTP = () => {
  return speakeasy.totp({
    secret: process.env.OTP_SECRET,
    encoding: "base32",
    step: 600, // OTP valid for 5 minutes
  });
};

const verifyOTP = (token) => {
  return speakeasy.totp.verify({
    secret: process.env.OTP_SECRET,
    encoding: "base32",
    token,
    step: 600,
    window: 1,
  });
};

module.exports = { generateOTP, verifyOTP };

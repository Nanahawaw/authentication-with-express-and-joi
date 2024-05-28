const speakeasy = require("speakeasy");

const generateOTP = () => {
  const secret = speakeasy.generateSecret({
    length: 20,
    otpauth_opts: { encoding: "base32" },
  });
  const otp = speakeasy.totp({
    secret: secret.base32,
    encoding: "base32",
  });
  return { otp, secret: secret.base32 };
};

module.exports = { generateOTP };

const { User } = require("../models");

const emailIsVerified = async (req, res, next) => {
  const { username } = req.body;

  try {
    const user = await User.findOne({ where: { username } });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    if (!user.isVerified) {
      return res.status(403).json({ error: "Email not verified" });
    }

    next();
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Internal server error" });
  }
};

module.exports = emailIsVerified;

const { User } = require("../models");
const userSchema = require("../validation.js");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

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

    const newUser = await User.create({ username, password: hashedPassword });
    // Remove the password field from the response
    const { password: _, ...userWithoutPassword } = newUser.toJSON();

    res.status(201).json({
      message: "User registered successfully",
      user: userWithoutPassword,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: err.message });
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
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: error.message });
  }
};

module.exports = { register, login };

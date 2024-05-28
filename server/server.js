const express = require("express");
const Sequelize = require("sequelize");
const authRouter = require("./route/auth.js");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const dotenv = require("dotenv").config();
const db = require("./models");

const app = express();

app.use(express.json());
app.use(cors());
app.use(cookieParser());

app.use("/api/auth", authRouter);

// Get the MySQL connection URI from the environment variable
const databaseUri = process.env.DATABASE_URL;

// Create the Sequelize instance using the connection URI
const sequelize = new Sequelize(databaseUri, {
  dialect: "mysql",
  // other options...
});

db.sequelize = sequelize;

app.listen(3000, () => {
  console.log("Server is running on port 3000");
});

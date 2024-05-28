import { sequelize, DataTypes } from "sequelize";

const User = sequelize.define("User", {
  username: {
    type: DataTypes.STRING,
  },
  password: {
    type: DataTypes.STRING,
  },
});
export default User;

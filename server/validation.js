import Joi from "joi";

const userSchema = Joi.object({
  username: Joi.string().email().required().messages({
    "string.email": "Username must be a valid email address",
    "string.empty": "Username is required",
  }),
  password: Joi.string()
    .pattern(
      new RegExp(
        "^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#@!$%^&*?-]).{8,} $"
      )
    )
    .required()
    .messages({
      "string.pattern.base":
        "Password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, one number, and one special character",
    }),
});
export default userSchema;

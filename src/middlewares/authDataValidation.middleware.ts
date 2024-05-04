import { body, validationResult } from "express-validator";
import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";

const signupValidation = asyncHandler(async (req, res, next) => {
  const rules = [
    body("fullName").trim().notEmpty().withMessage("Full Name is required"),
    body("email").trim().isEmail().withMessage("Email is invalid"),
    body("password").trim().notEmpty().withMessage("Password is required"),
    body("password")
      .trim()
      .isLength({ min: 8 })
      .withMessage("Password must be at least 8 characters long"),
    body("password")
      .trim()
      .matches(/^(?=.*[!@#$%^&*()_+{}\[\]:;<>,.?/~\-])(?=.*\d)(?=.*[a-zA-Z]).{8,}$/)
      .withMessage("Password must contain at least one alphabet, one digit, and one special character"),
  ];

  await Promise.all(rules.map((rule) => rule.run(req)));
  let errors = validationResult(req);

  if (!errors.isEmpty()) {
    console.log(errors.array().map((err) => err.msg));
    throw new ApiError(400, "Register validation failed");
  } else {
    next();
  }
});

const emailValidation = asyncHandler(async (req, res, next) => {
  const rules = [body("email").trim().isEmail().withMessage("Email is invalid")];
  await Promise.all(rules.map((rule) => rule.run(req)));
  let errors = validationResult(req);
  if (!errors.isEmpty()) {
    console.log(errors.array().map((err) => err.msg));
    throw new ApiError(400, "email validation failed");
  } else {
    next();
  }
});

const passwordValidation = asyncHandler(async (req, res, next) => {
  const rules = [
    body("password").trim().notEmpty().withMessage("Password is required"),
    body("password")
      .trim()
      .isLength({ min: 8 })
      .withMessage("Password must be at least 8 characters long"),
    body("password")
      .trim()
      .matches(/^(?=.*[!@#$%^&*()_+{}\[\]:;<>,.?/~\-])(?=.*\d)(?=.*[a-zA-Z]).{8,}$/)
      .withMessage("Password must contain at least one alphabet, one digit, and one special character"),
  ];

  await Promise.all(rules.map((rule) => rule.run(req)));
  let errors = validationResult(req);

  if (!errors.isEmpty()) {
    console.log(errors.array().map((err) => err.msg));
    throw new ApiError(400, "Password validation failed");
  } else {
    next();
  }
});

const changePasswordValidation = asyncHandler(async (req, res, next) => {
  const rules = [
    body("email").trim().isEmail().withMessage("Email is invalid"),
    body("newPassword").trim().notEmpty().withMessage("Password is required"),
    body("newPassword")
        .trim()
        .isLength({ min: 8 })
        .withMessage("Password must be at least 8 characters long"),
    body("newPassword")
        .trim()
        .matches(/^(?=.*[!@#$%^&*()_+{}\[\]:;<>,.?/~\-])(?=.*\d)(?=.*[a-zA-Z]).{8,}$/)
        .withMessage("Password must contain at least one alphabet, one digit, and one special character"),
];

  await Promise.all(rules.map((rule) => rule.run(req)));
  let errors = validationResult(req);

  if (!errors.isEmpty()) {
    console.log(errors.array().map((err) => err.msg));
    throw new ApiError(400, "Bad request : change Password validation failed");
  } else {
    next();
  }
});



export {
  signupValidation,
  emailValidation,
  changePasswordValidation,
  passwordValidation
}
const express = require("express");
const passport = require("passport");
const { body, validationResult } = require("express-validator");
const {
  register,
  login,
  logout,
  refreshToken,
  updateProfile
} = require("../controllers/authController");
const verifyToken = require("../middleware/verifyToken");
const requireRole = require("../middleware/requireRole");

const router = express.Router();

router.get("/google", passport.authenticate("google", {
  scope: ["profile", "email"],
  session: false
}));

router.get("/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    const accessToken = jwt.sign(
      { userId: req.user._id, role: req.user.role },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );
    
    res.cookie("access_token", accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict"
    });
    
    res.redirect("/dashboard");
  }
);

router.post("/register",
  [
    body("username")
      .trim()
      .isLength({ min: 3, max: 30 })
      .withMessage("Username must be 3-30 characters")
      .matches(/^[a-zA-Z0-9_]+$/)
      .withMessage("Username can only contain letters, numbers and underscores"),
    body("email")
      .isEmail()
      .withMessage("Please enter a valid email")
      .normalizeEmail(),
    body("password")
      .isLength({ min: 8 })
      .withMessage("Password must be at least 8 characters")
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/)
      .withMessage("Password must contain at least one uppercase, one lowercase, one number and one special character")
  ],
  register
);

router.post("/login",
  [
    body("username").trim().notEmpty().withMessage("Username or email is required"),
    body("password").notEmpty().withMessage("Password is required")
  ],
  login
);

router.post("/logout", logout);

router.post("/refresh-token", refreshToken);

router.put("/profile",
  verifyToken,
  [
    body("username")
      .optional()
      .trim()
      .isLength({ min: 3, max: 30 })
      .withMessage("Username must be 3-30 characters")
      .matches(/^[a-zA-Z0-9_]+$/)
      .withMessage("Username can only contain letters, numbers and underscores"),
    body("email")
      .optional()
      .isEmail()
      .withMessage("Please enter a valid email")
      .normalizeEmail(),
    body("bio")
      .optional()
      .trim()
      .isLength({ max: 500 })
      .withMessage("Bio cannot exceed 500 characters")
      .escape()
  ],
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    updateProfile(req, res).catch(next);
  }
);

router.get("/dashboard", verifyToken, (req, res) => {
  res.json({
    success: true,
    message: `Welcome ${req.user.username}`,
    user: req.user
  });
});

router.get("/admin-dashboard", verifyToken, requireRole("admin"), (req, res) => {
  res.json({
    success: true,
    message: `Welcome Admin ${req.user.username}`,
    user: req.user
  });
});

module.exports = router;
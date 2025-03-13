const express = require("express");
const passport = require("passport");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const { register, login, logout } = require("../controllers/authController");
const { verifyToken } = require("../middleware/verifyToken");
const requireRole = require("../middleware/requireRole");
const cookieParser = require("cookie-parser");

const router = express.Router();

router.use(cookieParser());

router.post("/register", register);
router.post("/login", login);
router.post("/logout", logout);

router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

router.get('/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (req, res) => {
    const payload = {
        userId: req.user._id,
        role: req.user.role,
    };

    const accessToken = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '15m' });
    const refreshToken = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.cookie("access_token", accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: "Strict",
    });

    res.cookie("refresh_token", refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: "Strict",
    });

    res.redirect('/dashboard');
});

router.post("/login", async (req, res) => {
    const { username, password } = req.body;

    try {
        const user = await User.findOne({ username });

        if (!user || !(await user.verifyPassword(password))) {
            return res.status(400).json({ message: "Invalid credentials" });
        }

        const payload = {
            userId: user._id,
            role: user.role,
        };

        const accessToken = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '15m' });
        const refreshToken = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '7d' });

        res.cookie("access_token", accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: "Strict",
        });

        res.cookie("refresh_token", refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: "Strict",
        });

        res.json({ message: "Logged in successfully" });
    } catch (error) {
        res.status(500).json({ message: "Server error during login" });
    }
});

router.post("/refresh-token", async (req, res) => {
    const refreshToken = req.cookies.refresh_token || req.body.refreshToken;

    if (!refreshToken) {
        return res.status(401).json({ message: "Refresh token not provided" });
    }

    jwt.verify(refreshToken, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({ message: "Invalid refresh token" });
        }

        const newAccessToken = jwt.sign(
            { userId: decoded.userId, role: decoded.role },
            process.env.JWT_SECRET,
            { expiresIn: '15m' }
        );

        res.cookie("access_token", newAccessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: "Strict",
        });

        res.json({ message: "Token refreshed" });
    });
});

router.post("/logout", (req, res) => {
    res.clearCookie("access_token");
    res.clearCookie("refresh_token");
    res.json({ message: "Logged out successfully" });
});

router.get("/dashboard", verifyToken, requireRole("user"), (req, res) => {
    res.json({
        message: "Welcome to your Dashboard!",
        user: req.user,
    });
});

router.get("/admin-dashboard", verifyToken, requireRole("admin"), (req, res) => {
    res.json({
        message: "Welcome to the Admin Dashboard!",
        user: req.user,
    });
});

module.exports = router;

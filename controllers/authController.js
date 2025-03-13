// controllers/authController.js
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const User = require("../models/User"); // Import your user model

// Generate JWT token
const generateToken = (user) => {
    return jwt.sign(
        { id: user._id, role: user.role },  // Include user ID and role in the token
        process.env.JWT_SECRET,  // Use JWT secret from environment
        { expiresIn: '15m' }  // Token expiration set to 15 minutes
    );
};

// Register User
const register = async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10); // Hash the password before saving

    try {
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();
        res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
        res.status(400).json({ message: "Error registering user" });
    }
};

// Login User
const login = async (req, res) => {
    const { username, password } = req.body;

    try {
        const user = await User.findOne({ username });
        if (!user) return res.status(404).json({ message: "User not found" });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

        // Generate JWT token
        const accessToken = generateToken(user);

        // Store token in HttpOnly cookies
        res.cookie("access_token", accessToken, {
            httpOnly: true,  // Prevents JS from accessing the cookie
            secure: process.env.NODE_ENV === "production",  // Only over HTTPS in production
            sameSite: "Strict",  // Helps with CSRF protection
        });

        res.json({ message: "Login successful" });
    } catch (error) {
        res.status(500).json({ message: "Server error" });
    }
};

// Logout User
const logout = (req, res) => {
    res.clearCookie("access_token");  // Clear the access token cookie
    res.json({ message: "Logged out successfully" });
};

module.exports = { register, login, logout };

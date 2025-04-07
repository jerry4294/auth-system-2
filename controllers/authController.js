const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const User = require("../models/User");
const { validationResult } = require("express-validator");
const escapeHtml = require("escape-html");

const generateToken = (user, expiresIn = '15m') => {
  return jwt.sign(
    { 
      userId: user._id, 
      role: user.role,
      username: user.username,
      email: user.email
    },
    process.env.JWT_SECRET,
    { expiresIn }
  );
};

const register = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ 
      success: false,
      errors: errors.array() 
    });
  }

  try {
    const { username, email, password } = req.body;

    const existingUser = await User.findOne({ 
      $or: [
        { username: { $regex: new RegExp(`^${username}$`, 'i') } },
        { email: { $regex: new RegExp(`^${email}$`, 'i') } }
      ]
    });

    if (existingUser) {
      const conflict = existingUser.username.toLowerCase() === username.toLowerCase()
        ? 'username' 
        : 'email';
      return res.status(409).json({ 
        success: false,
        message: `${conflict} already exists`
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const newUser = await User.create({
      username: escapeHtml(username),
      email: email.toLowerCase(),
      password: hashedPassword,
      role: 'user',
      bio: ''
    });

    const accessToken = generateToken(newUser, '15m');
    const refreshToken = generateToken(newUser, '7d');

    res.cookie("access_token", accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 15 * 60 * 1000
    });

    res.cookie("refresh_token", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.status(201).json({
      success: true,
      message: "User registered successfully",
      user: {
        id: newUser._id,
        username: newUser.username,
        email: newUser.email,
        role: newUser.role
      }
    });

  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({
      success: false,
      message: "Registration failed"
    });
  }
};

const login = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      errors: errors.array()
    });
  }

  try {
    const { username, password } = req.body;

    const user = await User.findOne({
      $or: [
        { username: { $regex: new RegExp(`^${username}$`, 'i') } },
        { email: { $regex: new RegExp(`^${username}$`, 'i') } }
      ]
    }).select('+password');

    if (!user) {
      return res.status(401).json({ 
        success: false,
        message: "Invalid credentials" 
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ 
        success: false,
        message: "Invalid credentials" 
      });
    }

    const accessToken = generateToken(user, '15m');
    const refreshToken = generateToken(user, '7d');

    res.cookie("access_token", accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 15 * 60 * 1000
    });

    res.cookie("refresh_token", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({
      success: true,
      message: "Login successful",
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        bio: user.bio
      }
    });

  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      success: false,
      message: "Login failed"
    });
  }
};

const updateProfile = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ 
      success: false,
      errors: errors.array() 
    });
  }

  try {
    const { username, email, bio } = req.body;
    const updates = {};
    const changes = {};

    if (username && username !== req.user.username) {
      updates.username = escapeHtml(username);
      changes.username = {
        old: req.user.username,
        new: updates.username
      };
    }

    if (email && email !== req.user.email) {
      updates.email = email.toLowerCase();
      changes.email = {
        old: req.user.email,
        new: updates.email
      };
    }

    if (bio !== undefined) {
      updates.bio = escapeHtml(bio);
      changes.bio = {
        old: req.user.bio || '',
        new: updates.bio
      };
    }

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({
        success: false,
        message: "No changes detected"
      });
    }

    const updatedUser = await User.findByIdAndUpdate(
      req.user.userId,
      updates,
      { new: true }
    ).select('-password');

    if (!updatedUser) {
      return res.status(404).json({
        success: false,
        message: "User not found"
      });
    }

    const newAccessToken = generateToken(updatedUser, '15m');

    res.cookie("access_token", newAccessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 15 * 60 * 1000
    });

    res.json({
      success: true,
      message: "Profile updated successfully",
      user: updatedUser,
      changes: Object.keys(changes).length > 0 ? changes : undefined
    });

  } catch (error) {
    console.error("Profile update error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to update profile"
    });
  }
};

const refreshToken = async (req, res) => {
  const token = req.cookies.refresh_token || req.body.refreshToken;

  if (!token) {
    return res.status(401).json({ 
      success: false,
      message: "Refresh token not provided" 
    });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);

    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: "User not found" 
      });
    }

    const newAccessToken = generateToken(user, '15m');

    res.cookie("access_token", newAccessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 15 * 60 * 1000
    });

    res.json({ 
      success: true,
      message: "Access token refreshed" 
    });

  } catch (error) {
    console.error("Refresh token error:", error);
    res.status(403).json({ 
      success: false,
      message: "Invalid refresh token" 
    });
  }
};

const logout = (req, res) => {
  res.clearCookie("access_token");
  res.clearCookie("refresh_token");
  res.json({ 
    success: true,
    message: "Logged out successfully" 
  });
};

module.exports = { 
  register, 
  login, 
  logout, 
  refreshToken,
  updateProfile 
};
const express = require("express");
const mongoose = require("mongoose");
const passport = require("passport");
const session = require("express-session");
const dotenv = require("dotenv");
const cookieParser = require('cookie-parser');
const { GOOGLE_CALLBACK_URL } = process.env;



// Load environment variables
dotenv.config();

// Initialize the app
const app = express();
app.use(cookieParser());

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true
}));

// Passport initialization
app.use(passport.initialize());
app.use(passport.session());

// MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log("✅ MongoDB Atlas Connected..."))
.catch((err) => console.log("MongoDB Connection Error:", err));

//routes
const authRoutes = require("./routes/authRoutes");
app.use("/api/auth", authRoutes); 

// Define home route
app.get("/", (req, res) => {
  res.send("Welcome to the Auth System 2!");
});

//server
const PORT = process.env.PORT || 5001;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

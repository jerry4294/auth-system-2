const jwt = require("jsonwebtoken");
const { JWT_SECRET } = process.env;

// Verify Token Middleware
function verifyToken(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1]; // Get token from Authorization header
  if (!token) {
    return res.status(401).json({ message: "No token provided" });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "Invalid token" });
    }
    req.user = decoded; // Set user data to req.user
    next(); // Proceed to the next middleware or route handler
  });
}

module.exports = { verifyToken };

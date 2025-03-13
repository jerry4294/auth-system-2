// middleware/verifyToken.js
const jwt = require("jsonwebtoken");

const verifyToken = (req, res, next) => {
    // Get the token from cookies
    const token = req.cookies.access_token;

    if (!token) {
        return res.status(401).json({ message: "No access token provided" });
    }

    // Verify the token using the secret key
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({ message: "Invalid or expired token" });
        }

        // If token is valid, attach the user data to the request
        req.user = decoded;
        next();
    });
};

module.exports = { verifyToken };

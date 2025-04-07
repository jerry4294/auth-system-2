const jwt = require("jsonwebtoken");

const verifyToken = (req, res, next) => {
    const token = req.cookies.access_token || 
                 req.headers['authorization']?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ 
            success: false,
            message: "Authentication required" 
        });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({ 
                success: false,
                message: "Invalid or expired token" 
            });
        }
        req.user = decoded;
        next();
    });
};

module.exports = verifyToken;
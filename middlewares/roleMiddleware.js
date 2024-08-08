const authenticateToken = require('./authMiddleware');

const authorizeRole = (roles) => {
    return (req, res, next) => {
        authenticateToken(req, res, () => {
            if (roles.includes(req.user.role)) {
                next();
            } else {
                res.status(403).json({ message: 'Forbidden: You do not have the required role' });
            }
        });
    };
};

module.exports = authorizeRole;

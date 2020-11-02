const jwt = require('jsonwebtoken');
const config = require('config'); // to get access to the secret in default.json

module.exports = function (req, res, next) {
    // Get the token from the header
    const token = req.header('x-auth-token'); // key to the token inside the header

    //Check if not token
    if(!token) {
        return res.status(401).json({msg: 'No token, authorization denied'})
    }

    try {
        const decoded = jwt.verify(token, config.get('jwtSecret'));

        req.user = decoded.user;
        next();

    } catch (err) {
        res.status(401).json({msg: 'Token is not valid'})
    }
}
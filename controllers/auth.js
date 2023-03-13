const User = require('../models/user');
const jwt = require('jsonwebtoken');
const expressJwt = require('express-jwt'); // for authorization check
const {errorHandler} = require('../helpers/dbErrorHandler');
const { rawListeners } = require('../models/user');


exports.signup = (req, res) => {
    console.log("req.body", req.body)
    const user = new User(req.body)
    user.save((err, user) => {
        if(err){
            return res.status(400).json({
                err: errorHandler(err)
            });
        }
        user.salt = undefined;
        user.hashed_password = undefined;
        res.json({
            user 
        });
    })
};

exports.signin = (req, res) => {
    const {email, password} = req.body
    User.findOne({email}, (err, user) => {if (err || !user) {
        return res.status(400).json({
            err: 'User with that email does not exist. Please signup'
            });
        }

        if(!user.authenticate(password)){
            return res.status(401).json({
                error: "Email and password dont match"
            });
        }
        const token = jwt.sign({_id: user._id}, process.env.SECRET);
        res.cookie('t', token, {expire: new Date() + 9999} )
        const {_id, name, email, role} = user
        return res.json({token, user: {_id, email, name, role} });


    });
};

exports.signout = (req, res) => {

    res.clearCookie('t')
    res.json({message: "Signout Successful"});

};

exports.requireSignin = expressJwt({
    secret: process.env.SECRET, 
    algorithms: ["HS256"],
    userProperty: "auth"
});



/*
exports.requireSignin = (req, res, next) => {
    const token = req.token
if (!token) {
    res.status(401).send('Unauthorized: No token provided');
} else {
    jwt.verify(token, process.env.SECRET, function(err, decoded) {
    if (err) {
        res.status(401).send('Unauthorized: Invalid token');
    } else {
        req.email = decoded.email;
        next();
    }
    });
} 
} */


exports.isAuth = (req, res, next) => {
    let user = req.profile && req.auth && req.profile._id == req.auth._id
        if(!user){
            return res.status(403).json({
                error: "Access denied"
            });
        }

        next();
}

exports.isAdmin = (req, res, next) => {
    if(req.profile.role === 0){
        return res.status(403).json ({
            error: 'Admin resource! Access denied'
        });

    }

    next();

};
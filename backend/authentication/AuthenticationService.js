const UserModel = require('../user/UserModel');
var User = require('../user/UserModel');
var express = require('express');
var router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const tokenSecret = "secret";
const AuthenticationService = require('../authentication/AuthenticationService');
const e = require('express');
const { database } = require('../config/db');
const mongoose = require('mongoose');
const asyncHandler = require('express-async-handler')
require("dotenv").config();
const generateToken = require("../utils/generateToken.js");

const SECRET_KEY = process.env.JWT_KEY;

/*
exports.protect = asyncHandler(async (req, res, next) => {
  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer", "Basic")
  ) {
    try {
      token = req.headers.authorization.split(" ")[1];

      //decodes token id
      const decoded = jwt.verify(token, SECRET_KEY);

      req.user = await User.findById(decoded.userID).select("-password");

      next();
    } catch (error) {
      res.status(401);
      throw new Error("Not authorized, token failed");
    }
  }

  if (!token) {
    res.status(401);
    throw new Error("Not authorized, no token");
  }
});*/


//@description     Auth the user
//@route           POST /api/users/login
//@access          Public
exports.auth = asyncHandler(async (req, res) => {
  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer", "Basic")
  ) {
    try {
      token = req.headers.authorization.split(" ")[1];

      //decodes token id
      const decoded = jwt.verify(token, SECRET_KEY);

      req.user = await User.findById(decoded.id).select("-password");

      next();
    } catch (error) {
      res.status(401);
      throw new Error("Not authorized, token failed");
    }
  }

  const { userID, password } = req.body;

  const user = await User.findOne({ userID });

  if (user && (await user.matchPassword(password))) {
    res.json({
      _id: user._id,
      userName: user.userName,
      isAdministrator: user.isAdministrator,
      token: generateToken(user._id),
    });
  } else {
    res.status(401);
    throw new Error("Invalid userID or Password");
  }

});

//@description     Register new user
//@route           POST /api/users/
//@access          Public
exports.register = asyncHandler(async (req, res) => {
  
  const { userID,userName, password, isAdministrator } = req.body;

  const userExists = await User.findOne({ userID });

  if (userExists) {
    res.status(404);
    throw new Error("User already exists");
  }

  const user = await User.create({
    userID,
    userName,
    password,
    isAdministrator,
  });

  if (user) {
    res.status(201).json({
      _id: user._id,
      userID: user.userID,
      userName: user.userName,
      isAdministrator: user.isAdministrator,
      token: generateToken(user._id),
    });
  } else {
    res.status(400);
    throw new Error("User not found");
  }
});

// @desc    GET user profile
// @route   GET /api/users/profile
// @access  Private
exports.update = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (user) {
    user.userID = req.body.userID || user.userID;
    user.userName = req.body.userName || user.userName;
    user.isAdministrator = req.body.isAdministrator || user.isAdministrator;
    if (req.body.password) {
      user.password = req.body.password;
    }

    const updatedUser = await user.save();

    res.json({
      _id: updatedUser._id,
      userID: updatedUser.userID,
      userName: updatedUser.userName,
      isAdministrator: updatedUser.isAdministrator,
      token: generateToken(updatedUser._id),
    });
  } else {
    res.status(404);
    throw new Error("User Not Found");
  }
});

exports.getUserById = asyncHandler(async (req, res) => {
  const user = await User.findById(req.params.id);

  if (user) {
    res.json(user);
  } else {
    res.status(404).json({ message: "User not found" });
  }

  res.json(user);
});

exports.getUsers = asyncHandler(async (req, res) => {
  const user = await User.find({ user: req.user._id });
  res.json(user);
});

//@description     Delete single Note
//@route           GET /api/notes/:id
//@access          Private
exports.delete = asyncHandler(async (req, res) => {
  const user = await User.findById(req.params.id);

  if (user.user.toString() !== req.user._id.toString()) {
    res.status(401);
    throw new Error("You can't perform this action");
  }

  if (user) {
    await userremove();
    res.json({ message: "User Removed" });
  } else {
    res.status(404);
    throw new Error("Forum not Found");
  }
});


/*
const getToken = (user) => {
  const payload = {user: user};
  const option = {expiresIn: '1000000h'};

  const token = jwt.sign(payload, SECRET_KEY, option);
  return token;
}

exports.verify = function(req, res) {
    var token = req.headers.authorization.split(" ")[1];
    if (!token) return res.status(401).send({ auth: false, message: 'No token provided.' });
    
    jwt.verify(token, SECRET_KEY, function(err, decoded) {
      if (err) return res.status(500).send({ auth: false, message: 'Failed to authenticate token.' });
      
      res.status(200).send(decoded);
    });
  };
/*
exports.create = function(req, res) {
  
    var hashedPassword = bcrypt.hashSync(req.body.password, 8);
    
    UserModel.create({
      userID : req.body.userID,
      userName : req.body.userName,
      password : hashedPassword,
      isAdministrator: req.body.isAdministrator,
    },
    function (err, user) {
      if (err) return res.status(500).send("There was a problem registering the user.")
      // create a token
      var token = jwt.sign({ id: user._id }, SECRET_KEY, {
        expiresIn: 86400 // expires in 24 hours
      });
      res.status(200).send({ auth: true, token: token });
    }); 
  };

exports.login = async (req, res) => {
    try {
      const user = await User.findOne({ userID: req.body.userID });
      !user && res.status(401).json("Wrong password or username!");
  
      const bytes = CryptoJS.AES.decrypt(user.password, process.env.SECRET_KEY);
      const originalPassword = bytes.toString(CryptoJS.enc.Utf8);
  
      originalPassword !== req.body.password &&
        res.status(401).json("Wrong password or username!");
  
      const accessToken = jwt.sign(
        { id: user._id, isAdministrator: user.isAdministrator },
        process.env.SECRET_KEY,
        { expiresIn: "5d" }
      );
  
      const { password, ...info } = user._doc;
  
      res.status(200).json({ ...info, accessToken });
    } catch (err) {
      res.status(500).json(err);
    }
  };

exports.create = async (req, res) => {

    const {
        userID,
        userName,
        password,
        isAdministrator,
    } = req.body;
    try {
        let user = await User.findOne({
            userID
        });
        if (user) {
            return res.status(400).json({
                msg: "User Already Exists"
            });
        }

        user = new User({
            userID,
            userName,
            password,
            isAdministrator

        });

        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);

        await user.save();

        const payload = {
            user: {
                userID: user.userID
            }
        };

        jwt.sign(
            payload,
            SECRET_KEY, {
                expiresIn: 10000000000
            },
            (err, token) => {
                if (err) throw err;
                res.status(200).json({user,
                    token
                });
            }
        );
    } catch (err) {
        console.log(err.message);
        res.status(500).send("Error in Saving");
    }
}
/*
exports.login =function isAuthenticateAdmin(req, res, next) {
  if (typeof req.headers.authorization !== "undefined") {
      var token = req.headers.authorization.split(" ")[1];
      
      console.log("Das hier ist der token: " + token)

      var privateKey = process.env.TOKEN_KEY

      jwt.verify(token, privateKey, (err, user) => {
          if(err) {
              console.log(err)
              res.status(500).json({ error: "Not Authorized"});
              //throw new Error("Not Authorized")
          }
          console.log(user.user)
          console.log("Token is valid");

          if (user.user == "admin") {
          var payload = JSON.parse(atob(token.split('.')[1]));
          req.tokenData = payload
          req.userID = payload.user
          res.json({user});
          return next();       
          }
          else {
              console.log("Du bist kein Admin")
              res.status(500).json({ msg: 'Du bist kein Admin bitte logge dich mit Admin Rechten an.'});
              //res.status(500).json({ error: "Not Authorized"});
          }
          
      });
     
  }
  else {
      res.status(401).json({ error: "Not Authorized" })
  }
}

exports.delete = function(req,res){
  var query = {_id: req.body._id};

  User.remove(query, function(err, User){
      if(err){
          console.log("Can´t delete: ",err);
      }
      res.json(User);
  })
};

exports.findOne = function (req, res, next) {
  User.find({userID: req.body.userID})
  .then(doc => {
      if(!doc) { return res.status(400).end();}
      return res.status(200).json(doc);
  })
  .catch(err => next(err));
}


exports.update = function(req, res) {
  var conditions = ({userID: req.body.userID})
  User.updateOne(conditions, {userName: req.body.userName})
  .then(doc => {
      if(!doc) { return res.status(404).end(); }
      return res.status(200).json(doc);
  })
  .catch(err => next(err));
  
}*/

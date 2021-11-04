const User = require('../user/UserModel');
const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const AuthenticationService = require('../authentication/AuthenticationService');
const e = require('express');
const { database } = require('../config/db');
const mongoose = require('mongoose');
require("dotenv").config();
const atob = require('atob');
const asyncHandler = require('express-async-handler')

const SECRET_KEY = process.env.TOKEN_KEY;


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
  
        req.user = await User.findById(decoded.id).select("-password");
  
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
  });
  
  exports.generateToken = (id) => {
    return jwt.sign({ id }), SECRET_KEY, {
      expiresIn: "30d",
    };
  };
  
  
  //@description     Auth the user
  //@route           POST /api/users/login
  //@access          Public
  exports.auth = asyncHandler(async (req, res) => {
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
      throw new Error("Invalid Email or Password");
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
exports.getUsers = async (req,res) =>{
    try{
        const users = await UserModel.find();
        return res.status(200).send({ success: true, data: users});
    }catch ( err){
        return res.status(500).send({ succes: false, data: null});
    }
}

exports.getUserswithouttoken = async (req,res) =>{
    if(req.body.isAdministrator = false){
        try{
            const users = await UserModel.find();
            return res.status(200).send({ success: true, data: users});
        }catch ( err){
            return res.status(500).send({ succes: false, data: null});
        }
    }
}

exports.getUserswithtoken = async (req,res) => {
    var token = req.headers.authorization.split(" ")[1];
    if (!token) return res.status(401).send({ auth: false, message: 'No token provided.' });
    
    jwt.verify(token, SECRET_KEY, function(err, decoded) {
      if (err) return res.status(500).send({ auth: false, message: 'Failed to authenticate token.' });
      
      res.status(200).send(decoded);
    });

  
    if (user) {
        try{
            const users = await UserModel.find();
            return res.status(200).send({ success: true, data: users});
        }catch ( err){
            return res.status(500).send({ succes: false, data: null});
        }
    }
}

exports.createnotoken = async (req, res) => {
    try {
        const {
            userID,
            userName,
            password,
            isAdministrator,
            
    
        } = req.body;
    

        const oldUser = await UserModel.findOne({ userID });
        if (oldUser) {
            return res.status(400).send(
                 "User Already Exists. Please Login"
            );
        }

        let encryptedPassword = await bcrypt.hash(password, 10);
        const user = await UserModel.create({
            userID,
            userName,
            password: encryptedPassword,
            isAdministrator
          });
           //prüfen der Eingabe
        if(!(userID && userName && password)){
            res.status(400).send("Alle Angaben sind nötig");
        }
        

        if(isAdministrator == 1){
         // Create token
         const token = jwt.sign(
            { user: user.id, userName },
        process.env.TOKEN_KEY,
        {
          expiresIn: "9999999999h",
          
        },
        (err, token) => {
            if (err) throw err;
            res.status(200).json({user, token
            });
        }
    );
      // save user token
      user.token = token;
        }else{
      res.status(200).json({user});
        }
        
        
    } catch (err) {
        console.log(err.message);
        res.status(500).send("Error in Saving");
    }
}

exports.loginnotoken = async (req, res) => {
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

exports.findOne = function (req, res, next) {
    UserModel.find({userID: req.body.userID})
    .then(doc => {
        if(!doc) { return res.status(400).end();}
        return res.status(200).json(doc);
    })
    .catch(err => next(err));
}

exports.update = function(req, res) {
    var conditions = ({userID: req.body.userID})
    UserModel.updateOne(conditions, {userName: req.body.userName})
    .then(doc => {
        if(!doc) { return res.status(404).end(); }
        return res.status(200).json(doc);
    })
    .catch(err => next(err)); 
}

exports.delete = function(req,res){
    var query = {_id: req.body._id};

    UserModel.remove(query, function(err, User){
        if(err){
            console.log("Can´t delete: ",err);
        }
        res.json(User);
    })
};


*/
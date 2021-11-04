const ForumModel = require('../forum/ForumModel');
const UserModel = require('../user/UserModel');
const Forum = require('../forum/ForumModel');
const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const tokenSecret = "tokensecret";
const AuthenticationService = require('../authentication/AuthenticationService');
const e = require('express');
const { database } = require('../config/db');
const mongoose = require('mongoose');
const asyncHandler =require("express-async-handler");

const SECRET_KEY = process.env.TOKEN_KEY;

// @desc    Get logged in user notes
// @route   GET /api/notes
// @access  Private
exports.getForum = asyncHandler(async (req, res) => {
  const forum = await Forum.find({ user: req.user._id });
  res.json(forum);
});

//@description     Fetch single Note
//@route           GET /api/notes/:id
//@access          Public
exports.getForumById = asyncHandler(async (req, res) => {
  const forum = await Forum.findById(req.params.id);

  if (forum) {
    res.json(forum);
  } else {
    res.status(404).json({ message: "Forum not found" });
  }

  res.json(forum);
});

//@description     Create single Note
//@route           GET /api/notes/create
//@access          Private
exports.createForum = asyncHandler(async (req, res) => {
  const { forumName, forumDescription } = req.body;

  if (!forumName || !forumDescription ) {
    res.status(400);
    throw new Error("Please Fill all the feilds");
    return;
  } else {
    const forum = new Forum({ user: req.user._id, forumName, forumDescription });

    const createdForum = await forum.save();

    res.status(201).json(createdForum);
  }
});

//@description     Delete single Note
//@route           GET /api/notes/:id
//@access          Private
exports.delete = asyncHandler(async (req, res) => {
  const forum = await Forum.findById(req.params.id);

  if (forum.user.toString() !== req.user._id.toString()) {
    res.status(401);
    throw new Error("You can't perform this action");
  }

  if (forum) {
    await forum.remove();
    res.json({ message: "Note Removed" });
  } else {
    res.status(404);
    throw new Error("Forum not Found");
  }
});

// @desc    Update a note
// @route   PUT /api/notes/:id
// @access  Private
exports.update = asyncHandler(async (req, res) => {
  const { forumName, forumDescription } = req.body;

  const forum = await Forum.findById(req.params.id);

  if (forum.user.toString() !== req.user._id.toString()) {
    res.status(401);
    throw new Error("You can't perform this action");
  }

  if (forum) {
    forum.forumName = forumName;
    forum.forumDescription = forumDescription;

    const updatedForum = await forum.save();
    res.json(updatedForum);
  } else {
    res.status(404);
    throw new Error("Forum not found");
  }
});





/*
exports.getForum = function(req, res){
    Forum.find(function(err, Forum){
        if(err){
            throw err;
        }
        res.json(Forum);
    });
};

exports.findOnebyID = function (req, res, next) {
    Forum.find({ownerID: req.body.ownerID})
    .then(doc => {
        if(!doc) { return res.status(400).end();}
        return res.status(200).json(doc);
    })
    .catch(err => next(err));
}

exports.create = ((req, res) => {
  //Retrieve data for post
  const { forumName, forumDescription, ownerID } = req.body;

  const comments = [];

  //Create a new Post and save it to DB
  const newPost = new Forum({
      forumName,
      forumDescription,
      ownerID,
  });

  // Save the new post
  newPost
      .save()
      .then(() => res.json("Post Added!"))
      .catch((err) => res.status(400).json("Error: " + err));
});
  
exports.findOne = function (req, res, next) {
    Forum.find({ownerID: req.body.ownerID})
    .then(doc => {
        if(!doc) { return res.status(400).end();}
        return res.status(200).json(doc);
    })
    .catch(err => next(err));
}


exports.update = function(req, res) {
    var conditions = ({id: req.params.id})
    Forum.updateOne(conditions, {forumDescription: req.body.forumDescription})
    .then(doc => {
        if(!doc) { return res.status(404).end(); }
        return res.status(200).json(doc);
    })
    .catch(err => next(err));
    
}

exports.delete = function(req,res){
    var query = {_id: req.body._id};

    Forum.remove(query, function(err, Forum){
        if(err){
            console.log("Can´t delete: ",err);
        }
        res.json(Forum);
    })
};*/


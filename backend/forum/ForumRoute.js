var express = require('express');
var router = express.Router();
const bcrypt = require('bcrypt');
const Forum = require('./ForumModel');
var ForumService = require('./ForumService');
const jwt = require('jsonwebtoken');
const tokenSecret = "tokensecret";
const AuthenticationService = require('../authentication/AuthenticationService');
const protect = require("../middleware/authMiddleware.js");



//Forum list

router.get('/',ForumService.getForum);

//Forum list

router.get('/',ForumService.getForum);

//Create forum

router.post('/', protect,ForumService.createForum);

//Change Forum details

router.put('/',ForumService.update);

//Delete Forum

router.delete('/', ForumService.delete);

//Get Forum by ID

router.get('/getByForumID',ForumService.getForumById);


module.exports = router;
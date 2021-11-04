var express = require('express');
var router = express.Router();
const bcrypt = require('bcrypt');
const User = require('./UserModel');
var UserService = require('./UserService');
const jwt = require('jsonwebtoken');
const AuthenticationService = require('../authentication/AuthenticationService');
const tokenSecret = "tokensecret";

//User list

router.get('/',UserService.getUsers);

//register User

router.post('/', UserService.register);

//Login user

router.post('/',UserService.auth);

//Change User details

router.put('/',UserService.update);

//Delete User

router.delete('/', UserService.delete);

//Get USer by ID

router.get('/getByUserID', UserService.getUserById);






module.exports = router;
var express = require('express');
var router = express.Router();
const UserService = require('./../user/UserService');
const AuthenticationService = require('../authentication/AuthenticationService');
const protect = require("../middleware/authMiddleware.js");


//User list

router.get('/',AuthenticationService.getUsers);

//register User

router.post('/register', AuthenticationService.register);

//Login user

router.post('/',protect,AuthenticationService.auth);

//Change User details

router.put('/',AuthenticationService.update);

//Delete User

router.delete('/',AuthenticationService.delete);

//Get USer by ID

router.get('/getByUserID', AuthenticationService.getUserById);



module.exports = router;
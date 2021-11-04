var express = require('express');
var router = express.Router();
const bcrypt = require('bcrypt');
const Forum = require('./ForumModel');
var ForumService = require('./ForumService');
const jwt = require('jsonwebtoken');
const tokenSecret = "tokensecret";
const AuthenticationService = require('../authentication/AuthenticationService');



router.get('/',MessageService.getForum)

router.post("/",MessageService.create);

router.put('/',MessageService.update);

router.get('/getByOwnerID',MessageService.findOne);

router.delete('/', MessageService.delete);



module.exports = router;
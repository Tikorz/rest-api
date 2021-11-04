const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const dotenv = require("dotenv");
const dbURI = "mongodb://localhost:27017/gamerforum";
const User = require("./user/UserModel");
const router = require("express").Router();
const auth = require('../backend/user/UserService');

// Bring in the database object
const config = require('./config/db');
// Initialize the app
const app = express();
// Defining the Middlewares
app.use(cors({
    exposedHeaders: ['Authorization'],
  }));
app.use(bodyParser.urlencoded({ extended: true }))
// BodyParser Middleware
app.use(bodyParser.json());


app.get('/', (req, res) => {
    return res.json({
        message: "Welcome to the gamerforum"
    });
});

// Bring in the user routes
const users = require('./user/UserRoute');
const forum = require('./forum/ForumRoute');
const publicusers = require('./user/PublicUserRoute');
const authenticate = require('./authentication/AuthenticationRoute');
//
app.get('/', (req, res) => {
    return res.json({
        message: "Welcome to the gamerforum"
    });
});
//
app.use('/publicUser', publicusers);
app.use('/publicUser', users);
app.use('/user',users);
app.use('/authenticate',authenticate);
app.use('/forum',forum);


//CONNECTION
mongoose.connect(dbURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
const db = mongoose.connection;
const user = mongoose.model('users', { userID: String},'users',{userName: String},'users', {password: String}, 'users', {isAdmministrator: String});
/*if(user){
    const admin = new User({ userID: 'admin', userName: 'admin', password: '123', isAdmministrator: true});
    admin.save().then(() => console.log('Admin has successfully added'));
}*/

db.on("error", (err)=>{console.error(err)});
db.once("open", () => { console.log ("Database started successfully")})

// Defining the PORT
const PORT = process.env.PORT || 8080;

app.listen(PORT, () => {
    console.log(`Server started on port ${PORT}`);
});

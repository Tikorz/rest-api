const MessageModel = require('../message/MessageModel');
const Message = require('../message/MessageModel');
const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const tokenSecret = "tokensecret";
const AuthenticationService = require('../authentication/AuthenticationService');
const e = require('express');
const { database } = require('../config/db');
const mongoose = require('mongoose');




exports.getForum = function(req, res){
    Message.find(function(err, Message){
        if(err){
            throw err;
        }
        res.json(Message);
    });
};


exports.create = async (req, res) => {
    const message = new Message({
        forumID: req.body.forumID,
        messageTitle: req.body.messageTitle,
        nessageText: req.body.messageText,
        authorID: req.body.authorID
    });
    message
    .save()
    .then((data) => {
        res.send(data);
    })
    .catch((err) => {
        res.status(500).send({
            message: err.message || "Das Forum konnte nicht erstellt werden."
        });
    });
};

exports.findOne = function (req, res, next) {
    Message.find({messageTitle: req.body.messageTitle})
    .then(doc => {
        if(!doc) { return res.status(400).end();}
        return res.status(200).json(doc);
    })
    .catch(err => next(err));
}


exports.update = function(req, res) {
    var conditions = ({id: req.params.id})
    Message.updateOne(conditions, {messageText: req.body.messageText})
    .then(doc => {
        if(!doc) { return res.status(404).end(); }
        return res.status(200).json(doc);
    })
    .catch(err => next(err));
    
}

exports.delete = function(req,res){
    var query = {_id: req.body._id};

    Message.remove(query, function(err, Message){
        if(err){
            console.log("Can´t delete: ",err);
        }
        res.json(Message);
    })
};
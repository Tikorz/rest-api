const mongoose = require('mongoose');
const moment = require('moment');

MessageSchema = new mongoose.Schema({
    forumID: {
        type: mongoose.Schema.Types.ObjectId, ref: "Forum"
    },
    messageTitle: {
        type: String,
    },
    messageText: {
        type: String,
    },
    authorID: {
        type: mongoose.Schema.Types.ObjectId, ref: "User"
    },
});

 module.exports = mongoose.model("Message", MessageSchema);

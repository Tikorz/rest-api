const mongoose = require('mongoose');
const moment = require('moment');


const forumSchema = ({
    forumName: {
        type: String,
        required: true,
    },
    forumDescription: {
        type: String,
        required: true,
    },
    ownerID: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: "User",
    },
    published_on: {
        type: String,
        default: moment().format("LLL")
    },
});


module.exports = mongoose.model('Forum', forumSchema);




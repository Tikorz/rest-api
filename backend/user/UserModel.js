const mongoose = require('mongoose');
const bcryptjs = require('bcryptjs');
const bcrypt = require('bcrypt');
const uniqueValidator = require('mongoose-unique-validator');

// User Schema
const UserSchema = mongoose.Schema({
    userID: {
        type: String,
        required: true,
    },
    userName: {
        type: String,
        required: true,
    },
    password: {
        type: String,
        required: true,
    },
    isAdministrator: {
        type: Boolean,
        deafult: false,
    },
    token: {
        type: String
    },
  
});

UserSchema.methods.matchPassword = async function (enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
  };

//UserSchema.plugin(uniqueValidator);

UserSchema.pre("save", async function (next) {
    if (!this.isModified("password")) {
      next();
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
  });

module.exports = mongoose.model('User', UserSchema);
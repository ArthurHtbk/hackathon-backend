const mongoose = require("mongoose");

const User = mongoose.model("User", {
  email: {
    unique: true,
    type: String,
  },
  username: {
    required: true,
    type: String,
  },
  websites: [],
  token: String,
  hash: String,
  salt: String,
});

module.exports = User;

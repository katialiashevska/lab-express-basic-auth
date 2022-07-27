const { Schema, model } = require("mongoose");

// TODO: Please make sure you edit the user model to whatever makes sense in this case
const userSchema = new Schema({
  username: {
    type: String,
    unique: true,
    trim: true,
    required: [true, "Username is required."]
  },
  email: {
    type: String,
    unique : true,
    lowercase: true,
    trim: true,
    required: [true, "Email is required."],
    match: [/^\S+@\S+\.\S+$/, 'Please use a valid email address.']
  },
  passwordHash: {
    type: String,
    required: [true, "Password is required."]
  }
},
{
  timestamps: true
}
);

const User = model("User", userSchema);

module.exports = User;

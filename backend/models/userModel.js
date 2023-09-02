const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const userschema = mongoose.Schema(
  {
    name: {
      type: String,
      required: [ true, " add a name" ],
    },
    email: {
      type: String,
      required: [ true, " add a email" ],
      unique: true,
      trim: true,
      match: [
        /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|.(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
        ,
        "please enter a valid email",
      ],
    },
    password: {
      type: String,
      required: [ true, " add a password" ],
    },
    photo: {
      type: String,
      // required: [true, " add a photo"],
      default: "http://i.ibb.co/4pDNDk1/avatar.png",
    },
    phone: {
      type: String,
      // required: [true, " add a phone"],
    },
    bio: {
      type: String,
      maxLenght: [ 300, "bio must not be more than 300 chars" ],
      default: "bio",
    },
  },
  {
    timestamps: true,
  },
  
);

userschema.pre("save" , async function(next){

if(!this.isModified("password")){
return next()
}
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(this.password, salt);
  this.password = hashedPassword
  next()
})
const user = mongoose.model("user", userschema);
module.exports = user;

const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const Token = require("../models/tokenModel");
const crypto = require("crypto");
const { request } = require("http");
const sendEmail = require("../utils/sendEmail");

const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "1d" });
};
//register
const registerUser = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    res.status(400);
    throw new Error("please fill in all fields");
  }
  if (password.length < 6) {
    res.status(400);
    throw new Error("password must be up to 6 chars");
  }

  //check if user email already exists
  const userExsits = await User.findOne({ email });
  if (userExsits) {
    res.status(400);
    throw new Error("Email has alreary been used");
  }

  //create new user
  const user = await User.create({
    name,
    email,
    password,
  });
  //generate token
  const token = generateToken(user._id);

  //send HTTP-only cookie
  res.cookie("token", token, {
    path: "/",
    httpOnly: true,
    expires: new Date(Date.now() + 1000 * 86400),
    sameSite: "none",
    secure: true,
  });

  if (user) {
    const { _id, name, email, photo, phone, bio } = user;
    res.status(201).json({
      _id,
      name,
      email,
      phone,
      photo,
      bio,
      token,
    });
  } else {
    res.status(400);
    throw new Error("invalid user data");
  }
});
// login user
const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  //validate req
  if (!email || !password) {
    res.status(400);
    throw new Error("enter paswword and email");
  }

  // Find user by email
  const user = await User.findOne({ email });
  if (!user) {
    return res.status(401).json({ message: "Invalid email or password" });
  }

  // Compare password with hashed password in database
  const isMatch = await bcrypt.compare(password, user.password);

  // If passwords don't match, return error
  if (!isMatch) {
    return res.status(401).json({ message: "Invalid email or password" });
  }
  //generate token
  const token = generateToken(user._id);

  //send HTTP-only cookie
  res.cookie("token", token, {
    path: "/",
    httpOnly: true,
    expires: new Date(Date.now() + 1000 * 86400),
    sameSite: "none",
    secure: true,
  });

  if (user && isMatch) {
    const { _id, name, email, photo, phone, bio } = user;
    res.status(200).json({
      message:"login successfully"
      ,_id,
      name,
      email,
      phone,
      photo,
      bio,
      token,
      
    });
  } else {
    throw new Error("invalid email or password");
  }
});

//logout
const logoutUser = asyncHandler((req, res) => {
  res.cookie("token", "", {
    path: "/",
    httpOnly: true,
    expires: new Date(0), // expire that cookie
    sameSite: "none",
    secure: true,
  });
  return res.status(200).json({ message: "successfully logged out" });
});

//get user data
const getUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (user) {
    const { _id, name, email, photo, phone, bio } = user;
    res.status(201).json({
      _id,
      name,
      email,
      phone,
      photo,
      bio,
      // token,
    });
  } else {
    res.status(400);
    throw new Error("invalid user data");
  }
});

// get login status
const loginStatus = asyncHandler(async (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.json(false);
  }
  //verify token
  const verified = jwt.verify(token, process.env.JWT_SECRET);
  if (verified) {
    return res.json(true);
  } else {
    return res.json(false);
  }
});

//update user
const updateUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (user) {
    const { name, email, photo, phone, bio } = user;
    user.email = email;
    user.name = req.body.name || name;
    user.phone = req.body.phone || phone;
    user.bio = req.body.bio || bio;
    user.photo = req.body.photo || photo;

    const updatedUser = await user.save();
    res.status(201).json({
      name: updatedUser.name,
      email: updatedUser.email,
      phone: updatedUser.phone,
      photo: updatedUser.photo,
      bio: updatedUser.bio,
    });
  } else {
    res.status(404);
    throw new Error("user not found");
  }
});

const updatePassword = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  const { oldPassword, password } = req.body;

  if (!user) {
    res.status(400);
    throw new Error("user not found , please signup");
  }

  if (!oldPassword || !password) {
    res.status(400);
    throw new Error("plaese add old and new password");
  }

  //check if old passwod is matches password in db
  const passwordIsCorrect = await bcrypt.compare(oldPassword, user.password);
  if (user && passwordIsCorrect) {
    user.password = password;
    await user.save();
    res.status(200).send("Password has changed successfully");
  } else {
    res.status(400);
    throw new Error("old password is incorrect");
  }
});

// reset pasword
const resetPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;

  const user = await User.findOne({ email });

  if (!user) {
    res.status(404);
    throw new Error("user doesn't exist");
  }

  //create reset token

  let resetToken = crypto.randomBytes(32).toString("hex") + user._id;
  //hash token
  const hashedToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");
  // save token to db
  await new Token({
    userId: user._id,
    token: hashedToken,
    createdAt: Date.now(),
    expiredAt: Date.now() + 5 * (60 * 1000), // 5 mintues
  }).save();

  //construct url
  const resetUrl = `${process.env.FRONTEND_URL}/resetpassword/${resetToken}`;

  //reset Eamil
  const message = `
  
   <h1>Password Reset</h1>
   <h2>Hello ${user.name}</h2>
    <p>We received a request to reset your password. If you did not make this request, please ignore this email.</p>
    <p>To reset your password, please click the link below:</p>
    <p><a href=${resetUrl} clicktracking=off>Reset Password</a></p>
    <p>This link will expire in 5 mintues.</p>
    <p>Thank you,${resetUrl}</p>
  `;

  const subject = "Password reset request";
  const send_to = user.email;
  const sent_from = process.env.EMAIL_USER;

  try {
    await sendEmail(subject, message, send_to, sent_from);
    res.status(200).json({ success: true, message: "reset eamil sent" });
  } catch (error) {
    res.status(500);
    throw new Error("Email not sent , please try again ");
  }

  res.send("forget password");
});
module.exports = {
  registerUser,
  loginUser,
  logoutUser,
  getUser,
  loginStatus,
  updateUser,
  updatePassword,
  resetPassword,
};

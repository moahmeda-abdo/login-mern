const express = require("express");
const {
  registerUser,
  loginUser,
  logoutUser,
  getUser,
  loginStatus,
  updateUser,
  updatePassword,
  resetPassword,
} = require("../controllers/userControllers");
const { protect } = require("../middleWare/authMiddleware");

const router = express.Router();

router.post("/register", registerUser);
router.post("/login", loginUser);
router.get("/logout", logoutUser);
router.get("/getuser", protect, getUser);
router.get("/loggedin", loginStatus);
router.patch("/update", protect, updateUser);
router.patch("/updatepassword", protect, updatePassword);
router.post("/resetpassword", resetPassword);

module.exports = router;

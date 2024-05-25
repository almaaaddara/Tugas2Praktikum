const express = require("express");
const router = express.Router();
const User = require("../controllers/userController");
const verify = require("../middleware/verify");

// endpoint POST data regist pengguna
router.post("/register", User.register);

// endpoint POST login pengguna (untuk membaca email dan password)
router.post("/login", User.login);

// endpoint GET untuk mendapatkan data All
router.get("users/", verify, User.getAllUsers);

// endpoint GET untuk mendapatkan data by ID
router.get("users/:id", User.getUserByID);

router.delete("/logout", User.logout);

router.get("/token", User.refreshToken);

router.get("/verify", User.verifyEmail);

router.post("/send", User.sendVerifyEmail);





module.exports = router;

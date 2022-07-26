const { Router } = require("express");
const router = new Router();
const mongoose = require("mongoose");
const User = require("../models/User.model");
const bcryptjs = require("bcryptjs");
const saltRounds = 10;
const {isLoggedIn, isLoggedOut} = require("../middleware/route-guard");

// SIGN UP
router.get("/signup", isLoggedOut, (req, res) => res.render("auth/signup"));

router.post("/signup", isLoggedOut, (req, res, next) => {
    const {username, email, password} = req.body;
    if (!username || !password) {
        res.render("auth/signup", {errorMessage: "All fields are required."});
    }
    bcryptjs
      .genSalt(saltRounds)
      .then(salt => bcryptjs.hash(password, salt))
      .then(hashedPassword => {
        return User.create({
            username,
            email,
            passwordHash: hashedPassword
        });
      })
      .then(userFromDB => {
        console.log("Newly created user is: ", userFromDB);
        res.redirect("/userProfile");
      })
      .catch(err => {
        if (err instanceof mongoose.Error.ValidationError) {
            res.status(500).redirect("/signup", {errorMessage: err.message})
        } else if (err.code === 11000) {
            res.status(500).redirect("/signup", {errorMessage: "The username you entered is already used."});
        } else {
            next(err);
        }
      });
});

// LOG IN
router.get("/login", isLoggedOut, (req, res) => res.render("auth/login"));

router.post("/login", isLoggedOut, (req, res, next) => {
    console.log("SESSION ===> ", req.session);
    const {email, password} = req.body;
    if (email === "" || password === "") {
        res.render("auth/login", {
            errorMessage: "All fields are required."
        });
        return;
    }
    User.findOne({email})
      .then(user => {
        if (!user) {
            res.render("auth/login", {errorMessage: "Email not found. Try again."});
            return;
        } else if (bcryptjs.compareSync(password, user.passwordHash)) {
            req.session.currentUser = user;
            res.redirect("/userProfile");
        } else {
            res.render("auth/login", {errorMessage: "Incorrect password."});
        }
      })
      .catch(err => next(err));
});
 
// LOG OUT
router.post("/logout", (req, res) => {
    req.session.destroy();
    res.redirect("/");
});

// USER PROFILE 
router.get("/userProfile", isLoggedIn, (req, res) => {
    res.render("users/user-profile", {userInSession: req.session.currentUser});
});

// MAIN 
router.get("/main", isLoggedIn, (req, res, next) => {
    res.render("main", {userInSession: req.session.currentUser});
});

module.exports = router;
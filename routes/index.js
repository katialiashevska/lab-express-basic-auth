const router = require("express").Router();
const {isLoggedIn, isLoggedOut} = require("../middleware/route-guard");

/* GET home page */
router.get("/", (req, res, next) => {
  res.render("index");
});

module.exports = router;

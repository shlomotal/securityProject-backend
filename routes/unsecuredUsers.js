const express = require("express"),
  router = express.Router();
const bcrypt = require("bcryptjs");
const config = require("config");
const match = require("nodemon/lib/monitor/match");
const general = require("../modules/general");

// get user lists
router.get("/getAll", async function (req, res) {
  var con = general.getConn();
  response = await con.promise().query("select * from users");
  allUsers = response[0];
  console.log(allUsers);
  res.send(JSON.stringify({ allUsers }));
  con.end();
  return true;
});

// create new user
router.post("/signup", async function (req, res) {
    
});

//LOGIN
router.post("/login", async (req, res) => {
});

//Change password
router.post("/changePass", async function (req, res){
});

	// JavaScript program to check if the string
	// contains uppercase, lowercase
	// special character & numeric value


module.exports = router;

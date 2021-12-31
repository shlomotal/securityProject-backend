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
    var errors = [];
    var con = general.getConn();
    console.log(
      "req: " + req.body.username,
      req.body.password,
      req.body.confirmPassword
    );
    if (req.body.confirmPassword !== req.body.password) {
      console.log("Passwords do not match");
      errors.push("Passwords do not match");
    }
    if (errors.length === 0) {
      responseExist = await con
        .promise()
        .query("select count(*) as cnt from users where username=?", [
          req.body.username,
        ]);
      console.log("exist: ", responseExist[0][0].cnt);
      if (responseExist[0][0].cnt !== 0) {
        res.send(JSON.stringify({ error: "The username already exists" }));
        con.end();
        return false;
      }
    //HASH PASSWORD
    const salt = await bcrypt.genSalt(10);
    console.log("salt: " + salt);
    const hashedPassword = await bcrypt.hash(req.body.password, salt);
    console.log("hashedPassword: " + hashedPassword);
    //
    var createQuery = await con
      .promise()
      .query("insert into users values (0,?,?,?,now(),NULL)", [
        req.body.username,
        hashedPassword,
        req.body.password
      ]);
    console.log("createdQuery: " + createQuery[0].insertId);
    userId = createQuery[0].insertId;
    res.send(
      JSON.stringify({ status: "User created successfully. userId:" + userId })
    );

    }
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

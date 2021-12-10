const express = require("express"),
  router = express.Router();
const bcrypt = require("bcryptjs");

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
  if (req.body.password < 10) {
    console.log("password:", req.body.password);
    errors.push("Password must be at least 10 characters");
  }
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
      .query("insert into users values (0,?,?,now(),NULL)", [
        req.body.username,
        hashedPassword,
      ]);
    console.log("createdQuery: " + createQuery[0].insertId);
    userId = createQuery[0].insertId;
    res.send(
      JSON.stringify({ status: "User created successfully. userId:" + userId })
    );
  //   await con
  //     .promise()
  //     .query("insert into salts values (0,?,?)", [userId, salt]);
  //   return true;
  // } else {
  //   res.send(JSON.stringify({ status: "error", errors }));
  //   con.end();
  //   return false;
  }
});

//LOGIN
router.post("/login", async (req, res) => {
  var con = general.getConn();

  // VALIDATE DATA BEFORE WE MAKE A USER
  //const { error } = loginValidation(req.body);
  //if (error) return res.status(400).send(error.details[0].message);

  //CHECK IF USER EXISTS
  responseExist = await con
    .promise()
    .query("select count(*) as cnt from users where username=?", [
      req.body.username,
    ]);
  console.log("exist: ", responseExist[0][0].cnt);
  if (responseExist[0][0].cnt === 0) {
    res.status(400);
    res.send(JSON.stringify({ error: "Incorrect username" }));
    con.end();
    return false;
  }
  responsePassword = await con
    .promise()
    .query("select password from users where username=?", [req.body.username]);

  //CHECK IF PASSWORD IS CORRECT
  console.log("responsePassword: ", responsePassword[0][0].password);
  console.log("req.body.password: ", req.body.password);
  const validPass = await bcrypt.compare(
    req.body.password,
    responsePassword[0][0].password
  );
  if (!validPass) return res.status(400).send("Username or password INCORRECT");

  //CREATE AND ASSIGN A TOKEN
  // const token = jwt.sign({ _id: user._id }, process.env.TOKEN_SECRET);
  // res
  //   .header("authToken", token)
  //   .header("Content-Type", "application/json")
  //   .send(JSON.stringify(token));

  //update last login
  await con
    .promise()
    .query("update users set lastLogin=now() where username=?", [
      req.body.username,
    ]);
  res.status(200).send(JSON.stringify({ status: "User login successful" }));
});

//Change password
router.post("/changePass", async function (req, res)
{
  var con = general.getConn();
  var errors = [];
  responseUsername = await con.promise().query("select count(*) as cnt from users where username=?", [req.body.username]);
  responsePassword = await con.promise().query("select password from users where username=?", [req.body.username]);
  console.log("req:" + req.body.username, req.body.oldPassword, req.body.newPassword ,req.body.confirmNewPassword);
  console.log("exist: ", responseUsername[0][0].cnt);
  if (responseUsername[0][0].cnt === 0) {
    res.status(400);
    res.send(JSON.stringify({ error: "Incorrect username" }));
    con.end();
    return false;
  }
  console.log("responsePassword: ", responsePassword[0][0].password);
  console.log("req.body.oldPassword: ", req.body.oldPassword);
  const validPass = await bcrypt.compare(
    req.body.oldPassword,
    responsePassword[0][0].password
  );
  console.log('valid password: ' + validPass);
  if (!validPass)
  {
    res.status(400).send(JSON.stringify({ error: "Incorrect Password" }));
    con.end();
    return false;
  }
  if (req.body.newPassword < 10) {
    console.log("password:", req.body.password);
    errors.push("Password must be at least 10 characters");
  }
  if (req.body.newPassword !== req.body.confirmNewPassword) {
    console.log("Passwords do not match");
    errors.push("Passwords do not match");
  }
  if (errors.length !== 0) {
    res.status(400).send(JSON.stringify({ error: "Incorrect Password" }));
    con.end();
    return false;
  }

  const salt = await bcrypt.genSalt(10);
  console.log("salt: " + salt);
  const hashedPassword = await bcrypt.hash(req.body.newPassword, salt);
  console.log("hashedPassword: " + hashedPassword);
  var createQuery = await con.promise().query("UPDATE users SET password=? WHERE username=?", [hashedPassword, req.body.username]);
  console.log("createdQuery: " + createQuery[0].insertId);

  userId = createQuery[0].insertId;
  res.status(200).send(JSON.stringify({ status: "password changed successfully. userId:" + userId }));

});


module.exports = router;

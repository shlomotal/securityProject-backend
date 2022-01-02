const express = require("express"),
  router = express.Router();
const bcrypt = require("bcryptjs");
const config = require("config");
const match = require("nodemon/lib/monitor/match");
const general = require("../modules/general");

const validEmailRegex = RegExp(
  /^(([^<>()\[\]\.,;:\s@\"]+(\.[^<>()\[\]\.,;:\s@\"]+)*)|(\".+\"))@(([^<>()[\]\.,;:\s@\"]+\.)+[^<>()[\]\.,;:\s@\"]{2,})$/i
);

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
  var complexPassword = config.get("complexPassword");
  var strongRegex = new RegExp(
    "^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])(?=.{" +
      config.get("passwordLength") +
      ",})"
  );
  var con = general.getConn();
  console.log(
    "req: " + req.body.username,
    req.body.password,
    req.body.confirmPassword
  );
  if (complexPassword) {
    if (!strongRegex.test(req.body.password)) {
      res.status(400).send(
        JSON.stringify({
          error: "Password is too weak",
        })
      );
      con.end();
      return false;
    }
    console.log("Great! its complex password");
  }
  if (req.body.confirmPassword !== req.body.password) {
    console.log("Passwords do not match");
    res.status(400).send(
      JSON.stringify({
        error: "Passwords do not match",
      })
    );
    con.end();
    return false;
  }
  if (!validEmailRegex.test(req.body.username)) {
    console.log("Email is not valid");
    res.status(400).send(
      JSON.stringify({
        error: "Email is not valid",
      })
    );
    con.end();
    return false;
  }

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
  if (config.get("passwordDictonary")) {
    isPasswordInDictonaryPasswordsDb = await con
      .promise()
      .query(
        "SELECT EXISTS(SELECT 1 FROM `dictonary_passwords` WHERE `password`=? LIMIT 1)",
        [req.body.confirmPassword]
      );
    console.log(
      "isPasswordInDictonaryPasswordsDb2: ",
      Object.values(isPasswordInDictonaryPasswordsDb[0][0])[0]
    );
    if (Object.values(isPasswordInDictonaryPasswordsDb[0][0])[0] == 1) {
      res
        .status(400)
        .send(
          JSON.stringify({ error: "The password is very common, change it" })
        );

      con.end();
      return false;
    }
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
      req.body.password,
    ]);
  console.log("createdQuery: " + createQuery[0].insertId);
  userId = createQuery[0].insertId;

  var insertIntoFailedLogins = await con
    .promise()
    .query("insert into failed_logins (userId, failsCount) values (?,0)", [
      userId,
    ]);
  res.send(
    JSON.stringify({ status: "User created successfully. userId:" + userId })
  );
  console.log("insert into failed_logins: " + insertIntoFailedLogins);
  //update history table
  var createHistoryQuery = await con
    .promise()
    .query("insert into passwordhistory values (0,?,?,now())", [
      req.body.username,
      req.body.password,
    ]);
});

//LOGIN
router.post("/login", async (req, res) => {
  var con = general.getConn();

  if (!validEmailRegex.test(req.body.username)) {
    console.log("Email is not valid");
    res.status(400).send(
      JSON.stringify({
        error: "Email is not valid",
      })
    );
    con.end();
    return false;
  }

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

  userId = await con
    .promise()
    .query("select id from users where username=?", [req.body.username]);
  console.log("user id: ", userId[0][0].id);

  if (!validPass) {
    if (config.get("loginRetries") != 0) {
      failedLogins(userId[0][0].id);
    }

    res
      .status(400)
      .send(JSON.stringify({ error: "Username or password INCORRECT" }));
    con.end();
    return false;
  }

  // checking if the user is locked
  if (config.get("loginRetries") != 0) {
    var dateLock = await con
      .promise()
      .query("SELECT dateLock FROM `failed_logins` WHERE `userId`=? LIMIT 1", [
        userId[0][0].id,
      ]);
    console.log("*** checking dateLock: ", Object.values(dateLock[0][0])[0]);
    if (Object.values(dateLock[0][0])[0]) {
      var isTimePassed = await con
        .promise()
        .query(
          "SELECT count(*) from failed_logins T where TIMESTAMPDIFF(MINUTE, T.dateLock, now()) > ? and userId = ?",
          [config.get("lockTimeInMinutes"), userId[0][0].id]
        );
      console.log("isTimePassed: ", Object.values(isTimePassed[0][0])[0]);
      if (Object.values(isTimePassed[0][0])[0] == 0) {
        console.log("user locked");
        res.status(400).send(JSON.stringify({ error: "User locked" }));
        con.end();
        return false;
      } else {
        // update failed logins table
        console.log("updading failed logins table");
        var updateFailedLogins = await con
          .promise()
          .query(
            "update failed_logins set failsCount=0, lastFail=null, dateLock=null where userId=?",
            [userId[0][0].id]
          );
        console.log("updated: ", updateFailedLogins);
      }
    }
  }

  //update last login
  await con
    .promise()
    .query("update users set lastLogin=now() where username=?", [
      req.body.username,
    ]);

  res.status(200).send(JSON.stringify({ status: "User login successful" }));
});

//Change password
router.post("/changePass", async function (req, res) {
  var complexPassword = config.get("complexPassword");
  var strongRegex = new RegExp(
    "^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])(?=.{" +
      config.get("passwordLength") +
      ",})"
  );
  var con = general.getConn();
  if (!validEmailRegex.test(req.body.username)) {
    console.log("Email is not valid");
    res.status(400).send(
      JSON.stringify({
        error: "Email is not valid",
      })
    );
    con.end();
    return false;
  }
  var errors = [];
  responseUsername = await con
    .promise()
    .query("select count(*) as cnt from users where username=?", [
      req.body.username,
    ]);
  responsePassword = await con
    .promise()
    .query("select password from users where username=?", [req.body.username]);
  console.log(
    "req:" + req.body.username,
    req.body.oldPassword,
    req.body.newPassword,
    req.body.confirmNewPassword
  );
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

  // getting user id
  userId = await con
    .promise()
    .query("select id from users where username=?", [req.body.username]);
  console.log("user id: ", userId[0][0].id);

  console.log("valid password: " + validPass);
  if (!validPass) {
    if (config.get("loginRetries") != 0) {
      failedLogins(userId[0][0].id);
    }

    res
      .status(400)
      .send(JSON.stringify({ error: "Username or password INCORRECT" }));
    con.end();
    return false;
  }
  if (req.body.newPassword !== req.body.confirmNewPassword) {
    console.log("Passwords do not match");
    errors.push("Passwords do not match");
  }
  if (complexPassword) {
    if (!strongRegex.test(req.body.newPassword)) {
      res.status(400).send(
        JSON.stringify({
          error: "You chose complex password and its to weak",
        })
      );
      con.end();
      return false;
    }
    console.log("Great! its complex password");
  }
  console.log(config.get("passwordDictonary"));
  if (config.get("passwordDictonary")) {
    isPasswordInDictonaryPasswordsDb = await con
      .promise()
      .query(
        "SELECT EXISTS(SELECT 1 FROM `dictonary_passwords` WHERE `password`=? LIMIT 1)",
        [req.body.confirmNewPassword]
      );
    console.log(
      "isPasswordInDictonaryPasswordsDb2: ",
      Object.values(isPasswordInDictonaryPasswordsDb[0][0])[0]
    );
    if (Object.values(isPasswordInDictonaryPasswordsDb[0][0])[0] == 1) {
      console.log("Password in dictonary_passwords");
      errors.push("Password in dictonary_passwords");
    }
  }
  if (config.get("passwordHistoryLength") != 0) {
    if (
      await isNewPasswordTheSameOfOtherLasPassowrd(
        req.body.newPassword,
        req.body.username
      )
    ) {
      console.log("Choose a password that you didn't chose before");
      errors.push("Choose a password that you didn't chose before");
    }
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
  var createQuery = await con
    .promise()
    .query(
      "UPDATE users SET password=?, Uncsecuredpassword = ?  WHERE username=?",
      [hashedPassword, req.body.newPassword, req.body.username]
    );
  createQuery = await con
    .promise()
    .query("insert into passwordhistory values (0,?,?,now())", [
      req.body.username,
      req.body.newPassword,
    ]);
  console.log("createdQuery: " + createQuery[0].insertId);
  userId = createQuery[0].insertId;
  res.status(200).send(
    JSON.stringify({
      status: "password changed successfully. userId:" + userId,
    })
  );
});

//function check for failed logins count them and lock the user if needed
async function failedLogins(userId) {
  var con = general.getConn();

  // getting count of failed login attempts
  var countFailedLogins = await con
    .promise()
    .query("select failsCount from failed_logins where userId=?", userId);
  console.log("count of failed logins: ", countFailedLogins[0][0].failsCount);

  // checking if need to lock
  var dateLock = null;
  if (countFailedLogins[0][0].failsCount == config.get("loginRetries") - 1) {
    console.log("locking");
    var locked = await con
      .promise()
      .query("update failed_logins set dateLock=now() where userId=?", [
        userId,
      ]);
  }

  // checking if failed logins was already the maximun
  var updatedCountFailedLogins = countFailedLogins[0][0].failsCount + 1;
  if (updatedCountFailedLogins > config.get("loginRetries")) {
    updatedCountFailedLogins = config.get("loginRetries");
  }

  console.log("updatedCountFailedLogins: ", updatedCountFailedLogins);

  if (countFailedLogins[0][0].failsCount != config.get("loginRetries")) {
    console.log("updating failed logins table");
    var updateFailedLogins = await con
      .promise()
      .query("update failed_logins set failsCount=? where userId=?", [
        updatedCountFailedLogins,
        userId,
      ]);
    //console.log("updateFailedLogins: ", updateFailedLogins);
  }
  var updateLastFail = await con
    .promise()
    .query("update failed_logins set lastFail=now() where userId=?", [userId]);
  console.log("updateLastFail: ", updateLastFail);
}

// function to check if new password is the same like "n" last passwords
async function isNewPasswordTheSameOfOtherLasPassowrd(i_Password, i_Username) {
  var con = general.getConn();
  isPasswordInDictonaryPasswordsDb = await con
    .promise()
    .query(
      "select count(*) from (select * from passwordhistory where username = ? order by createdDate desc limit ?) as newTable where newTable.Uncsecuredpassword= ? ",
      [i_Username, config.get("passwordHistoryLength"), i_Password]
    );
  console.log(config.get("passwordHistoryLength"));
  console.log(i_Password);
  console.log(i_Username);
  con.end();
  return Object.values(isPasswordInDictonaryPasswordsDb[0][0])[0] > 0;
}

module.exports = router;

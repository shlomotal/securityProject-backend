const express = require("express"),
  router = express.Router();
const bcrypt = require("bcryptjs");
const config = require("config");
const match = require("nodemon/lib/monitor/match");
const general = require("../modules/general");
const nodemailer = require("nodemailer");
const crypto = require("crypto");

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
    .query("insert into users values (0,?,?,?,now(),NULL, NULL, NULL)", [
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
  var validPass = false;
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

  //CHECK IF PASSWORD IS CORRECT for secured site
  if (config.get("isSecured")) {
    console.log("responsePassword: ", responsePassword[0][0].password);
    console.log("req.body.password: ", req.body.password);
    validPass = await bcrypt.compare(
      req.body.password,
      responsePassword[0][0].password
    );
  }

  //Check if password is correct for UNSECURED sit (SQL Injection)
  else {
    console.log("unsecured function");
    USERNAME = req.body.username;
    PASSWORD = req.body.password;
    responseFromDbSqlInjection = await con
      .promise()
      .query(
        "SELECT count(*) FROM users WHERE username = '" +
          USERNAME +
          "' AND Uncsecuredpassword = '" +
          PASSWORD +
          "' LIMIT 1;"
      );
    if (Object.values(responseFromDbSqlInjection[0][0])[0] != 0) {
      validPass = true;
    }
  }

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
  console.log("password history len: ", config.get("passwordHistoryLength"));
  console.log("i_password: ", i_Password);
  console.log("i_username: ", i_Username);
  console.log(
    "result query: ",
    Object.values(isPasswordInDictonaryPasswordsDb[0][0])[0]
  );
  con.end();
  return Object.values(isPasswordInDictonaryPasswordsDb[0][0])[0] > 0;
}
//send email
function sendEmail(email, token) {
  var email = email;
  var token = token;
  var mail = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: "projectsemailnew@gmail.com", // Your email id
      pass: "projects2021", // Your password
    },
  });
  var mailOptions = {
    from: "Comunication_LTD@gmail.com",
    to: email,
    subject: "Reset Password Link - Comunication_LTD.com",
    html:
      '<p>Your reset pin is: "' +
      token +
      '" . Please copy that and past in the reset password page.</p>',
    //html: '<p>You requested for reset password, kindly use this <a href="http://localhost:4000/reset-password?token=' + token + '">link</a> to reset your password</p>'
  };
  mail.sendMail(mailOptions, function (error, info) {
    if (error) {
      console.log("There is any problem");
    } else {
      console.log("the email sent succefully");
      res.status(200).send(JSON.stringify({ status: "User login successful" }));
    }
  });
}

router.post("/reset-password-email", function (req, res, next) {
  var con = general.getConn();
  var email = req.body.username;
  con.query(
    'SELECT username FROM users WHERE username ="' + email + '"',
    function (err, result) {
      if (err) throw err;
      var type = "";
      var msg = "";
      console.log("debug result: ", result);
      console.log("result len: ", result.length);
      console.log(email);
      if (result.length !== 0) {
        var current_date = new Date().valueOf().toString();
        var token = crypto
          .createHash("sha1")
          .update(current_date, "uft-8")
          .digest("hex");
        var saltRounds = 10;
        ///==========================================================================================================>
        bcrypt.genSalt(saltRounds, function (err, salt) {
          bcrypt.hash(token, salt, function (err, hash) {
            // Store hash in your password DB.
            var sent = sendEmail(email, token);
            console.log("The hash token is: " + hash);
            if (sent != "0") {
              var data = {
                unsecuredToken: token,
                token: hash,
              };
              con.query(
                'UPDATE users SET ? WHERE username ="' + email + '"',
                data,
                function (err, result) {
                  if (err) throw err;
                }
              );
              type = "success";
              msg =
                "The reset password link has been sent to your email address";
              res.status(200).send(
                JSON.stringify({
                  status:
                    "The reset password link has been sent to your email address",
                })
              );
              return true;
            } else {
              type = "error";
              msg = "Something goes to wrong. Please try again";
              console.log("res0");
              res
                .status(400)
                .send(
                  JSON.stringify({ status: "Something goes to much wrong." })
                );
              return false;
            }
          });
        });
      } else {
        console.log("The email did not sent ");
        type = "error";
        msg = "The Email is not registered with us";
        console.log("res1");
        res
          .status(400)
          .send(JSON.stringify({ status: "Something goes wrong." }));
        return false;
      }
      //req.flash(type, msg);
    }
  );
});
/* update password to database */
router.post("/update-password", function (req, res, next) {
  var username = req.body.username;
  var con = general.getConn();
  var token = req.body.token;
  var password = req.body.password;
  var confirmNewPassword = req.body.confirmNewPassword;
  var complexPassword = config.get("complexPassword");
  var strongRegex = new RegExp(
    "^(?=.[a-z])(?=.[A-Z])(?=.[0-9])(?=.[!@#$%^&*])(?=.{" +
      config.get("passwordLength") +
      ",})"
  );
  var errors = [];
  console.log(password);
  console.log(confirmNewPassword);
  if (password !== confirmNewPassword) {
    console.log("Passwords do not match");
    errors.push("Passwords do not match");
  }

  if (complexPassword) {
    if (!strongRegex.test(req.body.password)) {
      res.status(400).send(
        JSON.stringify({
          error: "You chose simple password and its to weak",
        })
      );
      return false;
    }
    console.log("Great! its complex password");
  }

  console.log(config.get("passwordDictonary"));
  if (config.get("passwordDictonary")) {
    con.query(
      'SELECT EXISTS(SELECT 1 FROM `dictonary_passwords` WHERE `password`="' +
        req.body.confirmNewPassword +
        '")',
      function (err, result) {
        if (err) throw err;
        console.log("result:" + Object.values(result[0]));
        console.log("result: ", Object.values(result[0])[0]);
        if (Object.values(result[0])[0] == 1) {
          console.log("Password in dictonary_passwords");
          errors.push("Password in dictonary_passwords");
          res
            .status(400)
            .send(JSON.stringify({ error: "Password in dictonary" }));
          return false;
        } else {
          console.log("errors : " + errors.length);
          if (errors.length !== 0) {
            res
              .status(400)
              .send(JSON.stringify({ error: "Incorrect Password" }));
            con.end();
            return false;
          } else {
            con.query(
              'SELECT * FROM users WHERE username ="' + username + '"',
              async function (err, result) {
                ///needs to add compre check between the hash token---------------------------------------------->
                if (err) throw err;
                var type;
                var msg;
                if (result.length > 0) {
                  console.log("The token is: " + token);
                  //console.log("The unsecuredtoken is: " + result[0].unsecuredToken);
                  var resenedToken = result[0].token;
                  console.log(resenedToken);
                  const validToken = await bcrypt.compare(token, resenedToken);
                  console.log("validToken: " + validToken);
                  if (!validToken) {
                    console.log("wrong token");
                    type = "success";
                    msg = "Invalid link; please try again";
                    res.status(400).send(
                      JSON.stringify({
                        status: "Reset password was not happend",
                      })
                    );
                  } else {
                    var saltRounds = 10;
                    // var hash = bcrypt.hash(password, saltRounds);
                    bcrypt.genSalt(saltRounds, function (err, salt) {
                      bcrypt.hash(password, salt, function (err, hash) {
                        var data = {
                          password: hash,
                          Uncsecuredpassword: password,
                        };
                        con.query(
                          'UPDATE users SET ? WHERE username ="' +
                            result[0].username +
                            '"',
                          data,
                          function (err, result) {
                            if (err) throw err;
                          }
                        );
                      });
                      console.log(
                        "Your password has been updated successfully"
                      );
                      res.status(200).send(
                        JSON.stringify({
                          status: "Reset password has updated successful",
                        })
                      );
                      return true;
                    });
                  }
                } else {
                  console.log("Did not work");
                  type = "success";
                  msg = "Invalid link; please try again";
                  res
                    .status(400)
                    .send(
                      JSON.stringify({ status: "Reset password was not sent" })
                    );

                  return false;
                }
                //req.flash(type, msg);
              }
            );
          }
        }
      }
    );
  } else {
    con.query(
      'SELECT * FROM users WHERE unsecuredToken ="' + token + '"',
      function (err, result) {
        if (err) throw err;
        var type;
        var msg;
        if (result.length > 0) {
          var saltRounds = 10;
          // var hash = bcrypt.hash(password, saltRounds);
          bcrypt.genSalt(saltRounds, function (err, salt) {
            bcrypt.hash(password, salt, function (err, hash) {
              var data = {
                password: hash,
                Uncsecuredpassword: password,
              };
              con.query(
                'UPDATE users SET ? WHERE username ="' +
                  result[0].username +
                  '"',
                data,
                function (err, result) {
                  if (err) throw err;
                }
              );
            });
            console.log("Your password has been updated successfully");
            res.status(200).send(
              JSON.stringify({
                status: "Reset password has updated successful",
              })
            );
            return true;
          });
        } else {
          console.log("Did not work");
          type = "success";
          msg = "Invalid link; please try again";
          res
            .status(400)
            .send(JSON.stringify({ status: "Reset password was not sent" }));

          return false;
        }
        //req.flash(type, msg);
      }
    );
  }
});

//insert new client to DB
router.post("/addClient", async function (req, res, next) {
  var con = general.getConn();
  var clientFirstName = req.body.clientFirstName;
  var clientLastName = req.body.clientLastName;
  var clientPhoneNumber = req.body.clientPhoneNumber;
  var address = req.body.address;
  var QueryCheckForPhoneNumber = await con
    .promise()
    .query(
      "select count(*) from Clients where phoneNumber = '" +
        clientPhoneNumber +
        "'"
    );
  if (Object.values(QueryCheckForPhoneNumber[0][0])[0] === 0) {
    var createQuery = await con
      .promise()
      .query("insert into Clients values (0,?,?,?,?,now())", [
        clientFirstName,
        clientLastName,
        clientPhoneNumber,
        address,
      ]);
    var Query = await con
      .promise()
      .query(
        "select * from Clients where clientFirstName = '" +
          clientFirstName +
          "'"
      );
    res.status(200).send(
      JSON.stringify({
        message: Query[0][0],
      })
    );
  } else {
    res.status(400).send(
      JSON.stringify({
        Error: "The client already exist, try another phone number",
      })
    );
  }

  con.end();
  return false;
});

module.exports = router;

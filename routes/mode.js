const config = require("config");
const express = require("express"),
  router = express.Router();

router.post("/notSecured", async function (req, res) {
  var fs = require("fs");
  var updatedJson =
    '{\n"isSecured": false,\n"passwordLength": 0,\n"complexPassword": false,\n"passwordHistoryLength": 0,\n"passwordDictonary": false,\n"loginRetries": 0,\n"lockTimeInMinutes": 0\n}';

  fs.writeFile("config/default.json", updatedJson, function (err) {
    if (err) throw err;
    console.log("Replaced!");
  });

  res
    .status(200)
    .send(JSON.stringify({ status: "config updated successfully" }));
});

router.post("/secured", async function (req, res) {
  var fs = require("fs");
  var updatedJson =
    '{\n"isSecured": true,\n"passwordLength": 10,\n"complexPassword": true,\n"passwordHistoryLength": 3,\n"passwordDictonary": true,\n"loginRetries": 3,\n"lockTimeInMinutes": 5\n}';

  fs.writeFile("config/default.json", updatedJson, function (err) {
    if (err) throw err;
    console.log("Replaced!");
  });

  res
    .status(200)
    .send(JSON.stringify({ status: "config updated successfully" }));
});

module.exports = router;

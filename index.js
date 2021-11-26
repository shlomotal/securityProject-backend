const express = require("express"),
  app = express(),
  mysql = require("mysql2"), // import mysql module
  cors = require("cors");
  //bodyParser = require("body-parser");

const crypto = require("crypto");
const formidable = require("express-formidable")

// make server object that contain port property and the value for our server.
var server = {
  port: 4040,
};

// routers
const usersRouter = require("./routes/users");

// use the modules
app.use(cors());
//app.use(formidable())
//app.use(bodyParser.json());
app.use(express.json());


app.use("/users", usersRouter);

// starting the server
app.listen(server.port, () =>
  console.log(`Server started, listening port: ${server.port}`)
);

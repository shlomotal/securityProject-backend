var mysql = require("mysql2") // import mysql module


module.exports = {
    getConn: function () {
        var con = mysql.createConnection({
            host: "localhost",
            user: "root",
            password: "318688611",
            database: "securityProjectSchema",
        })
        
        con.connect(function (err) {
            if (err) throw err
        })
        return con
    }
}    


require('dotenv').config(); //must always be require first
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require("bcrypt")
const saltRounds = 10

//level 4 authentication


const app = express();

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(express.static("public"));

//DB Connection
mongoose.connect(process.env.DATABASE_URL, {useNewUrlParser:true, useUnifiedTopology:true, useFindAndModify:false})

//schemas
const userSchema = new Schema({
    email: {
        type: String,
        required:[true, "An email is required!"]
    },
    password: {
        type: String,
        required:[true, "You would need a password too!"]
    }
})


const User = new mongoose.model("User", userSchema)

// routing
app.route("/").get(function (req, res) {
    res.render("home")
})

app.route("/login")
    .get(function (req, res) {
    res.render("login")
    })
    .post(function (req, res) {
        const username = req.body.username
        const password = req.body.password
        User.findOne({ email:username}, function (err, foundUser) {
            if (err) {
                console.log(err);   
            } else {
                if (foundUser) {
                    bcrypt.compare(password, foundUser.password, function (err, result) {
                        if (result===true) {
                            res.render("secrets")
                        } else {
                            console.log("Incorrect Password");
                        }
                    })                 
                    
                } else {
                    res.send("User does not exist!")
                }
            }
        })
    })

app.route("/register")
    .get(function (req, res) {
    res.render("register")
    })
    .post(function (req, res) {
        bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
            const newUser = new User({
                email: req.body.username,
                password:hash
        })

        newUser.save(function (err) {
            if (err) {
               console.log(err);
            } else {
                res.render("secrets")
            }
        })      
        })
      
    })

app.listen(3000, function() {
  console.log("Server started on port 3000");
});
require("dotenv").config(); //must always be require first
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
//passport-local is a dependency required by passport-local-mongoose
//but it is not necesary to refer/expose it in the code.

//level 5&6 authentication

const app = express();

app.set("view engine", "ejs");

app.use(
  bodyParser.urlencoded({
    extended: true,
  })
);
app.use(express.static("public"));

//Authentication steps  ----NOTE---The location of the steps in the code matters.
//STEP 1
app.use(
  session({
    secret: "process.env.SECRET",
    resave: false,
    saveUninitialized: false,
  })
);

//STEP 2
app.use(passport.initialize());
app.use(passport.session());

//DB Connection
mongoose.connect(process.env.DATABASE_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useFindAndModify: false,
  useCreateIndex: true,
});

//schemas
const userSchema = new Schema({
  username: {
    type: String,
    required: [true, "An username is required!"],
  },
  password: {
    type: String,
  },
});

//STEP 3
userSchema.plugin(passportLocalMongoose);

const User = new mongoose.model("User", userSchema);

//STEP 4
passport.use(User.createStrategy());

//STEP 5
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

// routing
app.route("/").get(function (req, res) {
  res.render("home");
});

app
  .route("/login")
  .get(function (req, res) {
    res.render("login");
  })
  .post(function (req, res) {
    const user = new User({
      username: req.body.username,
      password: req.body.password,
    });

    req.login(user, function (err) {
      if (err) {
        console.log(err);
      } else {
        passport.authenticate("local")(req, res, function () {
          res.redirect("/secrets");
        });
      }
    });
  });

app.get("/logout", function (req, res) {
  req.logout();
  res.redirect("/");
});

app
  .route("/register")
  .get(function (req, res) {
    res.render("register");
  })
  .post(function (req, res) {
    console.log(req.body.password);
    User.register(
      { username: req.body.username },
      req.body.password,
      function (err, user) {
        if (err) {
          console.log(err);
          res.redirect("/register");
        } else {
          passport.authenticate("local")(req, res, function () {
            res.redirect("/secrets");
          });
        }
      }
    );
  });

app.route("/secrets").get(function (req, res) {
  if (req.isAuthenticated()) {
    res.render("secrets");
  } else {
    res.redirect("/login");
  }
});

app.listen(3000, function () {
  console.log("Server started on port 3000");
});

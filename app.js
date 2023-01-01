//jshint esversion:6
require('dotenv').config();
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const FacebookStrategy = require('passport-facebook').Strategy;


//////level 3 security using hash function.
// const md5 = require("md5");

//////level 4 security.
// const bcrypt = require("bcrypt");
// const saltRounds = 10;

//////for level 2 encryption.
// const encrypt = require("mongoose-encryption");

const app = express();

app.use(express.urlencoded({extended:true}));
app.use(express.json());
app.use(express.static("public"));

app.set("view engine", "ejs");

//use express-session
app.use(session({
    secret: process.env.SECRET,
    resave:false,
    saveUninitialized:false
}));

//initialize passport and get it to setup our session.
app.use(passport.initialize());
app.use(passport.session());


//CONFIGURE  google STRATEGY
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    // userProfileURL:"https://www.googleapis.com/auth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
      console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

//configure fb strategy.
passport.use(new FacebookStrategy({
    clientID: process.env.APP_ID,
    clientSecret:process.env.APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) { 
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));




mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser:true, useUnifiedTopology:true, useFindAndModify:false});
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
    email:String,
    password: String,
    secret: String,
    googleId:String,
    facebookId:String
});

//add passportLocalMongoose as a plugin to userSchema.
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);


///////this was for level 2 security.
// const secret = process.env.SECRET;
// userSchema.plugin(encrypt, {secret:secret, encryptedFields:["password"]});

const User = mongoose.model("User", userSchema);

//passport local configurations.
passport.use(User.createStrategy());
passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});


app.get("/", function(req, res){
    res.render("home");
}); 

app.get("/login", function(req, res){
    res.render("login");
});

app.get("/register", function(req, res){
    res.render("register");
});

app.get("/submit", function(req, res){
  if(req.isAuthenticated){
    res.render("submit");
  }else{
    res.redirect("/login");
  }
});

app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;
  console.log(req.user);

  User.findById({_id:req.user.id}, function(err, foundUser){
    if(err){
      console.log(err);
    }else{
      if(foundUser){
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
        res.redirect("/secrets");
        });
      }
    }
  }); 
});


//user should be allowed access if only they are registered.
app.get("/secrets", function(req, res){
    User.find({"secret":{$ne:null}}, function(err, foundUsers){
      if (err){
        console.log(err);
      }else{
        if(foundUsers){
          res.render("secrets", {usersWithSecrets:foundUsers});
          console.log(foundUsers);
        }
      }

    });
    
});

//logout user using passport.
app.get("/logout", function(req, res){
    req.logOut();
    res.redirect("/");
});

//to sign in with google.
app.get("/auth/google",
  passport.authenticate("google", { scope: [ "profile" ] }));

//where google sends user once they are authenticated.
app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect("/secrets");
  });

  //fb auth
app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });





/////////////using passportLocalMongoose for security and authentication.
app.post("/register", function(req, res){
    User.register({username:req.body.username}, req.body.password, function(err, user){
        if (err){
            console.log(err);
            res.redirect("/register");
        }else{
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
    });

});

app.post("/login", function(req, res){
    const user = new User({
        username:req.body.username,
        password:req.body.password
    });
    //use passport to login user
    req.logIn(user, function(err){
        if (err){
            console.log(err);
        }else{
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
    });
});








/////password is hashed with bcrypt at register and login.

// app.post("/register", function(req, res){
//     bcrypt.hash(req.body.password, saltRounds, function(err, hash){
//         const newUser = new User({
//             email: req.body.username,
//             password: hash
//         });
//         newUser.save(function(err){
//             if(err){
//                 console.log(err);
//             }else{
//                 res.render("secrets");
//             }
//         });

//     });
    
// });

// app.post("/login", function(req, res){
//     const username = req.body.username;
//     const password = req.body.password;

//     User.findOne({email: username}, function(err, foundUser){
//         if (err){
//             console.log(err);
//         }else{
//             if(foundUser){
//                 bcrypt.compare(password, foundUser.password, function(err, result){
//                     if (result === true){
//                         res.render("secrets");
//                     }
//                 });  
//             }
//         }
//     });
// }); 




app.listen(3000, function(){
    console.log("server has started on port 3000");
});
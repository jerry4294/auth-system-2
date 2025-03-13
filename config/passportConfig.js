const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const User = require('../models/User'); // Update path if necessary
const mongoose = require('mongoose');

// Google OAuth Strategy Configuration
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID, // From .env
  clientSecret: process.env.GOOGLE_CLIENT_SECRET, // From .env
  callbackURL: process.env.GOOGLE_CALLBACK_URL, // From .env
},
  function (accessToken, refreshToken, profile, done) {
    // Find or create user based on Google profile
    User.findOne({ googleId: profile.id })
      .then(user => {
        if (user) {
          // User exists, proceed
          return done(null, user);
        } else {
          // Create a new user if not found
          const newUser = new User({
            googleId: profile.id,
            username: profile.displayName,
            email: profile.emails[0].value, // Assuming the user has an email
            avatar: profile.photos[0].value // Optional: You can also store the user's avatar
          });

          // Save new user to the database
          newUser.save()
            .then(user => {
              return done(null, user);
            })
            .catch(err => done(err));
        }
      })
      .catch(err => done(err));
  }
));

// Serialize the user into session
passport.serializeUser(function (user, done) {
  done(null, user.id); // Store the user's ID in the session
});

// Deserialize the user from the session
passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user); // Retrieve the user from the database
  });
});

const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const User = require('../models/User');
const mongoose = require('mongoose');

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL,
},
  function (accessToken, refreshToken, profile, done) {
    User.findOne({ googleId: profile.id })
      .then(user => {
        if (user) {
          return done(null, user);
        } else {
          const newUser = new User({
            googleId: profile.id,
            username: profile.displayName,
            email: profile.emails[0].value,
            avatar: profile.photos[0].value
          });

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

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

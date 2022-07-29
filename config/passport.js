const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const connection = require('./database');
const User = connection.models.User;
const validPassword = require('../lib/passwordUtils').validPassword;


const customFields = {
  username: 'username',
  password: 'password'
};



const verifyCallback = (username, password, next) => {
  User.findOne({
      username: username
    })
    .then((user) => {
      if (!user) {
        next(null, false)
      }
      const isValid = validPassword(password, user.hash, user.salt);
      if (isValid) {
        next(null, user)
      } else {
        next(null, false)
      }
    })
    .catch((err) => {
      next(err)
    })
};

const strategy = new LocalStrategy(customFields, verifyCallback);

passport.use(strategy);

passport.serializeUser((user, next) => {
  next(null, user.id)
});

passport.deserializeUser((userId, next) => {
  User.findById(userId)
    .then((user) => {
      next(null, user)
    })
    .catch(err => next(err))
});

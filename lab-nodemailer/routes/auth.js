const express = require('express');
const passport = require('passport');

const router = express.Router();
const bcrypt = require('bcrypt');
const User = require('../models/User');

// Bcrypt to encrypt passwords
const bcryptSalt = 10;


router.get('/login', (req, res, next) => {
  res.render('auth/login', { message: req.flash('error') });
});

router.post('/login', passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/auth/login',
  failureFlash: true,
  passReqToCallback: true,
}));

router.get('/signup', (req, res, next) => {
  res.render('auth/signup');
});

router.post('/signup', (req, res, next) => {
  const username = req.body.username;
  const password = req.body.password;
  const email = req.body.email;
  if (username === '' || password === '') {
    res.render('auth/signup', { message: 'Indicate username and password' });
    return;
  }

  User.findOne({ username }, 'username', (err, user) => {
    if (user !== null) {
      res.render('auth/signup', { message: 'The username already exists' });
      return;
    }
    if (user.status !== 'Active') {
      res.render('auth/signup', { message: 'The username already exists, but is not active, check your email!' });
      return;
    }

    const salt = bcrypt.genSaltSync(bcryptSalt);
    const hashPass = bcrypt.hashSync(password, salt);

    let confirmationCode = '';
    for (let i = 0; i < 30; i += 1) {
      confirmationCode += String.fromCharCode(Math.floor(Math.random()) * 128);
    }

    const newUser = new User({
      username,
      password: hashPass,
      email,
      confirmationCode,
    });

    newUser.save()
      .then(() => {
        
        res.redirect('/');
      })
      .catch((err) => {
        res.render('auth/signup', { message: 'Something went wrong' });
      });
  });
});

router.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/');
});

module.exports = router;

// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const express = require('express');
const bcrypt = require('bcryptjs');
const { checkUsernameFree, checkUsernameExists, checkPasswordLength, } = require('./auth-middleware');
const Users = require('../users/users-model');

const router = express.Router();

router.post('/register', checkUsernameFree, checkPasswordLength, (req, res, next) => {
  const credentials = req.body;

  const hash = bcrypt.hashSync(credentials.password, 8);
  credentials.password = hash;

  Users.add(credentials)
    .then((newUser) => {
      res.status(200).json({user_id: newUser.user_id, username: newUser.username})
    })
    .catch(next)
})

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */
router.post('/login', checkUsernameExists, (req, res, next) => {
  const credentials = req.body;

  Users.findBy('username', credentials.username)
    .then((user) => {
      if(!user || !bcrypt.compareSync(credentials.password, user[0].password)) {
        return res.status(401).json({ message: 'Invalid credentials' })
      } else {
        req.session.user = user[0]
        res.json({ message: `Welcome ${user[0].username}!`})
      }
    })
    .catch(next)
})

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */

router.get('/logout', (req, res, next) => {
  if (req.session.user) {
    req.session.destroy(err => {
      if (err) {
        res.json({ message: 'sorry there was an error logging you out'})
      } else {
        res.json({ message: 'logged out', status: 200})
      }
    })
  } else { 
    res.json({ message: 'no session', status: 200})
  }
})
/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */

 
// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router;
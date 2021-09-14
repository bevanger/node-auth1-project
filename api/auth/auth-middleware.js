const Users = require('../users/users-model');
/*
  If the user does not have a session saved in the server

  status 401
  {
    "message": "You shall not pass!"
  }
*/
function restricted(req, res, next) {
  if (req.session && req.session.user) {
    next()
  } else { 
    res.status(401).json({ message: 'you shall not pass!' })
  }
}

/*
  If the username in req.body already exists in the database

  status 422
  {
    "message": "Username taken"
  }
*/
function checkUsernameFree(req, res, next) {
  Users.findBy('username', req.body.username)
    .then((usernameIsTaken) => {
      if(usernameIsTaken.length > 0) {
        next({ message: 'username taken', status: 422})
      } else {
        next()
      }
    })
}

/*
  If the username in req.body does NOT exist in the database

  status 401
  {
    "message": "Invalid credentials"
  }
*/
function checkUsernameExists(req, res, next) {
  Users.findBy('username', req.body.username)
    .then((credentials) => {
      if(credentials.length < 1) {
        next({ message: 'Invalid credentials', status: 401})
      } else {
        next()
      }
    })
}

/*
  If password is missing from req.body, or if it's 3 chars or shorter

  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
*/
function checkPasswordLength(req, res, next) {
  if(!req.body.password || req.body.password.length <= 3 ) {
    next({ message: 'Password must be longer than 3 chars', status: 422})
  } else {
    next()
  }
}

// Don't forget to add these to the `exports` object so they can be required in other modules
module.exports = { 
  restricted, 
  checkUsernameFree,
  checkUsernameExists,
  checkPasswordLength,
}
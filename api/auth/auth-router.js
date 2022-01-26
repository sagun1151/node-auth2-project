const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const bcrypt = require("bcryptjs/dist/bcrypt");
const Users = require('../users/users-model')
const makeToken = require('./auth-token')

router.post("/register", validateRoleName, async (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
  let user = req.body;
    const hash = bcrypt.hashSync(user.password, 8)
    user.password = hash
    user.role_name = req.role_name
    try {
      const reg = await Users.add(user)
      console.log(reg)
      res.status(201).json(reg)
    } catch (error) {
      next(error)
    }
});


router.post("/login", checkUsernameExists, async (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
  try {
    const user = req.user
    const token = makeToken(user)
    res.status(200).json({message: `${user.username} is back`, token: token})
  } catch (error) {
    next(error)
  }
});

module.exports = router;

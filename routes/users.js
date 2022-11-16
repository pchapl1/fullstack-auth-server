var express = require('express');
const { uuid } = require('uuidv4');
const { route } = require('.');
const { db } = require('../mongo');
var router = express.Router();
const bcrypt = require('bcryptjs')
const jwt = require("jsonwebtoken");
require("dotenv").config();


/* GET users listing. */
router.get('/', function(req, res, next) {
  res.send('respond with a resource');
});

router.get('/message', function(req, res, next){

  const tokenKeyHeader = process.env.TOKEN_HEADER_KEY
  const token = req.headers(tokenKeyHeader)

  const jwtSecretKey = process.env.JWT_SECRET_KEY;
  const verifiedToken = jwt.verify(token, jwtSecretKey);

  if (!verifiedToken) {
    return res.json({
      success: false,
      message: "ID Token could not be verified",
    });
  }

  if (userData && userData.scope === "user") {
    return res.json({
      success: true,
      message: "I am a normal user",
    });
  }
  
  if (userData && userData.scope === "admin") {
    return res.json({
      success: true,
      message: "I am an admin user",
    });
  }

})


// post route
router.post('/register', async function(req, res, next){
  
  
  const email = req.body.email
  const password = req.body.password
  
  const saltRounds = 5
  const salt = await bcrypt.genSalt(saltRounds);
  
  const passwordHash = await bcrypt.hash(password, salt);
  
  const user = {
    email,
    password: passwordHash, 
    id: uuid()
  }
  
  await db().collection('users').insertOne(user)

  
  res.json({
    success: true
  })
})


router.post('/login', async function(req, res, next){

  const email = req.body.email
  const password = req.body.password

  const user = await db().collection('users').findOne({
    email: email
  })

  if (!user) {
    res.json({
      success: false,
      msg: "Could not find user"
    }).status(204)
    return;
  }

  const match = await bcrypt.compare(password, user.password)
  if (!match) {
    res.json({
      success: false,
      msg: "Password was incorrect"
    }).status(204)
    return
  }

  let scope;

  if (user.email.endsWith('codeimmsersives.com')) {
    scope = 'admin'
  } else {
    scope = 'user'
  }

  const userData = {
    date: new Date(),
    userId: user.id,
    scope 
  }

  const payload = {
    userData,
    exp: Math.floor(Date.now() / 100 + (60 * 60))
  }


  const jwtSecretKey = process.env.JWT_SECRET_KEY;
  console.log(jwtSecretKey)
  const token = jwt.sign(payload, jwtSecretKey);

  res.json({
    success: true,
    token: token,
    email: user.email
  })
})

module.exports = router;
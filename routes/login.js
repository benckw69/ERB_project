var express = require('express');
var router = express.Router();

const MongoClient = require('mongodb').MongoClient;
const {url,db} = require('./config');
const auth = require('./auth');
const client = new MongoClient(url);
const users_c = client.db(db).collection("users");
const bcrypt = require('bcrypt');
const passport = require('passport');
const LocalStrategy = require('passport-local');

passport.use(new LocalStrategy(
  {
    usernameField: 'email',
    passwordField: 'password',
    passReqToCallback: true
  }
  ,async (req, email, password, done)=> {
    try {
      await client.connect();
      let userExist = await users_c.findOne({email:email, type:req.query.type, loginMethod:"email"});
      if(!userExist) return done(null, false,{message:"找不到電郵地址，請重新輸入"});
      if(!bcrypt.compareSync(password, userExist.password)) return done(null, false,{message:"密碼不正確，請重新輸入"});
      return done(null, userExist);
    } finally {
      await client.close();
    }
  }
));


/* GET login page. */
router.get('/',auth.isNotlogin,(req,res)=>{
  res.render('login');

}).post('/',auth.isNotlogin, (req,res,next)=>{
  const callback = passport.authenticate('local', { successRedirect: '/',
    failureRedirect: '/login?type='+req.query.type,
    failureMessage: true });
    callback(req, res, next);
}).get('/google/:type', (req,res,next)=>{
  req.session.type = req.params.type;
  passport.authenticate('google')(req,res,next);
}).get('/oauth/google',passport.authenticate('google', { failureRedirect: '/login/google/fail', failureMessage: true }), function(req, res) {
  res.redirect('/');
}).get('/google/fail',(req,res)=>{
  let type = res.session.type;
  delete res.session.type;
  res.redirect('/login?type='+type);
});

module.exports = router;

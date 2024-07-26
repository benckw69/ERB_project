var express = require('express');
var router = express.Router();

const { MongoClient, ObjectId } = require('mongodb');
const auth = require('./auth');
const {url,db} = require('./config');
const client = new MongoClient(url);
const users_c = client.db(db).collection("users");
const validator = require('email-validator');
const bcrypt = require('bcrypt');

router.get('/',auth.isNotlogin,(req,res)=>{
  if(req.query.type=="admin") res.redirect("/");
  else res.render('register');

}).post('/',auth.isNotlogin, async (req, res) => {
  let type = req.query.type;
  let {username,email,password,password_repeat,referral} = req.body;
  if(referral.length ==24 ) referral = new ObjectId(referral);
  else referral="";

  //check whether two passwords are the same and the length is longer than or equal to 8.
  if(password != password_repeat ) req.session.messages.push("兩次輸入密碼並不一致");
  if(password.length < 8) req.session.messages.push("密碼長度未夠8位");
  if(!validator.validate(email)) req.session.messages.push("電郵地址格式錯誤");
  if(!! req.session.messages.length) res.redirect('/register?type='+type);
  else {
    //check whether email exist in the database.
    try {
      await client.connect();
      const userExist = await users_c.findOne({email:email, type:type, loginMethod:"email"});
      if(userExist) req.session.messages.push("電郵地址已經存在");
      else {
        //insert data into database
        const saltRounds = 10;
        const salt = bcrypt.genSaltSync(saltRounds);
        const hash = bcrypt.hashSync(password, salt);
        let userData = {type:type, email:req.body.email, username:username, password:hash, loginMethod:"email"};
        if(type == "student" || type == "teacher") userData.money = 0;
        if(type == "teacher") userData.introduction = "";
        let userExist = await users_c.findOne({_id:referral});
        if(userExist) {
          userData.money = 10;
          const updateReferral = await users_c.updateOne({_id:referral},{$set:{money:userExist.money+10}});
          if(updateReferral.modifiedCount != 1) req.session.messages.push("不能加入現金，請再嘗試");
        }
        const user = await users_c.insertOne(userData);

        //check whether data are inserted.  Find back the inserted data
        if(user.acknowledged) {
          const newUser = await users_c.findOne({email:email, type:type, loginMethod:"email"});
          if(newUser) {req.login(newUser,(err)=>{
            if(err) req.session.messages.push("出現問題，請重試");
            else res.redirect('/?msg=3');
          })}
          else req.session.messages.push("未能尋找新増紀錄，請再嘗試");
        }
        else req.session.messages.push("未能新増紀錄，請再嘗試");
      }
      if(!! req.session.messages.length) res.redirect('/register?type='+type);
    } finally {
        await client.close();
    }
  }
});

module.exports = router;

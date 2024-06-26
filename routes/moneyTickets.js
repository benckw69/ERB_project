var express = require('express');
var router = express.Router();

const MongoClient = require('mongodb').MongoClient;
const config = require('./config');
const { ObjectId } = require('mongodb');
const client = new MongoClient(config.url);

/*  */
router.get('/insert', (req, res) => {
  let msgCode = req.query.msg, msg;
  if(msgCode=="1") msg= "成功兌換現金卷";
  else if(msgCode=="2") msg = "兌換現金卷失敗，請再嘗試";
  else if(msgCode=="3") msg = "兌換現金卷失敗：號碼錯誤，請更改號碼後再嘗試";
  else if(msgCode=="4") msg = "兌換現金卷失敗：伺服器無法刪除紀錄，請稍後再嘗試";
  else if(msgCode=="5") msg = "兌換現金卷失敗：伺服器無法找到用家，請稍後再嘗試";
  else if(msgCode=="6") msg = "兌換現金卷失敗：伺服器無法新增現金給予用家，請稍後再嘗試";

  if(req.session.user&& req.session.user.type=="student") res.render('moneyTickets_insert', { msg:msg });
  else res.redirect('/');

}).post('/insert', async(req, res) => {
  if(req.session.user && req.session.user.type=="student") {
    //need edit
    
    let code=req.body.ticketNum;
    let user=req.session.user;
    try {
      await client.connect();
      const moneyTickets_c = client.db("learningPlatform").collection("moneyTickets");
      const getMoneyTickets = await moneyTickets_c.findOne({code:code});
      if(getMoneyTickets) {
        //delete the tickets and modify the value of money of user
        const deleteMoneyTickets = await moneyTickets_c.deleteOne({code:code});
        if(deleteMoneyTickets.deletedCount == 1) {
          const users_c = client.db("learningPlatform").collection("users");
          const getUser = await users_c.findOne({_id:new ObjectId(user._id)});
          if(getUser) {
            getUser.money =Number(getUser.money) + Number(getMoneyTickets.money);
            delete getUser._id;
            const addMoneyToUser = await users_c.replaceOne({_id:new ObjectId(user._id)},getUser);
            if(addMoneyToUser) res.redirect('/moneyTickets/insert?msg=1');
            else res.redirect('/moneyTickets/insert?msg=6');
          } else res.redirect('/moneyTickets/insert?msg=5');
        } else res.redirect('/moneyTickets/insert?msg=4');
      }
      //when there is no code in database, return error message
      else res.redirect('/moneyTickets/insert?msg=3');
    } finally {
      await client.close();
    }
  }
  else res.redirect('/');
}).get('/view', async(req,res)=>{
  let msgCode=req.query.msg, msg;
  if(msgCode=="1") msg= "刪除成功";
  else if(msgCode=="2") msg = "刪除失敗，請稍後再試";
  if(req.session.user && req.session.user.type=="admin") {
    try{
      await client.connect();
      const moneyTickets_c = client.db("learningPlatform").collection("moneyTickets");  
      const moneyTickets = await moneyTickets_c.find().toArray();
      res.render('moneyTickets_view', { moneyTickets:moneyTickets, pop:msg });
    } finally {
      await client.close();
    }
  }
  else res.redirect('/');
}).get('/new',(req,res)=>{
  let msgCode=req.query.msg, msg;
  if(msgCode=="1") msg= "添加使用卷成功";
  else if(msgCode=="2") msg = "已有此使用卷號碼，請嘗試輸入其他號碼";
  else if(msgCode=="3") msg = "號碼不能為空，請輸入號碼";
  else if(msgCode=="4") msg = "未能插入新紀錄，請稍後再試";

  if(req.session.user && req.session.user.type=="admin") res.render('moneyTickets_new', { msg:msg });
  else res.redirect('/');
}).post('/new', async(req,res)=>{
  if(req.session.user && req.session.user.type=="admin") {
    let code = req.body.code, money = req.body.money;
    const moneyTickets_new = {code:code, money:money};
    if(code.length==0) res.redirect('/moneyTickets/new?msg=3');
    else {
      try {
        await client.connect();
        const moneyTickets_c = client.db("learningPlatform").collection("moneyTickets");  
        const moneyTicketsExist = await moneyTickets_c.findOne({code:code});
        if(moneyTicketsExist) res.redirect('/moneyTickets/new?msg=2');
        else {
          const moneyTickets_insert = await moneyTickets_c.insertOne(moneyTickets_new);
          if(moneyTickets_insert.acknowledged) res.redirect('/moneyTickets/new?msg=1');
          else res.redirect('/moneyTickets/new?msg=4');
        }
      } finally {
        await client.close();
      }
    }
  }
  else res.redirect('/');
}).get('/delete',async(req,res)=>{
  if(req.session.user && req.session.user.type=="admin") {
    if(req.query.id && req.query.id.length==24){
      let id=req.query.id;
      try {
        await client.connect();
        const moneyTickets_c = client.db("learningPlatform").collection("moneyTickets");
        const deleteMoneyTickets = await moneyTickets_c.deleteOne({_id:new ObjectId(id)});
        if(deleteMoneyTickets.deletedCount == 1) res.redirect("/moneyTickets/view?msg=1");
        else res.redirect('/moneyTickets/view?msg=2');
      } finally {
        await client.close();
      }
    } else res.redirect('/moneyTickets/view');
  }
  else res.redirect('/');
});

module.exports = router;

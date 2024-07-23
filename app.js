var createError = require('http-errors');
var express = require('express');
var path = require('path');
//var cookieParser = require('cookie-parser');
var logger = require('morgan');
const session = require('express-session');
const validator = require('email-validator');
const config = require('./routes/config');
const { MongoClient, ObjectId } = require('mongodb');
const client = new MongoClient(config.url);
const users_c = client.db(config.db).collection("users");
const passport = require('passport');

var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');
let coursesRouter = require('./routes/courses');
let loginRouter = require('./routes/login');
let registerRouter = require('./routes/register');


var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
//app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({secret:"secret string", resave:false, saveUninitialized:true}));
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser(function (user, cb) {
  cb(null,user._id);
});

passport.deserializeUser(function (_id, cb) {
  users_c.findOne({_id:new ObjectId(_id)}).then((result)=>{
    cb(null,result);
  });
  
});

app.use((req,res,next)=>{
  res.locals.user = req.user;
  res.locals.title = config.title;
  res.locals.messages = req.session.messages;
  req.session.messages = [];
  next();
})

app.use('/login', loginRouter);
app.use('/register', registerRouter);
app.use('/users', usersRouter);
app.use('/courses',coursesRouter);
app.use('/moneyTickets',require('./routes/moneyTickets'));
app.use('/searchTeachers', require('./routes/searchTeachers'))
app.use('/searchStudents', require('./routes/searchStudents'))
app.use('/', indexRouter);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;

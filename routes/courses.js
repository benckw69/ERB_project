var express = require('express');
var router = express.Router();

const MongoClient = require('mongodb').MongoClient;
const config = require('./config');
const db = config.db;
const client = new MongoClient(config.url);
const ObjectId = require('mongodb').ObjectId;

const courses_c = client.db(db).collection("courses");
const courses_u = client.db(db).collection("users");
const buyRecords_c = client.db(db).collection("buyRecords");

const isValidUrl = urlString=> {
    var urlPattern = new RegExp('^(https?:\\/\\/)?'+ // validate protocol
  '((([a-z\\d]([a-z\\d-]*[a-z\\d])*)\\.)+[a-z]{2,}|'+ // validate domain name
  '((\\d{1,3}\\.){3}\\d{1,3}))'+ // validate OR ip (v4) address
  '(\\:\\d+)?(\\/[-a-z\\d%_.~+]*)*'+ // validate port and path
  '(\\?[;&a-z\\d%_.~+=-]*)?'+ // validate query string
  '(\\#[-a-z\\d_]*)?$','i'); // validate fragment locator
return !!urlPattern.test(urlString);
}

/* GET courses page. */
//show all courses, pass course object to ejs. Can see the comments
router.get('/',async (req,res)=>{
    if(req.session.user&& req.session.user.type=="student"){
        //get all courses and ratings from database
        try {
            await client.connect();
            let courses = await courses_c.find().toArray();
            let buyRecords = await buyRecords_c.find().toArray();
        //convert author names from _id to their username
            let courseauthor_a = courses.map((courses)=>courses.author);
            let coursematch_a = courses.map((courses)=>courses._id);
            console.log("b",coursematch_a)
            for (let i=0;i<courses.length;i++) {
            let courseauthor_b = await courses_u.findOne({_id:new ObjectId(courseauthor_a[i])});

            courses[i].author = courseauthor_b.username;
            }

            //
            let coursematch = [];
            for (let i=0;i<coursematch_a.length;i++) {
                coursematch.push([]);
                let coursematch_b = await buyRecords_c.find({courseId:new ObjectId(coursematch_a[i])}).toArray();
                for(let j=0;j<coursematch_b.length;j++){
                    if(coursematch_b[j].rate) coursematch[i].push(coursematch_b[j].rate);
                    console.log("c",coursematch_b)
                    console.log("a",coursematch)
                }

                
           // console.log("a",courses)
            }
            if(courses) res.render('courses_all',{courses:courses, search:{method:"words",param:""}});
        } finally {
            await client.close();
        }
    }
    else res.redirect('/');
    
}).post('/',async (req,res)=>{
    if(req.session.user && req.session.user.type=="student"){
        let courses_c = client.db('learningPlatform').collection('courses');
        let users_c = client.db('learningPlatform').collection('users');
        let {searchMethod} = req.body;
        try {
            await client.connect();
            if(searchMethod == "words"){
                let {searchWords} = req.body;
                let searchByWords = await courses_c.find({name:{$regex:searchWords}}).toArray();
                for(let i=0; i<searchByWords.length;i++){
                    searchByWords[i].id = searchByWords[i].author;
                    let findAuthorName = await users_c.findOne({_id:searchByWords[i].id});
                    searchByWords[i].author = findAuthorName.username;
                }
                res.render('courses_all',{courses:searchByWords, search:{method:"words",param:searchWords}});
            } else if(searchMethod == "category"){
                let {category} = req.body;
                let searchByCategory;
                if(category=="all") searchByCategory = await courses_c.find().toArray();
                else searchByCategory = await courses_c.find({category:category}).toArray();
                for(let i=0; i<searchByCategory.length;i++){
                    searchByCategory[i].id = searchByCategory[i].author;
                    let findAuthorName = await users_c.findOne({_id:searchByCategory[i].id});
                    searchByCategory[i].author = findAuthorName.username;
                }
                res.render('courses_all',{courses:searchByCategory, search:{method:"category",param:category}});
            } else if(searchMethod == "tutor"){
                let {searchWords} = req.body;
                let searchTutor = await users_c.find({username:{$regex:searchWords}, type:"teacher"}).toArray();
                let authorName = [];
                for(const i of searchTutor) {
                    authorName.push(i._id);
                }
                let searchByAuthorId = await courses_c.find({author:{$in:authorName}}).toArray();
                for(let i=0;i<searchByAuthorId.length;i++){
                    searchByAuthorId[i].id = searchByAuthorId[i].author;
                    let findAuthorName = await users_c.findOne({_id:searchByAuthorId[i].id});
                    searchByAuthorId[i].author = findAuthorName.username;
                }
                res.render('courses_all',{courses:searchByAuthorId, search:{method:"words",param:searchWords}});
            } 
            else res.redirect('/courses');
        } finally {
            await client.close();
        }
    } else res.redirect('/');
}).get('/paid',async (req,res)=>{
    //only students can see the page.  Show the course student attended, pass only the course student attended
    if(req.session.user&& req.session.user.type=="student"){
        let courses=[];
        try{
            await client.connect();
            let buyRecords = await buyRecords_c.find({userId:new ObjectId(req.session.user._id)}).toArray();
            if(buyRecords){
                for (const i of buyRecords){
                let boughtcourses = await courses_c.findOne({_id:i.courseId});
                courses.push(boughtcourses);
            }
                for (let i=0;i<courses.length;i++){
                let courseauthor = await courses_u.findOne({_id:courses[i].author});
                courses[i].author = courseauthor.username;
                }
                res.render('courses_paid',{courses:courses});
                     } else {
                res.render('courses_paid',{courses:[], message:"你沒有任何購買紀錄！"});
            }
    } finally{
            await client.close();
        }
    }
    else res.redirect('/');
}).get('/myCourses',async(req,res)=>{
    //only teachers can see the page.
    if(req.session.user&& req.session.user.type=="teacher"){
                //first, get course paid, then get course detail
        try {
          await client.connect();
          //convert author name from _id to username of the author
          let data = await courses_c.find({author:new ObjectId(req.session.user._id)}).toArray();
          let buyRecords = await buyRecords_c.find().toArray();
          if(data.length>=1){
            let courseauthor = await courses_u.findOne({_id:data[0].author})
            if(courseauthor){
                let authorname = courseauthor.username;
                for (let i=0;i<data.length;i++) {
                data[i].author = authorname;
                }
            }
            res.render("courses_myCourses", {
                courses: data
            });
            } else res.render("courses_myCourses", {
                courses: []
            });
          
        } finally {
          await client.close();
        }
      } else res.redirect("/");
}).get('/myCourses/:courseId',async(req,res)=>{
    const {courseId} = req.params;
    //define edit message
    let msg = req.query.msg;
    if(req.query.msg=="1") msg="更改資料成功";
    else if(req.query.msg=="2") msg="更改資料失敗。請重新嘗試";
    if(req.session.user&& req.session.user.type=="teacher"){
        //only course owner can see the page.  Course owner can edit the data, show the form that allow course owner to edit.  Need edit
        let course, canView=true;
        try {
          await client.connect();
          let data = await courses_c.findOne({_id:new ObjectId(courseId)});
          if (data) {
              res.render("courses_myCourses_edit", {
                course: data,
                courseId:req.params._id,msg:msg
              });
            }
        } finally {
          await client.close();
        }
    }
    else res.redirect('/');
}).post('/myCourses/:courseId',async(req,res)=>{
    const {courseId} = req.params;
    if(req.session.user&& req.session.user.type=="teacher"){
        //rendering details of selected course
        //allow the course to be edit by course owner, handle edited content to database
            try {
            await client.connect();
            let data = await courses_c.findOne({name: req.body.name,
            introduction: req.body.introduction,
            money: req.body.money,
            content: req.body.content,
            whatPeopleLearn: req.body.whatPeopleLearn,
            videoLink: req.body.videoLink,
            photoLink: req.body.photoLink,
            category: req.body.category}
            );
 
            let data1 = await courses_c.updateOne({ _id: new ObjectId(courseId) }, {
                $set: {
            name: req.body.name,
            introduction: req.body.introduction,
            money: req.body.money,
            content: req.body.content,
            whatPeopleLearn: req.body.whatPeopleLearn,
            videoLink: req.body.videoLink,
            photoLink: req.body.photoLink,
            category: req.body.category
                }
          });
        if (data1.matchedCount == 1) {
            res.redirect(`/courses/myCourses/${req.params.courseId}?msg=1`);
        }
        else { 
            res.redirect(`/courses/myCourses/${req.params.courseId}?msg=2`);
        }
    } finally {
    await client.close();
  }}
    else res.redirect('/');
    

}).get('/newCourse',(req,res)=>{
    if(req.session.user&& req.session.user.type=="teacher") {
        let msg="";
        if(req.query.msg==1) msg="新増課程成功";
        else if(req.query.msg==2) msg="新増課程失敗";
        else if(req.query.msg==3) msg+="課程名稱已被使用\n"
        else if(req.query.msg==4) msg+="課程價錢必須為數字\n"
        else if(req.query.msg==5) msg+="圖片連結或影片連結不是正確的連結"
        res.render('courses_newCourse',{
            user: req.session.user,
            msg:msg});
    }
    else res.redirect('/');
}).post('/newCourse',async(req,res)=>{
    if(req.session.user&& req.session.user.type=="teacher"){
        //add course to database
            try {
            await client.connect();
        //check if course name is already used
        let data = {name: req.body.name,
            introduction: req.body.introduction,
            money: req.body.money,
            content: req.body.content,
            whatPeopleLearn: req.body.whatPeopleLearn,
            author: new ObjectId(req.session.user._id),
            videoLink: req.body.videoLink,
            photoLink: req.body.photoLink,
            category: req.body.category
        };
        const existingDocument = await courses_c.findOne({ name: req.body.name });
        if (existingDocument) {
           res.redirect(`/courses/newCourse?msg=3`);
        } else {
            if (!isValidUrl(req.body.videoLink) || !isValidUrl(req.body.photoLink)) {
                res.redirect(`/courses/newCourse?msg=5`);
            } else if (!Number.isInteger(parseInt(req.body.money))) {
            res.redirect(`/courses/newCourse?msg=4`);
        } else {
            let insertData = await courses_c.insertOne(data);
            if(insertData.acknowledged) res.redirect(`/courses/newCourse?msg=1`);
            else res.redirect(`/courses/NewCourse?msg=2`);
        } 
        }
    } finally {
    await client.close();
  }}
    else res.redirect('/');
}).get('/:courseId', async (req, res)=>{
    const {courseId} = req.params;
    let msg="";
    if(req.query.msg==1) msg="評分成功";
    else if(req.query.msg==2) msg="評分失敗";
    else if(req.query.msg==3) msg="評分錯誤";
    if(req.session.user&& req.session.user.type=="student"){
        //get single course detail by course id
        try {
            await client.connect();
            let course = await courses_c.findOne({_id:new ObjectId(courseId)});
            if(courseId.length == 24 && course){
                courseauthor =  await courses_u.findOne({_id:new ObjectId(course.author)}); 
                course.author = courseauthor.username;
            if (!course) {
                    res.send("無法連接到伺服器，請重新嘗試。")
            } else {
                    let userId = new ObjectId(req.session.user._id);
                    let buyRecords = await buyRecords_c.findOne({courseId:course._id, userId:userId});
                    if(buyRecords) res.render('courses_detail',{course:course, paid:true, msg:msg});
                    else res.render('courses_detail',{course:course, paid:false, msg:msg});
                  }
                 } else res.redirect('/');
        }finally {
            await client.close();
        }
    }
    else res.redirect('/');
}).post('/:courseId', async (req, res)=>{
    const {courseId} = req.params;
    if(req.session.user&& req.session.user.type=="student"){
        try {
            await client.connect();
            let data = Number(req.body.rate);
            if (data >=5.1 || data <=-0.1) {
                res.redirect(`/courses/${req.params.courseId}?msg=3`);
            }
            else {
                let updateRecords = await buyRecords_c.updateOne({$and:[{userId:new ObjectId(req.session.user._id)}, {courseId:new ObjectId(courseId)}]},{$set:{rate:data}});
                console.log(updateRecords)
                console.log("userId",new ObjectId(req.session.user._id))
                console.log("course",courseId)
                console.log("data",data)
                console.log("req",req.body.rate)
                if(updateRecords.modifiedCount > 0) res.redirect(`/courses/${req.params.courseId}?msg=1`);
                else res.redirect(`/courses/${req.params.courseId}?msg=2`);
            }
        }finally {
            await client.close();
        }
    }
    else res.redirect('/');
}).get('/:courseId/buy', async(req, res)=>{
    const {courseId} = req.params;
    if(req.session.user&& req.session.user.type=="student"){
    try {
        await client.connect();
        //insert buy record at database. need edit
        let course = await courses_c.findOne({_id:new ObjectId(courseId)});
        let user = await courses_u.findOne({_id:req.session.user._id});
        if (user.money >= course.money) {
            let canBuy = true;
        if (canBuy) {
            let balance = user.money -= course.money;
            await buyRecords_c.insertOne({userId:req.session.user._id, courseId:courseId});
            await courses_u.updateOne({_id:req.session.user._id}, {$set: {money: balance}});
        }
    }
            res.render('courses_detail',{user:req.session.user, course:course});
    } finally {
        await client.close();
    }
}
    else res.redirect('/');
});

module.exports = router;
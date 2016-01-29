/*******************************************************           
* index.js - SuperGnome v.01 (GnomeNet 2015)           *   
*                                                      *   
* Author:  Atnas Dev Team                              *   
*                                                      *   
* Purpose:  Bringing joy to the world...               *   
*                                                      *   
* GNOME MASTER CODE                                    *   
********************************************************/  
var express = require('express');
var router = express.Router();
var sessions = [];
var fs = require('fs');
var disk = require('diskusage');
var path = require('path');
var multer = require('multer');
var upload = multer({ path: '/tmp/' });
var domain = require('domain');
var d = domain.create();
var sha1 = require('sha1');
var secret = 'gnoderules';
var sessionid = -1;

d.on('error', function(e) {
  console.error(e);
});

// make new directory
fs.mknewdir = function(dirPath, mode, callback) {
  fs.mkdir(dirPath, mode, function(error) {
    if (error && error.code === 'ENOENT') {
      fs.mknewdir(path.dirname(dirPath), mode, callback);
      fs.mknewdir(dirPath, mode, callback);
    }
    callback && callback(error);
  });
};

// STUART: (WIP) Image post prcessing module
// This may have currently broken the file uploads (sorry).
function postproc(action, file)
{
  //WIP: image post processing.
  if (action === 'timestamp') {
    console.log('timestamp');
    return "Timestamp processing successful.";
  } else if (action === 'darken50') {
    console.log('d50');
    return "Brightness processing successful.";
  } else if (action === 'darken20') {
    console.log('darken20');
    return "Brightness processing successful.";
  } else if (action === 'brighten50') {
    console.log('b50');
    return "Brightness processing successful.";
  } else if (action === 'brighten20') {
    console.log('b20');
    return "Brightness processing successful.";
  }
}

// make a new random dir to temporarily store uploaded files
function newdir()
{
  var dir  = "";
  var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  for( var i=0; i < 8; i++ )
    dir += chars.charAt(Math.floor(Math.random() * chars.length));
  return dir;
}

// session id generator
function gen_session()
{
  var t_sessionid = '';
  var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  for( var i=0; i < 20; i++ )
    t_sessionid += chars.charAt(Math.floor(Math.random() * chars.length));
  return t_sessionid;
}

// catch all web requests, make sure cookies are in place
router.all('*', function(req, res, next) {
  var db = req.db;
  db.get('status').findOne('',function (err, stats) {
    var logged_out = false;
    res.stats = stats;
    if (req.query.logout && req.cookies.sessionid !== undefined && sessions[req.cookies.sessionid] !== undefined && sessions[req.cookies.sessionid].logged_in === true) {
      delete(sessions[req.cookies.sessionid]);
      res.clearCookie(sessionid);
      logged_out = true;
    }
    if (req.cookies.sessionid === undefined || sessions[req.cookies.sessionid] === undefined || logged_out) {
      sessionid = gen_session();
      sessions[sessionid] = { username: "", logged_in: false, user_level: 0 };
      res.cookie('sessionid', sessionid);
      res.render('index', { title: 'GIYH::ADMIN PORT V.01', session: sessions[sessionid], res: res });
    } else {
      sessionid = req.cookies.sessionid;
      next();
    }
  });
});

// LOGIN POST
router.post('/', function(req, res, next) {
  var db = req.db;
  var msgs = [];
  db.get('users').findOne({username: req.body.username, password: req.body.password}, function (err, user) { // STUART: Removed this in favor of below.  Really guys?
  //db.get('users').findOne({username: (req.body.username || "").toString(10), password: (req.body.password || "").toString(10)}, function (err, user) { // LOUISE: allow passwords longer than 10 chars
    if (err || !user) {
      console.log('Invalid username and password: ' + req.body.username + '/' + req.body.password);
      msgs.push('Invalid username or password!');
      res.msgs = msgs;
      res.render('index', { title: 'GIYH::ADMIN PORT V.01', session: sessions[req.cookies.sessionid], res: res });
    } else {
      sessionid = gen_session();
      sessions[sessionid] = { username: user.username, logged_in: true, user_level: user.user_level };
      console.log("User level:" + user.user_level);
      res.cookie('sessionid', sessionid);
      res.writeHead(301,{ Location: '/' });
      res.end();
    }
  });
});

// SETTINGS UPLOAD
router.post('/settings', function(req, res, next) {
  if (sessions[sessionid].logged_in === true && sessions[sessionid].user_level > 99) { // AUGGIE: settings upload allowed for admins (admins are 100, currently)
    var filen = req.body.filen;
    var dirname = '/gnome/www/public/upload/' + newdir() + '/' + filen;
    var msgs = [];
    var free = 0;
    disk.check('/', function(e, info) {
      free = info.free;
    });
    try {
      fs.mknewdir(dirname.substr(0,dirname.lastIndexOf('/')));
      msgs.push('Dir ' + dirname.substr(0,dirname.lastIndexOf('/')) + '/ created successfully!');
    } catch(e) {
      if (e.code != 'EEXIST')
	throw e;
    }
    if (free < 99999999999) { // AUGGIE: I think this is breaking uploads?  Stuart why did you set this so high?
      msgs.push('Insufficient space!  File creation error!');
    }
    res.msgs = msgs;
    next();
  } else
    res.render('index', { title: 'GIYH::ADMIN PORT V.01', session: sessions[sessionid], res: res });
});

// FILES UPLOAD
router.post('/files', upload.single('file'), function(req, res, next) {
  if (sessions[sessionid].logged_in === true && sessions[sessionid].user_level > 99) { // NEDFORD: this should be 99 not 100 so admins can upload
    var msgs = [];
    file = req.file.buffer;
    if (req.file.mimetype === 'image/png') {
      msgs.push('Upload successful.');
      var postproc_syntax = req.body.postproc;
      console.log("File upload syntax:" + postproc_syntax);
      if (postproc_syntax != 'none' && postproc_syntax !== undefined) {
        msgs.push('Executing post process...');
        var result;
        d.run(function() {
          result = eval('(' + postproc_syntax + ')');
        });
        // STUART: (WIP) working to improve image uploads to do some post processing.
        msgs.push('Post process result: ' + result);
      }
      msgs.push('File pending super-admin approval.');
      res.msgs = msgs;
    } else {
      msgs.push('File not one of the approved formats: .png');
      res.msgs = msgs;
    }
  } else
    res.render('index', { title: 'GIYH::ADMIN PORT V.01', session: sessions[sessionid], res: res });
  next();
});

// CAMERA VIEWER
// STUART: Note: to limit disclosure issues, this code checks to make sure the user asked for a .png file
router.get('/cam', function(req, res, next) {
  var camera = unescape(req.query.camera);
  // check for .png
  //if (camera.indexOf('.png') == -1) // STUART: Removing this...I think this is a better solution... right?
  camera = camera + '.png'; // add .png if its not found
  console.log("Cam:" + camera);
  fs.access('./public/images/' + camera, fs.F_OK | fs.R_OK, function(e) {
    if (e) {
	    res.end('File ./public/images/' + camera + ' does not exist or access denied!');
    }
  });
  fs.readFile('./public/images/' + camera, function (e, data) {
    res.end(data);
  });
});

// FILES VIEWER
router.all('/files', function(req, res, next) {
  if (sessions[sessionid].logged_in === true) {
    var file_names = fs.readdirSync('./files');
    var files = [];
    for (var i = 0; i < file_names.length; i ++) {
      var stats = fs.statSync('./files/' + file_names[i]);
      files.push({'name': file_names[i], 'size': stats['size']});
    }
    res.files = files;
    var download = false;
    if (sessions[sessionid].logged_in === true) {
      var d = req.query.d;
      if (d !== undefined) {
        download = true;
        if (file_names.indexOf(d) !== -1) { 
          fs.readFile('./files/' + d, function(err, data) {
            res.end(data);
          });
        }
        else {
          if (res.msgs === undefined)
            res.msgs = [];
          res.msgs.push('File not found or access denied!');
          download = false;
        }
      }
    }
    if (!download) {
      res.render('files', { title: 'GIYH::ADMIN PORT V.01', session: sessions[sessionid], res: res });
    }
  } else
    res.render('index', { title: 'GIYH::ADMIN PORT V.01', session: sessions[sessionid], res: res });
});

// INDEX
router.get('/', function(req, res, next) {
  res.render('index', { title: 'GIYH::ADMIN PORT V.01', session: sessions[sessionid], res: res });
});

// GNOMENET VIEWER
router.get('/gnomenet', function(req, res, next) {
  if (sessions[sessionid].logged_in === true) {
    var db = req.db;
    db.get('gnomenet').find({},{ sort:[['id','asc']] }, function (err, gmessages) {
      res.gmessages = gmessages;
      res.render('gnomenet', { title: 'GIYH::ADMIN PORT V.01', session: sessions[sessionid], res: res });
    });
  } else
    res.render('index', { title: 'GIYH::ADMIN PORT V.01', session: sessions[sessionid], res: res });
});

// SETTINGS VIEWER
router.all('/settings', function(req, res, next) {
  if (sessions[sessionid].logged_in === true) {
    var db = req.db;
    db.get('settings').find({}, function (err, settings) {
      res.settings = settings;
      res.render('settings', { title: 'GIYH::ADMIN PORT V.01', session: sessions[sessionid], res: res });
    });
  } else
    res.render('index', { title: 'GIYH::ADMIN PORT V.01', session: sessions[sessionid], res: res });
});

// CAMERAS VIEWER
router.get('/cameras', function(req, res, next) {
  if (sessions[sessionid].logged_in === true) {
    var msgs = []
    var db = req.db;
    var page = 1;
    if (!isNaN(req.query.p) && req.query.p > 0 && req.query.p < 333335)
      page = req.query.p;
    if (page > 2 && sessions[sessionid].user_level < 1000) {
      // limit camera feed viewing to 12 feeds, this should be enough for the admins to verify connectivity and things are working
      // there is no reason for them to see beyond 12 feeds... there is absolutely nothing for them to gain.
      page = 2;
      msgs.push('Leave camera feed analysis to the burglers.  12 feeds should be enough to see that the cameras are working.');
      msgs.push('Trust us.  There is nothing but 1.99 million more living rooms after this page.');
      msgs.push('We\'ve checked.');
      res.msgs = msgs;
    }
    res.page = page;
    db.get('cameras').find({},{limit:6, skip:6*(page-1)}, function (err, cameras) {
      res.cameras = cameras;
      res.render('cameras', { title: 'GIYH::ADMIN PORT V.01', session: sessions[sessionid], res: res });
    });
  } else
    res.render('index', { title: 'GIYH::ADMIN PORT V.01', session: sessions[sessionid], res: res });
});

module.exports = router;

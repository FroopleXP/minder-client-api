// Requiring dependencies
var express = require('express');
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var expressSession = require('express-session');
var moment = require('moment');
var db = require('./mysql_conn.js');
var crypto = require('crypto');

// CSURF CSRF Protection
var csurf = require('csurf');

// Moment.js
moment().format();

// Cleaning tools
var xssFilters = require('xss-filters'),
    validator = require('validator');

// Cleaning settings
var vali_str_opt = {
    min: 5,
    max: 100
}

var app = express();
var port = process.env.PORT || 80;

// Requiring passport
var passport = require('passport');
var passportLocal = require('passport-local');

// Setting the renderer
app.set('view engine', 'ejs');

app.use("/views", express.static(__dirname + '/views'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(expressSession({ secret: 'casiodaemon',  resave: true, saveUninitialized: true }));

// Setting up Passport
app.use(passport.initialize());
app.use(passport.session());

passport.use(new passportLocal.Strategy(function(email, password, done) {
    db.query('SELECT * FROM admin_users WHERE admin_users.email = ?', email, function(err, rows, fields) {
        if (err) { return done(err); } // There was an error
        if (rows.length < 1) { // No user
            return done(null, false, {message: 'User not found!'});
        } else if (rows.length > 0) { // There's a user

            // Getting the data
            var email_db = rows[0]['email'],
                password_db = rows[0]['password'];

            // Checking the credentials
            if (email !== email_db) { // Email is not correct
                return done(null, false, {message: 'Invalid Email'});
            } else if (password !== password_db) { // Password is not correct
                return done(null, false, {message: 'Invalid Password'});
            } else {
                // Validation success, create the user model
                var user_model = {
                    id: rows[0]['id'],
                    firstname: rows[0]['fname'],
                    lastname: rows[0]['lname'],
                    full_name: rows[0]['full_name'],
                    email: rows[0]['email'],
                    estab_id: rows[0]['estab_belongs_to']
                }
                // Returning
                return done(null, user_model);
            }
        }
    });
}));

passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    db.query('SELECT * FROM admin_users WHERE admin_users.id = ?', id, function(err, rows, fields) {
        if (err) { return done(err); } // There was an error
        if (rows.length < 1) { // No user
            done(null, null);
        } else if (rows.length > 0) { // There's a user
            // Validation success, create the user model
            var user_model = {
                id: rows[0]['id'],
                firstname: rows[0]['fname'],
                lastname: rows[0]['lname'],
                full_name: rows[0]['full_name'],
                email: rows[0]['email'],
                estab_id: rows[0]['estab_belongs_to']
            }
            // Returning
            done(null, user_model);
        }
    });
});

// Custom middleware for checking that User is logged in to use the API
function ensureAuthenticationAPI(req, res, next) {
    if (req.isAuthenticated()) {
        next();
    } else if (!req.isAuthenticated()) {
        res.sendStatus(403);
    }
}
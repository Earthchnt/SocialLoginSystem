const express = require('express');
const passport = require('passport');
const LocalStrategy = require('passport-local');
const crypto = require('crypto');
const GoogleStrategy = require('passport-google-oidc');
const FacebookStrategy = require('passport-facebook');
const db = require('../db');
const router = express.Router();

passport.use(new LocalStrategy(function verify(username, password, cb) {
    db.get('SELECT * FROM users WHERE username = ?', [username], function (err, row) {
        if (err) { return cb(err); }
        if (!row) { return cb(null, false, { message: 'Incorrect username or password.' }); }

        crypto.pbkdf2(password, row.salt, 310000, 32, 'sha256', function (err, hashedPassword) {
            if (err) { return cb(err); }
            if (!crypto.timingSafeEqual(row.hashed_password, hashedPassword)) {
                return cb(null, false, { message: 'Incorrect username or password.' });
            }
            return cb(null, row);
        });
    });
}));

passport.use(new GoogleStrategy({
    clientID: process.env['GOOGLE_CLIENT_ID'],
    clientSecret: process.env['GOOGLE_CLIENT_SECRET'],
    callbackURL: '/oauth2/redirect/google',
    scope: ['profile']
}, function verify(issuer, profile, cb) {
    db.get('SELECT * FROM federated_credentials WHERE provider = ? AND subject = ?', [
        issuer,
        profile.id
    ], function (err, row) {
        if (err) { return cb(err); }
        if (!row) {
            db.run('INSERT INTO users (name) VALUES (?)', [
                profile.displayName
            ], function (err) {
                if (err) { return cb(err); }

                const id = this.lastID;
                db.run('INSERT INTO federated_credentials (user_id, provider, subject) VALUES (?, ?, ?)', [
                    id,
                    issuer,
                    profile.id
                ], function (err) {
                    if (err) { return cb(err); }
                    const user = {
                        id: id,
                        name: profile.displayName
                    };
                    return cb(null, user);
                });
            });
        } else {
            db.get('SELECT * FROM users WHERE id = ?', [row.user_id], function (err, row) {
                if (err) { return cb(err); }
                if (!row) { return cb(null, false); }
                return cb(null, row);
            });
        }
    });
}));

passport.use(new FacebookStrategy({
    clientID: process.env['FACEBOOK_CLIENT_ID'],
    clientSecret: process.env['FACEBOOK_CLIENT_SECRET'],
    callbackURL: '/oauth2/redirect/facebook',
    state: true
}, function verify(accessToken, refreshToken, profile, cb) {
    db.get('SELECT * FROM federated_credentials WHERE provider = ? AND subject = ?', [
        'https://www.facebook.com',
        profile.id
    ], function (err, row) {
        if (err) { return cb(err); }
        if (!row) {
            db.run('INSERT INTO users (name) VALUES (?)', [
                profile.displayName
            ], function (err) {
                if (err) { return cb(err); }

                const id = this.lastID;
                db.run('INSERT INTO federated_credentials (user_id, provider, subject) VALUES (?, ?, ?)', [
                    id,
                    'https://www.facebook.com',
                    profile.id
                ], function (err) {
                    if (err) { return cb(err); }
                    const user = {
                        id: id,
                        name: profile.displayName
                    };
                    return cb(null, user);
                });
            });
        } else {
            db.get('SELECT * FROM users WHERE id = ?', [row.user_id], function (err, row) {
                if (err) { return cb(err); }
                if (!row) { return cb(null, false); }
                return cb(null, row);
            });
        }
    });
}));

passport.serializeUser(function (user, cb) {
    process.nextTick(function () {
        cb(null, { id: user.id, username: user.username, name: user.name || null });
    });
});

passport.deserializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, user);
    });
});

router.get('/login', function (req, res, next) {
    res.render('login');
});

router.post('/login/password', passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login'
}));


router.get('/login/federated/google', passport.authenticate('google'));

router.get('/oauth2/redirect/google', passport.authenticate('google', {
    successRedirect: '/',
    failureRedirect: '/login'
}));

router.get('/login/federated/facebook', passport.authenticate('facebook'));

router.get('/oauth2/redirect/facebook', passport.authenticate('facebook', {
    successRedirect: '/',
    failureRedirect: '/login'
}));

router.post('/logout', function (req, res, next) {
    req.logout(function (err) {
        if (err) { return next(err); }
        res.redirect('/');
    });
});

router.get('/signup', function (req, res, next) {
    res.render('signup');
});

router.post('/signup', function (req, res, next) {
    const salt = crypto.randomBytes(16);
    crypto.pbkdf2(req.body.password, salt, 310000, 32, 'sha256', function (err, hashedPassword) {
        if (err) { return next(err); }
        db.run('INSERT INTO users (username, hashed_password, salt) VALUES (?, ?, ?)', [
            req.body.username,
            hashedPassword,
            salt
        ], function (err) {
            if (err) { return next(err); }
            const user = {
                id: this.lastID,
                username: req.body.username
            };
            req.login(user, function (err) {
                if (err) { return next(err); }
                res.redirect('/');
            });
        });
    });
});

module.exports = router;
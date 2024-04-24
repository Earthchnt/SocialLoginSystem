const express = require('express');
const router = express.Router();

/* GET home page. */
router.get('/', function (req, res) {
  if (!req.user) { return res.render('home'); }
  res.render('index', { user: req.user });
});

module.exports = router;
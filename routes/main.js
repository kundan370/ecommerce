var router = require('express').Router();

router.get('/',function (req,res) {
  res.render('main/home');
});

router.get('/about',function (req,res) {
  res.render('main/abouts');
});

module.exports = router;

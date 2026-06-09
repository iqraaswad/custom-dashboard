const express = require('express');
const router = express.Router();

router.get('/login', (req, res) => {
  if (req.session.authenticated) return res.redirect('/');
  res.render('login', { title: 'Login', error: null, path: '/login', layout: false });
});

router.post('/login', (req, res) => {
  const { username, password } = req.body;
  const configUser = process.env.DASHBOARD_USER || 'admin';
  const configPass = process.env.DASHBOARD_PASS || 'admin';

  if (username === configUser && password === configPass) {
    req.session.authenticated = true;
    req.session.user = username;
    return res.redirect('/');
  }
  res.render('login', { title: 'Login', error: 'Invalid credentials', path: '/login', layout: false });
});

router.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

module.exports = router;

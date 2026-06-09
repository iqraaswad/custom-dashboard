require('dotenv').config();

const express = require('express');
const session = require('express-session');
const path = require('path');
const ejsLayouts = require('express-ejs-layouts');

const indexRoutes = require('./routes/index');
const authRoutes = require('./routes/auth');

const app = express();
const PORT = process.env.PORT || 3000;
const BASE_PATH = process.env.BASE_PATH || '';

app.locals.basePath = BASE_PATH;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.set('layout', 'layout');
app.use(ejsLayouts);

app.use(BASE_PATH, express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
  secret: process.env.SESSION_SECRET || 'fallback-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 8 * 60 * 60 * 1000 }
}));

app.use((req, res, next) => {
  res.locals.authenticated = req.session.authenticated || false;
  res.locals.user = req.session.user || null;
  res.locals.currentPath = req.path;
  next();
});

app.use(BASE_PATH, authRoutes);
app.use(BASE_PATH, indexRoutes);

app.use((req, res) => {
  res.status(404).render('error', { title: '404', message: 'Page not found', path: '' });
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).render('error', { title: 'Error', message: 'Internal server error', path: '' });
});

app.listen(PORT, () => {
  console.log(`Wazuh Dashboard running at http://localhost:${PORT}${BASE_PATH}`);
});

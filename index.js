const express = require('express');
const passport = require('passport');
const session = require('express-session');
const bodyParser = require('body-parser');
const config = require('./config');
const fs = require('fs');

const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: 'your-secret-key', resave: true, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());

const usersData = JSON.parse(fs.readFileSync('./users.json', 'utf-8'));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  const user = usersData.find((user) => user.id === id);
  done(null, user);
});

const LocalStrategy = require('passport-local').Strategy;

passport.use(
  new LocalStrategy((username, password, done) => {
    const user = usersData.find((user) => user.username === username);
    if (!user) {
      return done(null, false, { message: 'Incorrect username.' });
    }
    if (user.password !== password) {
      return done(null, false, { message: 'Incorrect password.' });
    }
    return done(null, user);
  })
);

app.get('/login', (req, res) => {
  let style = ''; // Default style

  if (config.styleMode === 2) {
    // Dark style
    style = `
      body {
        font-family: Arial, sans-serif;
        background-color: #000;
        color: #fff;
      }
      .container {
        max-width: 400px;
        margin: 0 auto;
        padding: 20px;
        background-color: #333;
        border-radius: 5px;
        box-shadow: 0px 0px 5px 0px #666;
      }
      h1 {
        text-align: center;
      }
      form {
        text-align: center;
      }
      input[type="text"],
      input[type="password"] {
        width: 100%;
        padding: 10px;
        margin: 5px 0;
        background-color: #444;
        border: none;
        border-radius: 3px;
        color: #fff;
      }
      input[type="submit"] {
        width: 100%;
        padding: 10px;
        background-color: #007BFF;
        border: none;
        color: #fff;
        border-radius: 3px;
        cursor: pointer;
      }
      input[type="submit"]:hover {
        background-color: #0056b3;
      }
    `;
  } else if (config.styleMode === 3) {
    // Light style
    style = `
      body {
        font-family: Arial, sans-serif;
        background-color: #fff; /* Background is white */
        color: #333; /* Text color is dark gray */
      }
      .container {
        max-width: 400px;
        margin: 0 auto;
        padding: 20px;
        background-color: #f7f7f7; /* Container background is light gray */
        border-radius: 5px;
        box-shadow: 0px 0px 5px 0px #ccc;
      }
      h1 {
        text-align: center;
        color: #333; /* Heading color is dark gray */
      }
      form {
        text-align: center;
      }
      input[type="text"],
      input[type="password"] {
        width: 100%;
        padding: 10px;
        margin: 5px 0;
        border: 1px solid #ccc;
        border-radius: 3px;
      }
      input[type="submit"] {
        width: 100%;
        padding: 10px;
        background-color: #007BFF;
        border: none;
        color: #fff;
        border-radius: 3px;
        cursor: pointer;
      }
      input[type="submit"]:hover {
        background-color: #0056b3;
      }
    `;
  }

  res.send(`
    <html>
      <head>
        <title>${config.loginPageTitle}</title>
        <style>
          ${style}
        </style>
      </head>
      <body>
        <div class="container">
          <h1>${config.loginPageTitle}</h1>
          <form method="POST" action="/login">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username"><br>
            <label for="password">Password:</label>
            <input type="password" id="password" name="password"><br>
            <input type="submit" value="Login">
          </form>
        </div>
      </body>
    </html>
  `);
});



app.post(
  '/login',
  passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login',
  })
);

app.get('/dashboard', isAuthenticated, (req, res) => {
  let style = ''; // Default style

  if (config.styleMode === 2) {
    // Dark style
    style = `
      body {
        font-family: Arial, sans-serif;
        background-color: #000;
        color: #fff;
      }
      .container {
        max-width: 400px;
        margin: 0 auto;
        padding: 20px;
        background-color: #333;
        border-radius: 5px;
        box-shadow: 0px 0px 5px 0px #666;
      }
      h1 {
        text-align: center;
      }
      a {
        display: block;
        text-align: center;
        margin-top: 20px;
        background-color: #007BFF;
        color: #fff;
        padding: 10px;
        text-decoration: none;
        border-radius: 3px;
      }
      a:hover {
        background-color: #0056b3;
      }
    `;
  } else if (config.styleMode === 3) {
    // Light style
    style = `
      body {
        font-family: Arial, sans-serif;
        background-color: #f7f7f7;
      }
      .container {
        max-width: 400px;
        margin: 0 auto;
        padding: 20px;
        background-color: #fff;
        border-radius: 5px;
        box-shadow: 0px 0px 5px 0px #ccc;
      }
      h1 {
        text-align: center;
      }
      a {
        display: block;
        text-align: center;
        margin-top: 20px;
        background-color: #007BFF;
        color: #fff;
        padding: 10px;
        text-decoration: none;
        border-radius: 3px;
      }
      a:hover {
        background-color: #0056b3;
      }
    `;
  }

  res.send(`
    <html>
      <head>
        <title>Dashboard</title>
        <style>
          ${style}
        </style>
      </head>
      <body>
        <div class="container">
          <h1>Welcome, ${req.user.username}!</h1>
          <a href="/logout">Logout</a>
        </div>
      </body>
    </html>
  `);
});




app.get('/logout', (req, res) => {
  req.logout(() => {}); // Add an empty callback function here
  res.redirect('/login');
});


function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
}

const PORT = config.port;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
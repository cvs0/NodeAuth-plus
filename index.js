// TODO: Fix the HTML page to show the error messages.
// TODO: More settings.
// TODO: Fix the SSL too long error.


const express = require('express');
const passport = require('passport');
const session = require('express-session');
const { check, validationResult } = require('express-validator');
const bodyParser = require('body-parser');
const config = require('./config');
const fs = require('fs');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const LocalStrategy = require('passport-local').Strategy;
const usersDataJson = require('./users.json');
const { Html5Entities } = require('html-entities');

const app = express();

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});

app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  next();
});

app.use('/api/', limiter);

app.use(helmet({
  referrerPolicy: {
    policy: 'same-origin'
  },

  strictTransportSecurity: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },

  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", 'trusted-cdn.com'],
    },
  },

  frameguard: {
    action: 'deny'
  },

  contentTypeOptions: {
    nosniff: true
  },

  permittedCrossDomainPolicies: {
    permittedPolicies: 'none',
  },

  expectCt: {
    enforce: true,
    maxAge: 30,
  }
}));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: config.sessionSecret, resave: true, saveUninitialized: true }));
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

passport.use(
  new LocalStrategy({ usernameField: 'username' }, (username, password, done) => {
    const user = usersData.find((user) => user.username === username);
    
    if (!user) {
      return done(null, false, { message: 'Invalid credentials.' });
    }

    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) {
        return done(err);
      }

      if (!isMatch) {
        setTimeout(() => done(null, false, { message: 'Invalid credentials.' }), 1000);
        return;
      }

      return done(null, user);
    });
  })
);


app.get('/register', (req, res) => {
  if (config.registration) {
    let style = '';

    if (config.styleMode === 2) {
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

    const num1 = Math.floor(Math.random() * 10) + 1;
    const num2 = Math.floor(Math.random() * 10) + 1;
    const answer = num1 + num2;

    res.send(`
      <html>
        <head>
          <title>Registration</title>
          <style>
            ${style}
          </style>
        </head>
        <body>
          <div class="container">
            <h1>Register</h1>
            <form method="POST" action="/register">
              <label for="username">Username:</label>
              <input type="text" id="username" name="username" required><br>
              <label for="password">Password:</label>
              <input type="password" id="password" name="password" required><br>
              <!-- Math CAPTCHA input -->
              <label for="captcha">Math CAPTCHA: ${num1} + ${num2} = ?</label>
              <input type="number" id="captcha" name="captcha" required>
              <input type="hidden" name="captchaAnswer" value="${answer}">
              <input type="submit" value="Register">
            </form>
          </div>
        </body>
      </html>
    `);
  } else {
    let style = '';

    if (config.styleMode === 2) {
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
        p {
          text-align: center;
          color: #fff;
          margin-top: 10px; /* Adjust as needed */
        }
      `;
    } else if (config.styleMode === 3) {
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
        p {
          text-align: center;
          color: #333;
          margin-top: 10px; /* Adjust as needed */
        }
      `;
    }

    res.send(`
      <html>
        <head>
          <title>Registration Disabled</title>
          <style>
            ${style}
          </style>
        </head>
        <body>
          <div class="container">
            <h1>Registration is Disabled</h1>
            <p>Sorry, registration is currently disabled.</p>
          </div>
        </body>
      </html>
    `);
  }
});





app.get('/login', (req, res) => {
  let style = '';
  let errorMessage = '';

  if (config.styleMode === 2) {
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
      /* Style for the "Don't have an account?" text */
      p {
        text-align: center;
        color: #fff;
        margin-top: 10px; /* Adjust as needed */
      }
      a {
        color: #007BFF;
        text-decoration: none;
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
      /* Style for the "Don't have an account?" text */
      p {
        text-align: center;
        color: #333;
        margin-top: 10px; /* Adjust as needed */
      }
      a {
        color: #007BFF;
        text-decoration: none;
      }
    `;
  }

  if (req.query.error) {
    errorMessage = '<p style="color: red;">Invalid username or password.</p>';
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
          <!-- Display the error message if present -->
          ${errorMessage}
          <form method="POST" action="/login">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username"><br>
            <label for="password">Password:</label>
            <input type="password" id="password" name="password"><br>
            <input type="submit" value="Login">
          </form>
          <!-- Apply styles to the "Don't have an account?" text -->
          <p>Don't have an account? <a href="/register">Register here</a></p>
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


app.post('/register', async (req, res) => {
  const { username, password, captcha, captchaAnswer } = req.body;

  const captchaValue = parseInt(captcha);
  const userAnswer = parseInt(captchaAnswer);

  if (isNaN(captchaValue) || isNaN(userAnswer)) {
    return res.send('Invalid CAPTCHA input. Please enter a valid number.');
  }

  if (captchaValue !== userAnswer) {
    return res.send('Math CAPTCHA validation failed. Please try again.');
  }

  if (!isValidPassword(password)) {
    return res.send('Invalid password. Password must meet the requirements.');
  }

  const userExists = usersData.some((user) => user.username === username);

  if (userExists) {
    return res.send('Username already exists. Please choose another.');
  }

  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) {
      return res.status(500).send('Error hashing password');
    }

    const newUser = {
      id: usersData.length + 1,
      username,
      password: hashedPassword,
    };

    usersData.push(newUser);

    fs.writeFileSync('./users.json', JSON.stringify(usersData, null, 2), 'utf-8');

    if(config.actionConsoleInfo) {
      if(config.showIpsInOutput) {
        console.log(config.consoleTag, ' New user created: ' + newUser.username, ' |  from IP: ' + req.ip);
      } else {
        console.log(config.consoleTag, ' New user created: ' + newUser.username);
      }
    }
    

    res.redirect('/login');
  });
});


function isValidPassword(password) {
  if(config.strictPasswordsLevel == 1) {
    const minLength = 1;

    if(password.length < minLength) {
      return false;
    }

    return true;
  }

  if(config.strictPasswordsLevel == 2) {
    const minLength = 8;

    if(password.length < minLength) {
      return false;
    }

    return true;
  }

  if(config.strictPasswordsLevel == 3) {
    const minLength = 8;
    const uppercaseRegex = /[A-Z]/;
    const lowercaseRegex = /[a-z]/;
    const digitRegex = /[0-9]/;
    const specialCharRegex = /[!@#$%^&*()_+]/;

    if (password.length < minLength) {
      return false;
    }

    if (!uppercaseRegex.test(password)) {
      return false;
    }

    if (!lowercaseRegex.test(password)) {
      return false;
    }

    if (!digitRegex.test(password)) {
      return false;
    }

    if (!specialCharRegex.test(password)) {
      return false;
    }

    return true;
  }

  else {
    return true;
  }
}


app.get('/dashboard', isAuthenticated, (req, res) => {
  let style = '';

  if (config.styleMode === 2) {
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

app.get('/', (req, res) => {
  if(isAuthenticated) {
    res.redirect('/dashboard');
  } else {
    res.redirect('/login');
  }
});


app.get('/logout', (req, res) => {
  if(config.actionConsoleInfo) {
    if(config.showIpsInOutput) {
      console.log(config.consoleTag, ' User : ' + req.user.username + 'Logged out from IP: '+ req.ip);
    } else {
      console.log(config.consoleTag, ' User : ' + req.user.username + 'Logged out');
    }
  }

  req.logout(() => {});
  res.redirect('/login');
});


function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
}

const server = app.listen(config.port, config.host, () => {
  console.log(config.consoleTag, ` Server is running on ${config.host}:${config.port}`);
});
const express = require('express');
const passport = require('passport');
const session = require('express-session');
const bodyParser = require('body-parser');
const flash = require('express-flash');
const config = require('./config');
const fs = require('fs');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const LocalStrategy = require('passport-local').Strategy;
const path = require('path');
const { exec } = require('child_process');
const os = require('os');

const app = express();

// Define data directory
const dataDirectory = path.join(__dirname, 'data');

// Read and parse the blacklist data
const rawdata = fs.readFileSync(path.join(dataDirectory, 'blacklisted-ips.json'));
const blacklistData = JSON.parse(rawdata);
const blacklist = blacklistData.blacklist;

// Rate limiting configuration
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
});

// File paths
const blacklistedIPsFilePath = path.join(dataDirectory, 'blacklisted-ips.json');
const usersFilePath = path.join(dataDirectory, 'users.json');


// Function to create an empty JSON file with the specified file path
function createEmptyJSONFile(filePath) {
  const emptyArray = [];
  
  // Write an empty JSON array to the file
  fs.writeFileSync(filePath, JSON.stringify(emptyArray, null, 2), 'utf-8');
}

// Check if the blacklisted IPs file doesn't exist
if (!fs.existsSync(blacklistedIPsFilePath)) {
  // If it doesn't exist, create an empty JSON file
  createEmptyJSONFile(blacklistedIPsFilePath);

  // Log a message indicating that the file was created
  console.log('blacklisted-ips.json created.');
}

// Check if the users file doesn't exist
if (!fs.existsSync(usersFilePath)) {
  // If it doesn't exist, create an empty JSON file
  createEmptyJSONFile(usersFilePath);

  // Log a message indicating that the file was created
  console.log('users.json created.');
}


app.use((req, res, next) => {
  // Set cache control headers to prevent caching
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');

  // Prevent MIME type sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');

  // Get the client's IP address
  const clientIP = req.ip;

  // Check if the client's IP is blacklisted
  if (blacklist.includes(clientIP)) {
    return res.status(403).send('Your IP address is blacklisted.');
  }

  // If the IP is not blacklisted, proceed to the next middleware
  next();
});


app.use((err, req, res, next) => {
  const timestamp = new Date().toISOString();
  console.error(`[${timestamp}] Error:`, err.stack);

  res.status(500).json({ error: 'Something went wrong!' });
});


app.use('/api/', limiter);

app.use(helmet({
  referrerPolicy: {
    policy: 'same-origin',
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
    action: 'deny',
  },

  contentTypeOptions: {
    nosniff: true,
  },

  permittedCrossDomainPolicies: {
    permittedPolicies: 'none',
  },
  
  expectCt: {
    enforce: true,
    maxAge: 30,
  },
}));

app.use(bodyParser.urlencoded({ extended: true }));

app.use(
  session({
    secret: config.sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: config.sessionTimeout,
      secure: true,
      httpOnly: true,
      sameSite: 'strict',
    },
    store: new MongoStore({ mongooseConnection: yourMongooseConnection }), // If using MongoDB for session storage
  })
);

app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

const usersData = JSON.parse(fs.readFileSync(usersFilePath, 'utf-8'));

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
        return done(null, false, { message: 'Invalid credentials.' });
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

  if(config.registration) {
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
  } else {
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
        </div>
      </body>
    </html>
  `);
  }  
});

app.post(
  '/login',
  (req, res, next) => {
    if (req.isAuthenticated()) {
      return res.redirect('/dashboard');
    }
    next();
  },

  passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login',
    failureFlash: true,
  })
);

app.post('/register', async (req, res) => {
  // Extract user input from the request
  const { username, password, captcha, captchaAnswer } = req.body;
  
  // Convert CAPTCHA values to integers
  const captchaValue = parseInt(captcha);
  const userAnswer = parseInt(captchaAnswer);

  // Check if CAPTCHA values are valid integers
  if (isNaN(captchaValue) || isNaN(userAnswer)) {
    return res.send('Invalid CAPTCHA input. Please enter a valid number.');
  }

  // Validate CAPTCHA answer
  if (captchaValue !== userAnswer) {
    return res.send('Math CAPTCHA validation failed. Please try again.');
  }

  // Validate password against requirements
  if (!isValidPassword(password)) {
    return res.send('Invalid password. Password must meet the requirements.');
  }

  // Check if the username already exists
  const userExists = usersData.some((user) => user.username === username);

  if (userExists) {
    return res.send('Username already exists. Please choose another.');
  }

  // Generate a salt for password hashing
  bcrypt.genSalt(10, (saltError, salt) => {
    if (saltError) {
      return res.status(500).send('Error generating salt');
    }

    // Hash the password with the generated salt
    bcrypt.hash(password, salt, (hashError, hashedPassword) => {
      if (hashError) {
        return res.status(500).send('Error hashing password');
      }

      // Create a new user object
      const newUser = {
        id: usersData.length + 1,
        username,
        password: hashedPassword,
      };

      // Add the new user to the data
      usersData.push(newUser);

      // Write the updated user data to a file
      const userDataPath = path.join(__dirname, 'data', 'users.json');
      fs.writeFileSync(userDataPath, JSON.stringify(usersData, null, 2), 'utf-8');

      // Log the new user creation if configured
      if (config.actionConsoleInfo) {
        if (config.showIpsInOutput) {
          console.log(config.consoleTag, 'New user created: ' + newUser.username, ' |  from IP: ' + req.ip);
        } else {
          console.log(config.consoleTag, 'New user created: ' + newUser.username);
        }
      }

      // Redirect to the login page after successful registration
      res.redirect('/login');
    });
  });
});


function isValidPassword(password) {
  switch (config.strictPasswordsLevel) {
    case 1:
      // Password must have at least 1 character
      return password.length >= 1;
    case 2:
      // Password must have at least 8 characters
      return password.length >= 8;
    case 3:
      // Password requirements for level 3
      const minLength = 8;
      const uppercaseRegex = /[A-Z]/; // Requires at least one uppercase letter
      const lowercaseRegex = /[a-z]/; // Requires at least one lowercase letter
      const digitRegex = /[0-9]/;     // Requires at least one digit
      const specialCharRegex = /[!@#$%^&*()_+]/; // Requires at least one special character

      // Check if the password meets all requirements
      return (
        password.length >= minLength &&
        uppercaseRegex.test(password) &&
        lowercaseRegex.test(password) &&
        digitRegex.test(password) &&
        specialCharRegex.test(password)
      );
    default:
      // Default behavior when strictPasswordsLevel is undefined or an unsupported value
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

// Handle the root route
app.get('/', (req, res) => {
  // Check if the user is authenticated using the 'isAuthenticated' middleware
  if (isAuthenticated) {
    // Extend the session's lifetime and redirect to the dashboard
    req.session.touch();
    res.redirect('/dashboard');
  } else {
    // If not authenticated, redirect to the login page
    res.redirect('/login');
  }
});


// Handle user logout
app.get('/logout', (req, res) => {
  // Check if the user is authenticated
  if (req.isAuthenticated()) {
    if (config.actionConsoleInfo) {
      // Log user information and IP if configured to do so
      const userInfo = req.user ? `User: ${req.user.username}` : 'Unknown User';
      const ipInfo = config.showIpsInOutput ? `from IP: ${req.ip}` : '';

      console.log(`${config.consoleTag} ${userInfo} Logged out ${ipInfo}`);
    }

    // Regenerate the session to log the user out
    req.session.regenerate((err) => {
      if (err) {
        console.error('Error regenerating session:', err);
      }

      // Redirect to the login page after logout
      res.redirect('/login');
    });
  } else {
    // If not authenticated, redirect to the login page
    res.redirect('/login');
  }
});

// Middleware to check if the user is authenticated
function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }

  // Redirect to the login page with an error message if not authenticated
  req.flash('error', 'You must be logged in to access this page.');
  res.redirect('/login');
}


// Start the server and listen on the specified host and port
const server = app.listen(config.port, config.host, (err) => {
  if (err) {
    // Handle server start error and log it
    console.error(`${config.consoleTag} Server start error: ${err}`);
  } else {
    // Server started successfully, log the server's address
    console.log(
      `${config.consoleTag} Server is running on ${config.host}:${config.port}`
    );
  }
});


// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  console.error(config.consoleTag, 'Uncaught Exception:', err);
});


// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error(config.consoleTag, 'Unhandled Promise Rejection:', reason, promise);
});

// Handle SIGINT (Ctrl+C) to gracefully close the server
process.on('SIGINT', () => {
  console.log('Received SIGINT. Closing server gracefully...');

  server.close((err) => {
    if (err) {
      console.error('Error while closing server:', err);
      process.exit(1);
    }

    console.log('Server closed. Exiting process.');
    process.exit(0);
  });
});

// Handle SIGTERM to gracefully close the server
process.on('SIGTERM', () => {
  console.log('Received SIGTERM. Closing server gracefully...');

  server.close((err) => {
    if (err) {
      console.error('Error while closing server:', err);
      process.exit(1);
    }

    console.log('Server closed. Exiting process.');
    process.exit(0);
  });
});

// Handle SIGHUP signal for server restart
process.on('SIGHUP', () => {
  console.log('Received SIGHUP signal. Restarting server...');

  const isWindows = os.platform() === 'win32';
  const restartScript = isWindows ? '/scripts/restart-server.bat' : '/scripts/restart-server.sh';
  const scriptPath = path.join(__dirname, restartScript);

  // Execute the restart script
  exec(scriptPath, (error, stdout, stderr) => {
    if (error) {
      console.error('Error executing restart script:', error);
      return;
    }

    console.log('Server restarted successfully.');
  });
});

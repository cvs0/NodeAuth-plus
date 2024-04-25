const config = {
  // SESSION SETTINGS
  sessionSecret: 'your-secret-key',
  sessionTimeout: 3600000, // IN MILLISECONDS

  // SERVER SETTINGS
  port: process.env.PORT || 3000,
  host: '127.0.0.1',

  // REGISTRATION SETTINGS
  registration: true,

  /*
  1: Can use any password
  2: Must be at least 8 characters long
  3: Must be 8 characters long containing at least one number and special character with one capital letter.
  */
  strictPasswordsLevel: 1,

  // PAGE SETTINGS
  loginPageTitle: 'Login Page',

  // LOGGING SETTINGS
  actionConsoleInfo: true,
  showIpsInOutput: true,
  consoleTag: '[NodeAuth+]',

  // STYLE SETTINGS
  // 1: No style
  // 2: Dark style
  // 3: Light style
  styleMode: 2,
};

export { config }
// config.js
module.exports = {
  sessionSecret: 'your-secret-key',
  port: process.env.PORT || 3000,
  users: [
    { id: 1, username: 'user1', password: 'password1' },
    { id: 2, username: 'user2', password: 'password2' },
  ],
};

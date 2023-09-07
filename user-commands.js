// user-commands.js
const config = require('./config');

const addUser = (username, password) => {
  const newUser = {
    id: config.users.length + 1,
    username,
    password,
  };

  config.users.push(newUser);
  console.log(`User '${username}' added successfully.`);
};

module.exports = {
  addUser,
};

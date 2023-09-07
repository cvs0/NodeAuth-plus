// user-commands.js
const fs = require('fs');
const config = require('./config');
const usersData = require('./users.json'); // Import the users data

const addUser = (username, password) => {
  const newUser = {
    id: usersData.length + 1,
    username,
    password,
  };

  // Push the new user to the usersData array
  usersData.push(newUser);

  // Update the users.json file with the new user data
  fs.writeFileSync('./users.json', JSON.stringify(usersData, null, 2), 'utf-8');

  console.log(`User '${username}' added successfully.`);
};

module.exports = {
  addUser,
};

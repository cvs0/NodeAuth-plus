const fs = require('fs');
const bcrypt = require('bcrypt');
const config = require('./config');
const usersData = require('./users.json'); // Import the users data

const addUser = (username, password) => {
  // Hash the password securely
  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) {
      console.error('Error hashing the password:', err);
      return;
    }

    const newUser = {
      id: usersData.length + 1,
      username,
      password: hashedPassword, // Store the hashed password
    };

    // Push the new user to the usersData array
    usersData.push(newUser);

    // Update the users.json file with the new user data
    fs.writeFileSync('./users.json', JSON.stringify(usersData, null, 2), 'utf-8');

    console.log(`User '${username}' added successfully.`);
  });
};

module.exports = {
  addUser,
};

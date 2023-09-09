const fs = require('fs');
const bcrypt = require('bcrypt');
const config = require('./config');
const usersData = require('./users.json');

const addUser = (username, password) => {
  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) {
      console.error('Error hashing the password:', err);
      return;
    }

    const newUser = {
      id: usersData.length + 1,
      username,
      password: hashedPassword,
    };

    usersData.push(newUser);

    fs.writeFileSync('./users.json', JSON.stringify(usersData, null, 2), 'utf-8');

    console.log(`User '${username}' added successfully.`);
  });
};

module.exports = {
  addUser,
};

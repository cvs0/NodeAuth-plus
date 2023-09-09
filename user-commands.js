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

const deleteUser = (username) => {
  const userIndex = usersData.findIndex((user) => user.username === username);

  if (userIndex === -1) {
    console.error(`User '${username}' not found.`);
    return;
  }

  usersData.splice(userIndex, 1);

  fs.writeFileSync('./users.json', JSON.stringify(usersData, null, 2), 'utf-8');

  console.log(`User '${username}' deleted successfully.`);
};

const listUsers = () => {
  console.log('List of Users:');
  usersData.forEach((user) => {
    console.log(`Username: ${user.username}, ID: ${user.id}`);
  });
};

module.exports = {
  addUser,
  deleteUser,
  listUsers,
};
const fs = require('fs');
const bcrypt = require('bcrypt');
const config = require('./config');
const usersData = require('./data/users.json');
const winston = require('winston');
const path = require('path');

const logDirectory = path.join(__dirname, 'logs');

if (!fs.existsSync(logDirectory)) {
  fs.mkdirSync(logDirectory);
}

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: path.join(logDirectory, 'error.log'), level: 'error' }),
    new winston.transports.File({ filename: path.join(logDirectory, 'combined.log') }),
  ],
});

const addUser = (username, password) => {
  bcrypt.genSalt(10, (saltError, salt) => {
    if (saltError) {
      logger.error(`Error generating salt for user '${username}': ${saltError.message}`);
      return;
    }

    bcrypt.hash(password, salt, (hashError, hashedPassword) => {
      if (hashError) {
        logger.error(`Error hashing password for user '${username}': ${hashError.message}`);
        return;
      }
  
      const newUser = {
        id: usersData.length + 1,
        username,
        password: hashedPassword,
      };
  
      usersData.push(newUser);
  
      try {
        const userDataPath = path.join(__dirname, 'data', 'users.json');
        
        fs.writeFileSync(userDataPath, JSON.stringify(usersData, null, 2), 'utf-8');
        console.log(`User '${username}' added successfully.`);
      } catch (writeError) {
        logger.error(`Error writing user data to file for user '${username}': ${writeError.message}`);
      }
    });
  });
};

const blacklistIP = (ip) => {
  const blacklistedIPsDataPath = path.join(__dirname, 'data', 'blacklisted-ips.json');
  const rawdata = fs.readFileSync(blacklistedIPsDataPath);
  const blacklistData = JSON.parse(rawdata);

  blacklistData.blacklist.push(ip);

  try {
    fs.writeFileSync(blacklistedIPsDataPath, JSON.stringify(blacklistData, null, 2), 'utf-8');
  } catch (writeError) {
    logger.error(`Error writing blacklist data to file for IP '${ip}': ${writeError.message}`);
  }
};

const deleteUser = (username) => {
  const userIndex = usersData.findIndex((user) => user.username === username);

  if (userIndex === -1) {
    logger.warn(`User '${username}' not found.`);
    return;
  }

  usersData.splice(userIndex, 1);

  try {
    const userDataPath = path.join(__dirname, 'data', 'users.json');

fs.writeFileSync(userDataPath, JSON.stringify(usersData, null, 2), 'utf-8');
    console.log(`User '${username}' deleted successfully.`);
  } catch (writeError) {
    logger.error(`Error writing user data to file after deleting user '${username}': ${writeError.message}`);
  }
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
  blacklistIP,
};

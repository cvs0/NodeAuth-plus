// cli.js
const yargs = require('yargs');
const { addUser, deleteUser, listUsers, blacklistIP } = require('./user-commands');

yargs
  .command({
    command: 'add-user',
    describe: 'Add a new user',
    builder: {
      username: {
        describe: 'Username for the new user',
        demandOption: true,
        type: 'string',
      },
      password: {
        describe: 'Password for the new user',
        demandOption: true,
        type: 'string',
      },
    },

    handler: (argv) => {
      addUser(argv.username, argv.password);
    },
  })

  .command({
    command: 'blacklist-ip',
    describe: 'Blacklists IP addresses from accessing the site.',
    builder: {
      ip: {
        describe: 'IP address to blacklist',
        demandOption: true,
        type: 'string',
      },
    },
    
    handler: (argv) => {
      blacklistIP(argv.ip);
    },
  })

  .command({
    command: 'delete-user',
    describe: 'Delete an existing user',
    builder: {
      username: {
        describe: 'Username of the user to delete',
        demandOption: true,
        type: 'string',
      },
    },

    handler: (argv) => {
      deleteUser(argv.username);
    },
  })

  .command({
    command: 'list-users',
    describe: 'List all existing users',
    handler: () => {
      listUsers();
    },
  })
  .help()
  
  .argv;

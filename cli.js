// cli.js
const yargs = require('yargs');
const { addUser } = require('./user-commands');

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
  .help()
  .argv;

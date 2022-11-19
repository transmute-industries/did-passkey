#!/usr/bin/env node

// const fs = require('fs');
// const path = require('path');
const yargs = require('yargs');
const {hideBin} = require('yargs/helpers');

// const lib = require('./index');

// const readFile = (argv, argName) => {
//   try {
//     const file = fs
//         .readFileSync(path.resolve(process.cwd(), argv[argName]))
//         .toString();

//     return file;
//   } catch (e) {
//     console.error('Cannot read from file: ' + argv[argName]);
//     process.exit(1);
//   }
// };

// const readJsonFromPath = (argv, argName) => {
//   let value;
//   if (argv[argName]) {
//     try {
//       const file = readFile(argv, argName);
//       value = JSON.parse(file);
//     } catch (e) {
//       console.error('Cannot parse JSON from file: ' + argv[argName]);
//       process.exit(1);
//     }
//   }
//   return value;
// };

yargs(hideBin(process.argv))
    .scriptName('did-passkey')
    .command(
        'demo',
        'about demo',
        () => {},
        async (argv) => {
          console.log(argv);
        },
    )
    .demandCommand(1)
    .parse();

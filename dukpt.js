#!/usr/bin/env node

const { program, Option } = require('commander');
const { version } = require('./package.json');
const Dukpt = require('dukpt');
const { pinBlockFormat0 } = require('data-crypto');
const DukptMac = require('./lib/dukpt.mac.lib');
const Utils = require('./lib/util.lib');
const Thales = require('./lib/thales.hsm.lib');

const dukptOptions = {
  encryptionMode: '3DES',
  outputEncoding: 'hex',
  inputEncoding: 'ascii',
};

program
  .version(version)
  .addOption(new Option('--debug', 'output extra debugging'))
  .addOption(new Option('-h, --hsm-host <host>', 'Thales HSM host to connect to, for HSM commands').default('hsm'))
  .addOption(new Option('-p, --hsm-port <port>', 'Thales HSM port to connect to, for HSM commands').default(80))
  .addOption(new Option('-e, --encryption <mode>', 'encryption mode').choices(['3DES', 'AES']).default('3DES'))

program
  .command('pin <bdk> <ksn> <accountNumber> <pinDigits>')
  .description('generate encrypted ISO "Format 0" PIN block')
  .action((bdk, ksn, account, pin) => {
    const dukpt = new Dukpt(bdk, ksn, 'pinkey');
    let pinBlock = pinBlockFormat0(account, pin);
    console.log(dukpt.dukptEncrypt(pinBlock, { ...dukptOptions, inputEncoding: 'hex' }));
  })

program
  .command('mac <bdk> <ksn> <data>')
  .description('generate MAC')
  .action((bdk, ksn, data) => {
    const dukpt = new Dukpt(bdk, ksn, 'mackey');
    console.log(DukptMac.generate(dukpt, Utils.parseInputData(data)))
  })

program
  .command('mac-cryptojs <bdk> <ksn> <data>')
  .description('generate MAC [CryptoJS]')
  .action((bdk, ksn, data) => {
    const dukpt = new Dukpt(bdk, ksn, 'mackey');
    console.log(DukptMac.generateCryptojs(dukpt._sessionKey, Utils.parseInputData(data)))
  })

program
  .command('encrypt <bdk> <ksn> <data>')
  .description('encrypt data')
  .action((bdk, ksn, data) => {
    const dukpt = new Dukpt(bdk, ksn, 'datakey');
    console.log(dukpt.dukptEncrypt(Utils.parseInputData(data), { ...dukptOptions }));
  })

program
  .command('decrypt <bdk> <ksn> <data>')
  .description('decrypt data')
  .action((bdk, ksn, data) => {
    const dukpt = new Dukpt(bdk, ksn, 'datakey');
    console.log(dukpt.dukptDecrypt(Utils.parseInputData(data), { inputEncoding: 'hex', outputEncoding: 'ascii', trimOutput: true }))
  })

program
  .command('hsm-pin-trans <srcBdk> <srcKsn> <dstBdk> <dstKsn> <accountNumber> <srcPinBlock>')
  .description('Translate encrypted BDK from type-1 source BDK to another type-1 BDK [G0 command]')
  .action(async (sourceBdk, sourceKsn, destBdk, destKsn, accountNumber, sourcePinBlock) => {
    const thales = new Thales(program.opts().hsmHost, program.opts().hsmPort)
    const translatedPinBlock = await thales.translatePinBlock(sourceBdk, sourceKsn, destBdk, destKsn, accountNumber, sourcePinBlock)
    console.log(translatedPinBlock)
  })

program
  .command('hsm-gen-mac <encryptedBdk> <ksn> <data>')
  .description('Generate MAC (Mode 4: 8-byte MAC) [GW command]')
  .action(async (encryptedBdk, ksn, data) => {
    const thales = new Thales(program.opts().hsmHost, program.opts().hsmPort)
    data = Utils.parseInputData(data)
    const mac = await thales.generateMac(encryptedBdk, ksn, data)
    console.log(mac)
  })

program.parse(process.argv);

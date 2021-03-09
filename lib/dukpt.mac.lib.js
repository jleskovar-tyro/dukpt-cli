const crypto = require('crypto');
const CryptoJS = require("crypto-js");
class DukptMac {

  static generateCryptojs(sessionKey, data) {
    const leftKey = CryptoJS.enc.Hex.parse(sessionKey.substring(0, 16));
    const rightKey = CryptoJS.enc.Hex.parse(sessionKey.substring(16));
    const iv = CryptoJS.enc.Hex.parse('0000000000000000')

    let c = CryptoJS.DES.encrypt(CryptoJS.enc.Utf8.parse(data), leftKey, { iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.ZeroPadding })
    c = CryptoJS.DES.decrypt({ ciphertext: CryptoJS.enc.Hex.parse(c.ciphertext.toString().slice(-16)) }, rightKey, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.NoPadding })
    c = CryptoJS.DES.encrypt(c, leftKey, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.NoPadding })

    return c.ciphertext.toString().toUpperCase()
  }

  static generate(dukpt, data) {
    const leftKey = Buffer.from(dukpt._sessionKey.substring(0, 16), 'hex');
    const rightKey = Buffer.from(dukpt._sessionKey.substring(16), 'hex');
    const iv = Buffer.alloc(8, 0);

    data = Buffer.from(data, 'utf8')
    if (data.length % 8 > 0) {
      let padding = Buffer.alloc(8 - data.length % 8, 0)
      data = Buffer.concat([data, padding])
    }

    let cipher, c
    cipher = crypto.createCipheriv('des-cbc', leftKey, iv).setAutoPadding(false)
    c = Buffer.concat([cipher.update(data), cipher.final()])
    
    cipher = crypto.createDecipheriv('des-ecb', rightKey, '').setAutoPadding(false)
    c = Buffer.concat([cipher.update(c.slice(c.length - 8)), cipher.final()])
    
    cipher = crypto.createCipheriv('des-ecb', leftKey, '').setAutoPadding(false)
    c = Buffer.concat([cipher.update(c), cipher.final()])

    return c.toString('hex').toUpperCase();
  }
}

module.exports = DukptMac

const crypto = require('crypto');
class DukptMac {
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

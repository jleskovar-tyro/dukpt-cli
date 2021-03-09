const crypto = require('crypto')

class DukptMac {
  static generate(dukpt, data) {
    const leftKey = Buffer.from(dukpt._sessionKey.substring(0, 16), 'hex');
    const rightKey = Buffer.from(dukpt._sessionKey.substring(16), 'hex');
    const iv = Buffer.alloc(8, 0);
  
    data = Buffer.from(data, 'utf8')
    if (data.length % 8 > 0) {
      data = data + Buffer.alloc(8 - data.length % 8, 0)
    }
  
    let cipher, c
    cipher = crypto.createCipheriv('des-cbc', leftKey, iv).setAutoPadding(false)
    c = cipher.update(data, null, 'hex') + cipher.final('hex');
  
    cipher = crypto.createDecipheriv('des-ecb', rightKey, '').setAutoPadding(false)
    data = c.slice(c.length - 16)
    c = cipher.update(data, 'hex', 'hex') + cipher.final('hex');
  
    cipher = crypto.createCipheriv('des-ecb', leftKey, '').setAutoPadding(false)
    cipher.setAutoPadding(false)
    c = cipher.update(c, 'hex', 'hex') + cipher.final('hex');
  
    return c.toUpperCase();
  }
}

module.exports = DukptMac

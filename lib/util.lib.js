
const fs = require("fs");

class Utils {
  static parseInputData(data) {
    if (data === '-') {
      return fs.readFileSync(0).toString();
    }
    return data
  }  
}

module.exports = Utils

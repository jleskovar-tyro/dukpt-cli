const Struct = require('struct');
const net = require('net')
const { PromiseSocket, TimeoutError } = require('promise-socket');
const { createBrotliCompress } = require('zlib');

class Thales {
  constructor(host, port) {
    this.host = host
    this.port = port
  }

  async translatePinBlock(sourceBdk, sourceKsn, destBdk, destKsn, accountNumber, sourcePinBlock) {
    const Command = Thales.makePinTranslateCommand()
    Command.allocate()
    
    let request = Command.buffer()
    let proxy = Command.fields;
    proxy.length = request.length - 2
    proxy.header = 'HDR0'
    proxy.command = 'G0'
    proxy.sourceBdk = sourceBdk
    proxy.destBdkFlag = '*'
    proxy.destBdk = destBdk
    proxy.srcKsnDescriptor = '906'
    proxy.srcKsn = sourceKsn
    proxy.dstKsnDescriptor = '906'
    proxy.dstKsn = destKsn
    proxy.srcPinBlock = sourcePinBlock
    proxy.srcPinBlockFormat = '01'
    proxy.dstPinBlockFormat = '01'
    proxy.accountNumber = accountNumber.slice(accountNumber.length - 13, -1)
    
    return await this.sendRequestAndHandleHsmResponse(request, Thales.makePinTranslateResponse, (response) => {
      return response.pinBlock
    })
  }

  generateMac(bdk, ksn, data) {
  }

  verifyMac(bdk, ksn, data) {
  }

  async sendRequestAndHandleHsmResponse(request, responseCreator, handler) {
    const socket = new net.Socket();
    const promiseSocket = new PromiseSocket(socket)
    
    try {
      await promiseSocket.connect(this.port, this.host)
      await promiseSocket.write(request)

      for (let chunk; (chunk = await promiseSocket.read()); ) {
        let Response = Thales.makeBaseResponse()
        Response._setBuff(chunk)
        
        if (Response.fields.errorCode !== '00') {
          console.error('HSM returned error code: ' + proxy.errorCode)
          return null
        }  

        Response = responseCreator()
        Response._setBuff(chunk)
        return handler(Response.fields)
      }  
    } catch (error) {
      console.error('HSM Error: ' + error)
      return null
    } finally {
      await promiseSocket.destroy()
    }
  }

  static makePinTranslateCommand() {
    return Struct()
      .word16Sbe('length')
      .chars('header', 4)
      .chars('command', 2)
      .chars('sourceBdk', 33)
      .chars('destBdkFlag', 1)
      .chars('destBdk', 33)
      .chars('srcKsnDescriptor', 3)
      .chars('srcKsn', 20)
      .chars('dstKsnDescriptor', 3)
      .chars('dstKsn', 20)
      .chars('srcPinBlock', 16)
      .chars('srcPinBlockFormat', 2)
      .chars('dstPinBlockFormat', 2)
      .chars('accountNumber', 12)
  }

  static makeBaseResponse() {
    return Struct()
      .word16Sbe('length')
      .chars('header', 4)
      .chars('responseCode', 2)
      .chars('errorCode', 2)
  }

  static makePinTranslateResponse() {
    return Struct()
      .word16Sbe('length')
      .chars('header', 4)
      .chars('responseCode', 2)
      .chars('errorCode', 2)
      .chars('pinLength', 2)
      .chars('pinBlock', 16)
  }
}

module.exports = Thales
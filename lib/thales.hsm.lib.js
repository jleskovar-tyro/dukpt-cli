const Struct = require('struct');
const net = require('net')
const { PromiseSocket } = require('promise-socket');
const hexy = require('hexy')

class Thales {
  constructor(host, port, debug) {
    this.host = host
    this.port = port
    this.debug = debug
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

  async generateMac(bdk, ksn, data) {
    const Command = Thales.makeGenerateMacRequest()
    Command.allocate()
    
    let request = Command.buffer()
    let proxy = Command.fields;
    proxy.header = 'HDR0'
    proxy.command = 'GW'
    proxy.macMode = '4'
    proxy.macMethod = '1'
    proxy.bdk = bdk
    proxy.ksnDescriptor = '906'
    proxy.ksn = ksn

    let dataBuffer = Buffer.from(data, 'utf8');
    if (dataBuffer.length % 8 > 0) {
      dataBuffer = dataBuffer + Buffer.alloc(8 - (dataBuffer.length % 8), 0)
    }
    
    proxy.length = request.length + dataBuffer.length - 2
    proxy.messageLength = dataBuffer.length.toString().padStart(4, '0')
    
    request = request + dataBuffer
    return await this.sendRequestAndHandleHsmResponse(request, Thales.makeGenerateMacResponse, (response) => {
      return response.mac
    })
  }

  async encrypytData(bdk, ksn, data) {
    const Command = Thales.makeEncryptCommand()
    Command.allocate()
    
    let request = Command.buffer()
    let proxy = Command.fields;
    proxy.header = 'HDR0'
    proxy.command = 'M0'
    proxy.modeFlag = '01'
    proxy.inputFormatFlag = '2'
    proxy.outputFormatFlag = '1'
    proxy.keyType = '009'
    proxy.key = bdk
    proxy.ksnDescriptor = '906'
    proxy.ksn = ksn
    proxy.iv = '0000000000000000'

    let dataBuffer = Buffer.from(data, 'utf8');
    if (dataBuffer.length % 8 > 0) {
      dataBuffer = dataBuffer + Buffer.alloc(8 - (dataBuffer.length % 8), 0)
    }
    
    proxy.length = request.length + dataBuffer.length - 2
    proxy.messageLength = dataBuffer.length.toString().padStart(4, '0')
    
    request = request + dataBuffer
    return await this.sendRequestAndHandleHsmResponse(request, Thales.makeEncryptResponse, (response, buffer) => {
      const encryptedData = buffer.slice(30)
      return encryptedData.toString('hex')
    })
  }

  async decrypytData(bdk, ksn, data) {
    const Command = Thales.makeEncryptCommand()
    Command.allocate()
    
    let request = Command.buffer()
    let proxy = Command.fields;
    proxy.header = 'HDR0'
    proxy.command = 'M2'
    proxy.modeFlag = '01'
    proxy.inputFormatFlag = '0'
    proxy.outputFormatFlag = '2'
    proxy.keyType = '009'
    proxy.key = bdk
    proxy.ksnDescriptor = '906'
    proxy.ksn = ksn
    proxy.iv = '0000000000000000'

    let dataBuffer = Buffer.from(data, 'hex');
    proxy.length = request.length + dataBuffer.length - 2
    proxy.messageLength = dataBuffer.length.toString().padStart(4, '0')
    
    request = request + dataBuffer
    return await this.sendRequestAndHandleHsmResponse(request, Thales.makeEncryptResponse, (response, buffer) => {
      const decryptedData = buffer.slice(30)
      return decryptedData.toString('utf8')
    })
  }

  verifyMac(bdk, ksn, data) {
  }

  async sendRequestAndHandleHsmResponse(request, responseCreator, handler) {
    const socket = new net.Socket();
    const promiseSocket = new PromiseSocket(socket)
    
    try {
      await promiseSocket.connect(this.port, this.host)

      if (this.debug) {
        console.log('Sending HSM request:')
        console.log(hexy.hexy(request))
      }

      await promiseSocket.write(request)

      for (let chunk; (chunk = await promiseSocket.read()); ) {
        let Response = Thales.makeBaseResponse()

        if (this.debug) {
          console.log('Processing HSM response:')
          console.log(hexy.hexy(chunk))
        }

        Response._setBuff(chunk)
        
        if (Response.fields.errorCode !== '00') {
          console.error('HSM returned error code: ' + Response.fields.errorCode)
          return null
        }  

        Response = responseCreator()
        Response._setBuff(chunk)
        return handler(Response.fields, chunk)
      }  
    } catch (error) {
      console.error('HSM Error: ' + error)
      return null
    } finally {
      await promiseSocket.destroy()
    }
  }

  static makeEncryptCommand() {
    return Struct()
      .word16Sbe('length')
      .chars('header', 4)
      .chars('command', 2)
      .chars('modeFlag', 2)
      .chars('inputFormatFlag', 1)
      .chars('outputFormatFlag', 1)
      .chars('keyType', 3)
      .chars('key', 33)
      .chars('ksnDescriptor', 3)
      .chars('ksn', 20)
      .chars('iv', 16)
      .chars('messageLength', 4)
  }

  static makeEncryptResponse() {
    return Struct()
      .word16Sbe('length')
      .chars('header', 4)
      .chars('responseCode', 2)
      .chars('errorCode', 2)
      .chars('iv', 16)
      .chars('messageLength', 4)
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

  static makePinTranslateResponse() {
    return Struct()
      .word16Sbe('length')
      .chars('header', 4)
      .chars('responseCode', 2)
      .chars('errorCode', 2)
      .chars('pinLength', 2)
      .chars('pinBlock', 16)
  }

  static makeGenerateMacRequest() {
    return Struct()
      .word16Sbe('length')
      .chars('header', 4)
      .chars('command', 2)
      .chars('macMode', 1)
      .chars('macMethod', 1)
      .chars('bdk', 33)
      .chars('ksnDescriptor', 3)
      .chars('ksn', 20)
      .chars('messageLength', 4)
  }

  static makeGenerateMacResponse() {
    return Struct()
      .word16Sbe('length')
      .chars('header', 4)
      .chars('responseCode', 2)
      .chars('errorCode', 2)
      .chars('mac', 16)
  }

  static makeBaseResponse() {
    return Struct()
      .word16Sbe('length')
      .chars('header', 4)
      .chars('responseCode', 2)
      .chars('errorCode', 2)
  }
}

module.exports = Thales

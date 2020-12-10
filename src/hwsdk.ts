import bippath from 'bip32-path';
import Transport from '@ledgerhq/hw-transport';
const COTI_SCRAMBLE_KEY = 'COTI';

export const BIP32_PATH = "44'/6779'/0'/0";

export class HWSDK {
  readonly transport: Transport;

  constructor(transport: Transport) {
    this.transport = transport;

    transport.decorateAppAPIMethods(this, ['getPublicKey', 'signMessage'], COTI_SCRAMBLE_KEY);
  }

  // Get COTI public key for a given BIP32 account index.
  async getPublicKey(index?: number, interactive = true) {
    let path = BIP32_PATH;
    if (index !== undefined) {
      path = `${path}/${index}`;
    }
    const paths: number[] = bippath.fromString(path).toPathArray();
    const buffer = Buffer.alloc(1 + paths.length * 4);
    buffer[0] = paths.length;
    paths.forEach((element, pathIndex) => {
      buffer.writeUInt32BE(element, 1 + 4 * pathIndex);
    });

    const response = await this.transport.send(0xe0, 0x02, interactive ? 0x01 : 0x00, 0x00, buffer);
    const publicKeyLength = response[0];
    const publicKey = response.slice(1, 1 + publicKeyLength).toString('hex');

    return { publicKey };
  }

  // Get COTI public key for a given BIP32 account index.
  async getUserPublicKey(interactive = true) {
    return this.getPublicKey(undefined, interactive);
  }

  // Signs a message and retrieves v, r, s given the raw transaction and the BIP32 path.
  async signMessage(index: number | undefined, messageHex: string) {
    let path = BIP32_PATH;
    if (index !== undefined) {
      path = `${path}/${index}`;
    }
    const paths: number[] = bippath.fromString(path).toPathArray();
    let offset = 0;
    const message = Buffer.from(messageHex, 'hex');
    const data = [];

    while (offset !== message.length) {
      const maxChunkSize = offset === 0 ? 150 - 1 - paths.length * 4 - 4 : 150;
      const chunkSize = offset + maxChunkSize > message.length ? message.length - offset : maxChunkSize;
      const buffer = Buffer.alloc(offset === 0 ? 1 + paths.length * 4 + 4 + chunkSize : chunkSize);
      if (offset === 0) {
        buffer[0] = paths.length;
        paths.forEach((element, index) => {
          buffer.writeUInt32BE(element, 1 + 4 * index);
        });
        buffer.writeUInt32BE(message.length, 1 + 4 * paths.length);
        message.copy(buffer, 1 + 4 * paths.length + 4, offset, offset + chunkSize);
      } else {
        message.copy(buffer, 0, offset, offset + chunkSize);
      }
      data.push(buffer);
      offset += chunkSize;
    }
    let response;
    for (let i = 0; i < data.length; ++i) {
      response = await this.transport.send(0xe0, 0x04, i === 0 ? 0x00 : 0x80, 0x00, data[i]);
    }
    if (response === undefined) throw new Error(`Undefined sign message response`);
    const v = response[0];
    const r = response.slice(1, 1 + 32).toString('hex');
    const s = response.slice(1 + 32, 1 + 32 + 32).toString('hex');

    return { v, r, s };
  }

  // Signs a message and retrieves v, r, s given the raw transaction and the BIP32 path.
  async signUserMessage(messageHex: string) {
    return this.signMessage(undefined, messageHex);
  }
}

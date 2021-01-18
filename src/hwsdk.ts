import bippath from 'bip32-path';
import Transport from '@ledgerhq/hw-transport';

const COTI_SCRAMBLE_KEY = 'COTI';

const CLA = 0xe0;

const INS_GET_PUBLIC_KEY = 0x02;
const INS_SIGN_MESSAGE = 0x04;

const P1_CONFIRM = 0x01;
const P1_UNCONFIRM = 0x00;
const P1_FIRST = 0x00;
const P1_MORE = 0x80;
const P2_HASHED = 0x01;
const P2_NOT_HASHED = 0x00;

export const BIP32_PATH = "44'/6779'/0'/0";

export enum SigningType {
  MESSAGE,
  FULL_NODE_FEE,
  TX_TRUST_SCORE,
  BASE_TX,
  TX,
}

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

    const response = await this.transport.send(CLA, INS_GET_PUBLIC_KEY, interactive ? P1_CONFIRM : P1_UNCONFIRM, 0x00, buffer);
    const publicKeyLength = response[0];
    const publicKey = response.slice(1, 1 + publicKeyLength).toString('hex');

    return { publicKey };
  }

  // Get COTI public key for a given BIP32 account index.
  async getUserPublicKey(interactive = true) {
    return this.getPublicKey(undefined, interactive);
  }

  // Signs a message and retrieves v, r, s given the raw transaction and the BIP32 path.
  async signMessage(index: number | undefined, messageHex: string, signingType = SigningType.MESSAGE, hashed = true) {
    let path = BIP32_PATH;
    if (index !== undefined) {
      path = `${path}/${index}`;
    }
    const paths: number[] = bippath.fromString(path).toPathArray();
    let offset = 0;
    const message = Buffer.from(messageHex, 'hex');
    const data = [];

    while (offset !== message.length) {
      const maxChunkSize = offset === 0 ? 150 - 2 - paths.length * 4 - 4 : 150;
      const chunkSize = offset + maxChunkSize > message.length ? message.length - offset : maxChunkSize;
      const buffer = Buffer.alloc(offset === 0 ? 2 + paths.length * 4 + 4 + chunkSize : chunkSize);
      if (offset === 0) {
        buffer[0] = paths.length;
        paths.forEach((element, index) => {
          buffer.writeUInt32BE(element, 1 + 4 * index);
        });
        buffer[1 + 4 * paths.length] = signingType;
        buffer.writeUInt32BE(message.length, 2 + 4 * paths.length);
        message.copy(buffer, 2 + 4 * paths.length + 4, offset, offset + chunkSize);
      } else {
        message.copy(buffer, 0, offset, offset + chunkSize);
      }
      data.push(buffer);
      offset += chunkSize;
    }
    let response;
    for (let i = 0; i < data.length; ++i) {
      response = await this.transport.send(CLA, INS_SIGN_MESSAGE, i === 0 ? P1_FIRST : P1_MORE, hashed ? P2_HASHED : P2_NOT_HASHED, data[i]);
    }
    if (response === undefined) throw new Error(`Undefined sign message response`);
    const v = response[0];
    const r = response.slice(1, 1 + 32).toString('hex');
    const s = response.slice(1 + 32, 1 + 32 + 32).toString('hex');

    return { v, r, s };
  }

  // Signs a message and retrieves v, r, s given the raw transaction and the BIP32 path.
  async signUserMessage(messageHex: string, signingType = SigningType.MESSAGE, hashed = true) {
    return this.signMessage(undefined, messageHex, signingType, hashed);
  }
}

import bippath from 'bip32-path';
import Transport from '@ledgerhq/hw-transport';
import * as errors from './errors';

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

export interface BaseTransactionSigningData {
  amount: string;
  address: string;
}

export interface TransactionSigningData {
  amount: string;
}

export type SigningData = BaseTransactionSigningData | TransactionSigningData;

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
    try {
      const response = await this.transport.send(CLA, INS_GET_PUBLIC_KEY, interactive ? P1_CONFIRM : P1_UNCONFIRM, 0x00, buffer);
      const publicKeyLength = response[0];
      const publicKey = response.slice(1, 1 + publicKeyLength).toString('hex');
      return { publicKey };
    } catch (e) {
      throw errors.getError(e);
    }
  }

  // Get COTI public key for a given BIP32 account index.
  async getUserPublicKey(interactive = true) {
    return this.getPublicKey(undefined, interactive);
  }

  // Signs a message and retrieves v, r, s given the raw transaction and the BIP32 path.
  async signMessage(
    index: number | undefined,
    messageInBytes: Uint8Array,
    signingType = SigningType.MESSAGE,
    hashed = true,
    signingData?: SigningData
  ) {
    let path = BIP32_PATH;
    if (index !== undefined) {
      path = `${path}/${index}`;
    }
    const paths: number[] = bippath.fromString(path).toPathArray();
    let offset = 0;
    const message = Buffer.from(messageInBytes);
    let amount: Buffer | undefined;
    let address: Buffer | undefined;
    if ([SigningType.BASE_TX, SigningType.TX].includes(signingType)) {
      if (signingData === undefined) throw new Error('Missing signing data');
      amount = Buffer.from(signingData.amount, 'utf-8');
      if (SigningType.BASE_TX === signingType) {
        if ('address' in signingData) {
          address = Buffer.from(signingData.address, 'utf-8');
        } else throw new Error('Missing address in signing data');
      }
    }
    const data: Buffer[] = [];
    const pathLengthByteNumber = 1;
    const pathParameterByteNumber = 4;
    const signingTypeByteNumber = 1;
    const messageLengthByteNumber = 4;
    const amountLengthByteNumber = 4;
    let minimalFirstRequestByteNumber =
      pathLengthByteNumber + paths.length * pathParameterByteNumber + signingTypeByteNumber + messageLengthByteNumber;
    if (amount != undefined) minimalFirstRequestByteNumber += amountLengthByteNumber;

    let processedMessageLength = 0;
    let processedAmountLength = 0;
    let processedAddressLength = 0 ;
    let firstRequest = true;
    const amountLength = amount !== undefined ? amount.length : 0;
    const addressLength = address !== undefined ? address.length : 0;
    while (offset !== (message.length + amountLength + addressLength)) {
      let bufferIndex = 0;
      const maxChunkSize = firstRequest ? 150 - minimalFirstRequestByteNumber : 150;
      
      const messageChunkSize = Math.min(message.length - processedMessageLength, maxChunkSize);
      const amountChunkSize = Math.min(amountLength - processedAmountLength, maxChunkSize - messageChunkSize);
      const addressChunkSize = Math.min(addressLength - processedAddressLength, maxChunkSize - messageChunkSize - amountChunkSize);

      const chunkSize = messageChunkSize + amountChunkSize + addressChunkSize;
      const buffer = Buffer.alloc(firstRequest ? minimalFirstRequestByteNumber + chunkSize : chunkSize);
      if (firstRequest) {
        buffer[bufferIndex] = paths.length;
        bufferIndex += pathLengthByteNumber;

        paths.forEach((element, index) => {
          buffer.writeUInt32BE(element, bufferIndex);
          bufferIndex += pathParameterByteNumber;
        });

        buffer[bufferIndex] = signingType;
        bufferIndex += signingTypeByteNumber;
        
        buffer.writeUInt32BE(message.length, bufferIndex);
        bufferIndex += messageLengthByteNumber;

        if(amount !== undefined) {
          buffer.writeUInt32BE(amountLength, bufferIndex);
          bufferIndex += amountLengthByteNumber;
        }
        firstRequest = false;
      }
      if(messageChunkSize !== 0) {
        message.copy(buffer, bufferIndex, processedMessageLength, processedMessageLength + messageChunkSize);
        processedMessageLength += messageChunkSize;
        bufferIndex += messageChunkSize;
      }
      if(amount != undefined && amountChunkSize !== 0) {
        amount.copy(buffer, bufferIndex, processedAmountLength, processedAmountLength + amountChunkSize);
        processedAmountLength += amountChunkSize;
        bufferIndex += amountChunkSize;
      }
      if(address != undefined && addressChunkSize !== 0) {
        address.copy(buffer, bufferIndex, processedAddressLength, processedAddressLength + addressChunkSize);
        processedAddressLength += addressChunkSize;
      }  
      
      data.push(buffer);
      offset += chunkSize;
    }
    let response;
    for (let i = 0; i < data.length; ++i) {
      try {
        response = await this.transport.send(CLA, INS_SIGN_MESSAGE, i === 0 ? P1_FIRST : P1_MORE, hashed ? P2_HASHED : P2_NOT_HASHED, data[i]);
      } catch (e) {
        throw errors.getError(e);
      }
    }
    if (response === undefined) throw new Error(`Undefined sign message response`);
    const v = response[0];
    const r = response.slice(1, 1 + 32).toString('hex');
    const s = response.slice(1 + 32, 1 + 32 + 32).toString('hex');

    return { v, r, s };
  }

  // Signs a message and retrieves v, r, s given the raw transaction and the BIP32 path.
  async signUserMessage(messageInBytes: Uint8Array, signingType = SigningType.MESSAGE, hashed = true) {
    return this.signMessage(undefined, messageInBytes, signingType, hashed);
  }
}

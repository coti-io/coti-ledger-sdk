declare module 'bip32-path';
declare module '@ledgerhq/errors' {
  export class TransportStatusError extends Error {
    statusCode: number;
    statusText: string;

    constructor(statusCode: number);
  }
}

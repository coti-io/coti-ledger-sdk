import { getAltStatusMessage } from '@ledgerhq/errors';

export const CustomStatusCodes = {
  APPLICATION_NOT_RUNNING_WEB: 0x6511,
  APPLICATION_NOT_RUNNING_NODE: 0x6700,
  SECURITY_STATUS_NOT_SATISFIED: 0x6982,
  DEVICE_LOCKED: 0x6983,
  REJECTED_BY_USER: 0x6985,
  INVALID_PATH: 0x6a81,
  INSTRUCTION_NOT_INITIATED: 0x6a82,
};

export interface TransportStatusError extends Error {
  statusCode: number;
  statusText: string;
}

export class TransportStatusError {
  constructor(error: Error) {
    Object.assign(this, error);
    if (this.statusCode) {
      const statusText = Object.keys(CustomStatusCodes).find(k => CustomStatusCodes[k as keyof typeof CustomStatusCodes] === this.statusCode);
      if (statusText) {
        const smsg = getCustomAltStatusMessage(this.statusCode) || getAltStatusMessage(this.statusCode) || statusText;
        const statusCodeStr = this.statusCode.toString(16);
        this.message = `Ledger device: ${smsg} (0x${statusCodeStr})`;
        this.statusText = statusText;
      }
    }
  }
}

export function getError(error: Error) {
  const transportStatusError = new TransportStatusError(error);
  if (transportStatusError.statusCode) return transportStatusError;
  return error;
}

export function getCustomAltStatusMessage(code: number) {
  switch (code) {
    case 0x6511:
    case 0x6700:
      return 'Ledger application not running';
    case 0x6982:
      return 'Security status not satisfied';
    case 0x6983:
      return 'Device is locked';
    case 0x6985:
      return 'Rejected by user';
    case 0x6a81:
      return 'Invalid path';
    case 0x6a82:
      return 'Instruction not initiated';
  }
}

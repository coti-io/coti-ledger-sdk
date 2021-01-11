import { TransportStatusError } from '@ledgerhq/errors';
import { StatusCodes } from '@ledgerhq/hw-transport';

export const CustomStatusCodes = {
  REJECTED_BY_USER: 0x6985,
};

export function setCustomStatus(transactionStatusError: TransportStatusError) {}

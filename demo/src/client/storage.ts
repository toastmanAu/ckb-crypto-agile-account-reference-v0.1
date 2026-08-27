import {
  PasskeyRecordSchema,
  type PasskeyRecord,
} from "../shared/schemas.js";

export const PASSKEY_STORAGE_KEY = "ckb-passkey-demo.passkey.v1";

export function loadPasskeyRecord(storage: Storage): PasskeyRecord | null {
  const serialized = storage.getItem(PASSKEY_STORAGE_KEY);
  if (serialized === null) {
    return null;
  }

  try {
    return PasskeyRecordSchema.parse(JSON.parse(serialized));
  } catch {
    storage.removeItem(PASSKEY_STORAGE_KEY);
    return null;
  }
}

export function savePasskeyRecord(storage: Storage, record: PasskeyRecord): void {
  const verified = PasskeyRecordSchema.parse(record);
  storage.setItem(PASSKEY_STORAGE_KEY, JSON.stringify(verified));
}

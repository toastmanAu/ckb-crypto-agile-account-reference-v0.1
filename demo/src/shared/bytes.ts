export function bytesFromHex(hex: string): Uint8Array {
  if (!/^0x(?:[0-9a-f]{2})+$/.test(hex)) {
    throw new TypeError("expected canonical lowercase 0x hex");
  }
  const out = new Uint8Array((hex.length - 2) / 2);
  for (let index = 0; index < out.length; index += 1) {
    out[index] = Number.parseInt(hex.slice(2 + index * 2, 4 + index * 2), 16);
  }
  return out;
}

export function hexFromBytes(bytes: Uint8Array): `0x${string}` {
  let value = "0x";
  for (const byte of bytes) {
    value += byte.toString(16).padStart(2, "0");
  }
  return value as `0x${string}`;
}

export function bytesConcat(...parts: readonly Uint8Array[]): Uint8Array {
  let length = 0;
  for (const part of parts) {
    length += part.length;
    if (!Number.isSafeInteger(length)) {
      throw new RangeError("byte length");
    }
  }
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function u16le(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
    throw new RangeError("u16");
  }
  return Uint8Array.of(value & 0xff, value >>> 8);
}

export function u32le(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new RangeError("u32");
  }
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, true);
  return out;
}

export function u64le(value: bigint): Uint8Array {
  if (value < 0n || value > 0xffff_ffff_ffff_ffffn) {
    throw new RangeError("u64");
  }
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value, true);
  return out;
}

import { describe, expect, it } from "vitest";

import {
  bytesConcat,
  bytesFromHex,
  hexFromBytes,
  u16le,
  u32le,
  u64le,
} from "../../src/shared/bytes.js";

describe("bounded byte helpers", () => {
  it("round-trips canonical lowercase hex", () => {
    expect(bytesFromHex("0x0001feff")).toEqual(Uint8Array.of(0, 1, 254, 255));
    expect(hexFromBytes(Uint8Array.of(0, 1, 254, 255))).toBe("0x0001feff");
  });

  it.each(["", "00", "0x0", "0xGG", "0xAA"])("rejects malformed hex %s", (hex) => {
    expect(() => bytesFromHex(hex)).toThrow();
  });

  it("concatenates without aliasing the inputs", () => {
    const left = Uint8Array.of(1, 2);
    const joined = bytesConcat(left, Uint8Array.of(3));
    left[0] = 9;
    expect(joined).toEqual(Uint8Array.of(1, 2, 3));
  });

  it("writes exact little-endian integer boundaries", () => {
    expect(u16le(0xffff)).toEqual(Uint8Array.of(0xff, 0xff));
    expect(u32le(0x1234_5678)).toEqual(Uint8Array.of(0x78, 0x56, 0x34, 0x12));
    expect(u64le(0xffff_ffff_ffff_ffffn)).toEqual(new Uint8Array(8).fill(0xff));
  });

  it.each([
    () => u16le(-1),
    () => u16le(0x1_0000),
    () => u32le(0x1_0000_0000),
    () => u64le(-1n),
    () => u64le(0x1_0000_0000_0000_0000n),
  ])("throws before integer truncation", (encode) => {
    expect(encode).toThrow(RangeError);
  });
});

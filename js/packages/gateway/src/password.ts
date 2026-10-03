/**
 * Password hashing for the analytics surface.
 *
 * scrypt, because it is memory-hard and in Node's standard library. The stored
 * form is `salt:hash` in hex: a per-account random salt, and a hash of the
 * password with that salt. No plaintext password is ever written to the config.
 *
 * Verification is asynchronous. It costs a few tens of milliseconds on purpose,
 * and doing that on the event loop would let a handful of parallel login attempts
 * stall the whole gateway -- including the checker path, which is the one thing
 * that must always answer. The cost belongs to the thread that asked for it.
 */

import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';

const SALT_BYTES = 16;
const KEY_BYTES = 64;

function derive(password: string, salt: Buffer): Promise<Buffer> {
  // The overload that takes a plain key length needs the N, r, p and maxmem
  // arguments present; the defaults are the ones Node documents as intended.
  return new Promise((resolve, reject) => {
    scrypt(password, salt, KEY_BYTES, (err, key) => (err ? reject(err) : resolve(key)));
  });
}

export async function hashPassword(password: string, salt: Buffer = randomBytes(SALT_BYTES)): Promise<string> {
  const key = await derive(password, salt);
  return `${salt.toString('hex')}:${key.toString('hex')}`;
}

export interface VerifyResult {
  ok: boolean;
  /**
   * True when the stored value is malformed rather than merely wrong.
   *
   * Worth telling apart: a corrupt hash means the operator has to fix the config,
   * where a wrong password just means someone mistyped.
   */
  malformed: boolean;
}

export async function verifyPassword(password: string, stored: string): Promise<VerifyResult> {
  const parts = stored.split(':');
  const saltHex = parts[0];
  const keyHex = parts[1];
  if (saltHex === undefined || keyHex === undefined) return { ok: false, malformed: true };
  const salt = Buffer.from(saltHex, 'hex');
  const expected = Buffer.from(keyHex, 'hex');
  if (salt.length !== SALT_BYTES || expected.length !== KEY_BYTES) {
    return { ok: false, malformed: true };
  }
  const actual = await derive(password, salt);
  // Both buffers are the same fixed length, checked above, so this compares
  // length-independent and cannot leak the hash through an early return.
  return { ok: timingSafeEqual(actual, expected), malformed: false };
}

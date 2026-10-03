/**
 * Artifact capture: search strings inside a request that are worth surfacing.
 *
 * Two classes are looked for, both by shape rather than by meaning.
 *
 * 1. Flags, which may be passed straight in a request -- in the path, a form
 *    field, a header, anywhere. The conservative flag heuristic lives in
 *    flags.ts; this module just runs it over the captured text.
 *
 * 2. Encoding and hash material: md5 (32 hex), sha1 (40), sha256 (64),
 *    sha512 (128), base64 blocks, generic hex and pure binary 0/1 runs. These
 *    are the things a checker or a participant is likely to move around, and the
 *    UI shows them so a hash swapped in a request is visible without hunting.
 *
 * Detection is deliberately cheap and linear: the whole request (path, query,
 * headers, body) is scanned token by token, and a token is classified by its
 * own characters. Nothing here decides policy -- this is capture and display.
 */

import { detectFlags } from './flags.js';

export type ArtifactType = 'md5' | 'sha1' | 'sha256' | 'sha512' | 'base64' | 'hex' | 'binary';

export interface Artifact {
  type: ArtifactType;
  value: string;
}

const TOKEN = /[A-Za-z0-9+/]+/g;

const HASH_LENGTHS: Record<number, ArtifactType> = {
  32: 'md5',
  40: 'sha1',
  64: 'sha256',
  128: 'sha512',
};

/** The shortest token worth calling an artifact at all. */
const MIN_TOKEN = 16;

/** Longest value kept, so a giant upload cannot balloon a capture file. */
const MAX_VALUE = 128;

function isPureOneZero(token: string): boolean {
  return /^[01]+$/.test(token);
}

function isHex(token: string): boolean {
  return /^[0-9A-Fa-f]+$/.test(token);
}

function isBase64(token: string): boolean {
  // Alphabet only, long enough to matter, not hex (those are hashes), with a
  // digit and a length that a legitimate unpadded base64 can actually take.
  // `=` is a token separator, so padding never merges a value into its field
  // name; a value read this way is judged unpadded, and decoded base64 stores
  // data in 3-byte reads, so length % 4 is never 1.
  return (
    token.length >= 16 &&
    /^[A-Za-z0-9+/]+$/.test(token) &&
    /\d/.test(token) &&
    token.length % 4 !== 1
  );
}

/** Classify one maximal run of token characters. */
export function classifyToken(token: string): Artifact | null {
  if (token.length < MIN_TOKEN) return null;
  if (isPureOneZero(token)) return { type: 'binary', value: token };
  if (isHex(token)) {
    const type = HASH_LENGTHS[token.length];
    return { type: type ?? 'hex', value: token };
  }
  if (isBase64(token)) return { type: 'base64', value: token };
  return null;
}

/** Distinct hashes and encodings found in a text, per token. */
export function extractArtifacts(text: string): Artifact[] {
  if (!text) return [];
  const out: Artifact[] = [];
  const seen = new Set<string>();
  for (const match of text.matchAll(TOKEN)) {
    const token = match[0];
    if (token.length > MAX_VALUE) continue;
    const artifact = classifyToken(token);
    if (artifact === null || seen.has(`${artifact.type}\u0000${artifact.value}`)) continue;
    seen.add(`${artifact.type}\u0000${artifact.value}`);
    out.push(artifact);
  }
  return out;
}

export interface Captured {
  flags: string[];
  artifacts: Artifact[];
}

/**
 * Capture what a request carries: flags and hash/encoding material, across the
 * path, the query, the headers and the body.
 *
 * The distinct pieces are joined rather than scored separately, so a flag split
 * across a header boundary is still one haystack. Detection is per token, so a
 * token is classified as a whole and never by a substring of itself.
 */
export function scanCapture(texts: Iterable<string>): Captured {
  const pieces: string[] = [];
  for (const text of texts) {
    if (typeof text === 'string' && text.length > 0) pieces.push(text);
  }
  const blob = pieces.join('\n');
  return { flags: detectFlags(blob), artifacts: extractArtifacts(blob) };
}
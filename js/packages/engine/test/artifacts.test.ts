import { describe, expect, it } from 'vitest';

import {
  classifyToken,
  extractArtifacts,
  scanCapture,
  type Artifact,
} from '../src/artifacts.js';

describe('classifyToken', () => {
it('classifies md5, sha1, sha256, sha512 by length', () => {
    expect(classifyToken('d41d8cd98f00b204e9800998ecf8427e')?.type).toBe('md5');
    expect(classifyToken('da39a3ee5e6b4b0d3255bfef95601890afd80709')?.type).toBe('sha1');
    expect(classifyToken('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')?.type).toBe('sha256');
    expect(classifyToken('cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e')?.type).toBe('sha512');
  });

  it('classifies generic even-length hex', () => {
    expect(classifyToken('a1b2c3d4e5f60718')?.type).toBe('hex');
  });

  it('classifies pure 0/1 runs as binary even at hash lengths', () => {
    expect(classifyToken('1'.repeat(64))?.type).toBe('binary');
  });

it('classifies base64 by alphabet and length', () => {
    expect(classifyToken('MTIzNDU2Nzg5MDEyMzQ1Njc4')?.type).toBe('base64');
  });

  it('ignores short and mixed tokens', () => {
    expect(classifyToken('short')).toBeNull();
    expect(classifyToken('not!a*token')).toBeNull();
  });
});

describe('extractArtifacts', () => {
  it('finds hashes inside prose', () => {
    const md5 = 'd41d8cd98f00b204e9800998ecf8427e';
    const sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    const out = extractArtifacts(`token=${md5} ctx=${sha256}`);
    const types = out.map((a: Artifact) => a.type);
    expect(types).toContain('md5');
    expect(types).toContain('sha256');
    expect(out.some((a) => a.value === md5)).toBe(true);
  });

  it('does not split a long hash into shorter ones', () => {
    const sha1 = 'a'.repeat(40);
    const out = extractArtifacts(sha1);
    expect(out).toHaveLength(1);
    expect(out[0]?.type).toBe('sha1');
  });

  it('handles empty text', () => {
    expect(extractArtifacts('')).toEqual([]);
    expect(extractArtifacts('no artefacts here, just words')).toEqual([]);
  });
});

describe('scanCapture', () => {
  it('finds flag-shaped strings and hashes together', () => {
    const flag = 'flag{th3_c4ptur3d_fl4g}';
    const md5 = 'd41d8cd98f00b204e9800998ecf8427e';
    const out = scanCapture([`/submit`, `flag=${flag}`, `sig=${md5}`]);
    expect(out.flags).toContain(flag);
    expect(out.artifacts.some((a) => a.value === md5)).toBe(true);
  });

  it('ignores empty pieces', () => {
    const out = scanCapture(['', undefined as unknown as string, '']);
    expect(out.flags).toEqual([]);
    expect(out.artifacts).toEqual([]);
  });
});


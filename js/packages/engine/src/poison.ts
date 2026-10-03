/**
 * Deterministic flag poisoning.
 *
 * Hard invariants (AltayCTF 2026 rules):
 *
 *   * a request classified as `checker` is NEVER modified - a poisoned flag the
 *     checker cannot read costs the jury points and looks like a service bug
 *   * a request classified as `unknown` is NEVER modified either; it is treated
 *     as a team, because mislabelling the checker is far more expensive than
 *     missing one poisoning opportunity
 *   * the transform is a pure function of (secret, team, endpoint, flag). The same
 *     team replaying the same request always receives the same poisoned value, so
 *     an attacker cannot fingerprint the defence by repeated probing
 *   * length, character-class profile and flag prefix/suffix are preserved, so
 *     checkers, schema validators and length assertions keep passing
 *
 * Poisoning is disabled unless `flag_format.pattern` is configured. There is no
 * fallback guess.
 */

import { createHmac } from 'node:crypto';
import type { Config } from './config.js';
import { splitEnvelope, xegerToRegex } from './flags.js';

export class PoisonerMisconfigured extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PoisonerMisconfigured';
  }
}

/**
 * Flag bodies stay inside this alphabet so downstream validators that expect
 * [a-z0-9_] keep working.
 */
export const DEFAULT_ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789_';

export type PoisonAction = 'pass_through' | 'poison' | 'disabled';

export interface PoisonDecision {
  action: PoisonAction;
  reason: string;
  value: string | null;
  actor: string;
  teamKey: string;
  poisoned: boolean;
}

function decision(
  action: PoisonAction,
  reason: string,
  init: { value?: string | null; actor?: string; teamKey?: string } = {},
): PoisonDecision {
  const value = init.value ?? null;
  return {
    action,
    reason,
    value,
    actor: init.actor ?? 'unknown',
    teamKey: init.teamKey ?? '',
    poisoned: action === 'poison' && value !== null,
  };
}

export class Poisoner {
  readonly enabled: boolean;
  readonly mask: string | null;
  readonly envelope: [string, string];
  readonly fmtPrefix: string;
  private readonly cfgPattern: string;
  private readonly alphabet: string;
  private readonly secret: Buffer;
  private readonly flagRegex: RegExp;

  constructor(cfg: Config, alphabet = DEFAULT_ALPHABET, secret?: string) {
    this.cfgPattern = cfg.flagFormat.pattern;
    this.fmtPrefix = cfg.flagFormat.prefix;
    this.enabled = cfg.flagFormat.known();
    this.mask = cfg.flagFormat.literalMask();
    this.envelope = this.enabled
      ? splitEnvelope(cfg.flagFormat.pattern)
      : (['', ''] as [string, string]);
    this.alphabet = cfg.flagFormat.bodyAlphabet || alphabet;

    // The key must never come from a published field such as notes, otherwise
    // anyone holding a poisoned flag can recompute the scheme.
    const resolved = secret ?? process.env.AD_POISON_SECRET;
    if (!resolved) {
      throw new PoisonerMisconfigured(
        'AD_POISON_SECRET is not set; refusing to derive the poisoning key from ' +
          'service data. Export a private secret before generating plans.',
      );
    }
    this.secret = Buffer.from(resolved, 'utf8');

    // An unusable pattern must still yield a matcher, or a real flag would pass
    // through unpoisoned while the report claimed poisoning was active.
    this.flagRegex = xegerToRegex(cfg.flagFormat.pattern) ?? new RegExp(
      cfg.flagFormat.pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'),
    );
  }

  decide(
    actor: string,
    teamKey: string,
    endpoint: string,
    flag: string,
  ): PoisonDecision {
    if (!this.enabled) {
      return decision(
        'disabled',
        'flag_format.pattern not configured; poisoning stays off rather than guessing',
        { actor, teamKey },
      );
    }
    if (!flag) {
      return decision('pass_through', 'no flag in payload', { actor, teamKey });
    }
    if (actor === 'checker') {
      return decision(
        'pass_through',
        'checker traffic must always receive the exact flag',
        { actor, teamKey },
      );
    }
    if (actor === 'unknown') {
      return decision(
        'pass_through',
        'unclassified source; refusing to poison to protect the checker',
        { actor, teamKey },
      );
    }
    if (!this.isFlag(flag)) {
      return decision(
        'pass_through',
        'value does not match the configured flag pattern',
        { actor, teamKey },
      );
    }

    return decision(
      'poison',
      `team traffic (${actor}); deterministic per team/endpoint`,
      { value: this.transform(flag, teamKey, endpoint), actor, teamKey },
    );
  }

  /** Rewrite every flag-shaped value in a text blob. */
  poisonText(
    blob: string,
    actor: string,
    teamKey: string,
    endpoint: string,
  ): { text: string; decisions: PoisonDecision[] } {
    const decisions: PoisonDecision[] = [];
    if (!this.enabled) {
      return {
        text: blob,
        decisions: [decision('disabled', 'no flag pattern configured', { actor })],
      };
    }
    const matcher = new RegExp(this.flagRegex.source, this.flagRegex.flags + 'g');
    const text = blob.replace(matcher, (match) => {
      const result = this.decide(actor, teamKey, endpoint, match);
      decisions.push(result);
      return result.value ?? match;
    });
    return { text, decisions };
  }

  isFlag(flag: string): boolean {
    return new RegExp(`^(?:${this.flagRegex.source})$`).test(flag);
  }

  /** Replace the flag body with deterministic, profile-preserving noise. */
  private transform(flag: string, teamKey: string, endpoint: string): string {
    const [prefix, suffix] = this.split(flag);
    const bodyLength = flag.length - prefix.length - suffix.length;
    if (bodyLength <= 0) return flag;
    return prefix + this.noise(teamKey, endpoint, bodyLength) + suffix;
  }

  /** Return the (prefix, suffix) that must survive poisoning. */
  private split(flag: string): [string, string] {
    const mask = this.mask;
    if (mask && mask.length === flag.length) {
      const filled: number[] = [];
      for (let i = 0; i < mask.length; i += 1) {
        if (mask[i] === '_') filled.push(i);
      }
      if (filled.length > 0) {
        const first = filled[0] as number;
        const last = filled[filled.length - 1] as number;
        return [flag.slice(0, first), flag.slice(last + 1)];
      }
    }
    const [prefix, suffix] = this.envelope;
    if (prefix && flag.startsWith(prefix)) {
      if (!suffix || flag.endsWith(suffix)) return [prefix, suffix];
    }
    if (this.fmtPrefix && flag.startsWith(this.fmtPrefix)) {
      return [this.fmtPrefix, ''];
    }
    return ['', ''];
  }

  private noise(teamKey: string, endpoint: string, length: number): string {
    const seed = Buffer.from(`${teamKey}|${endpoint}`, 'utf8');
    const out: string[] = [];
    let counter = 0;
    const counterBuf = Buffer.alloc(4);
    while (out.length < length) {
      counterBuf.writeUInt32BE(counter, 0);
      const mac = createHmac('sha256', this.secret)
        .update(Buffer.concat([seed, counterBuf]))
        .digest();
      for (const byte of mac) {
        out.push(this.alphabet[byte % this.alphabet.length] as string);
        if (out.length >= length) break;
      }
      counter += 1;
    }
    return out.join('');
  }

  describe(): Record<string, unknown> {
    return {
      enabled: this.enabled,
      flag_pattern: this.cfgPattern,
      mask: this.mask,
      prefix: this.fmtPrefix,
      envelope: [...this.envelope],
      alphabet: this.alphabet,
      checker_policy: 'never modify',
      unknown_policy: 'never modify',
      team_policy:
        'deterministic per (team, endpoint), length and charset preserved',
      requires: 'flag_format.pattern in the service config',
      secret_source: 'AD_POISON_SECRET',
    };
  }
}

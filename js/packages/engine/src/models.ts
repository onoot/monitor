/**
 * Shared finding model.
 *
 * Kept separate so the regex pass, the semantic pass and the route pass can all
 * produce findings without importing each other.
 */

import { createHash } from 'node:crypto';

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;

export type Severity = (typeof SEVERITIES)[number];

/**
 * Higher means worse: critical ranks above info.
 *
 * `sortFindings` negates this to order the worst finding first, so do not
 * "simplify" this into an index lookup.
 */
export function severityRank(severity: string): number {
  return SEVERITIES.length - (SEVERITIES.indexOf(severity as Severity) + 1);
}

export function fingerprint(text: string): string {
  return createHash('sha1').update(text.trim(), 'utf8').digest('hex').slice(0, 12);
}

/** 1-based line number of a character offset. */
export function lineOf(text: string, offset: number): number {
  let line = 1;
  const limit = Math.min(offset, text.length);
  for (let i = 0; i < limit; i += 1) {
    if (text.charCodeAt(i) === 10) line += 1;
  }
  return line;
}

export function collapseWhitespace(text: string): string {
  return text.replace(/\s+/g, ' ');
}

/** Squeeze runs of whitespace so a finding payload stays one readable line. */
export function snippetOf(text: string, limit = 500): string {
  return collapseWhitespace(text.trim()).slice(0, limit);
}

export interface Evidence {
  file: string;
  line: number;
  snippet: string;
  fingerprint: string;
}

export interface EvidenceInit {
  file: string;
  line: number;
  snippet: string;
  fingerprint?: string;
}

export function evidence(init: EvidenceInit): Evidence {
  return {
    file: init.file,
    line: init.line,
    snippet: init.snippet,
    fingerprint: init.fingerprint ?? fingerprint(init.snippet),
  };
}

export function evidenceToDict(value: Evidence): Record<string, unknown> {
  return {
    file: value.file,
    line: value.line,
    snippet: value.snippet,
    fingerprint: value.fingerprint,
  };
}

export interface FindingInit {
  ruleId: string;
  category: string;
  title: string;
  severity: Severity | string;
  evidence: Evidence;
  description?: string;
  exploit?: string;
  breaker?: string;
  remediation?: string;
  cwe?: readonly string[];
  sources?: readonly string[];
  confidence?: 'low' | 'medium' | 'high';
}

export interface Finding {
  ruleId: string;
  category: string;
  title: string;
  severity: Severity | string;
  evidence: Evidence;
  description: string;
  exploit: string;
  breaker: string;
  remediation: string;
  cwe: readonly string[];
  sources: readonly string[];
  confidence: 'low' | 'medium' | 'high';
}

/**
 * `breaker` answers "how does this hurt the checker", `exploit` answers "how do
 * teams use it". Both are mandatory on a rule: a finding without them cannot be
 * triaged under the AltayCTF scoring rules.
 */
export function finding(init: FindingInit): Finding {
  return {
    ruleId: init.ruleId,
    category: init.category,
    title: init.title,
    severity: init.severity,
    evidence: init.evidence,
    description: init.description ?? '',
    exploit: init.exploit ?? '',
    breaker: init.breaker ?? '',
    remediation: init.remediation ?? '',
    cwe: init.cwe ?? [],
    sources: init.sources ?? [],
    confidence: init.confidence ?? 'medium',
  };
}

export function findingToDict(value: Finding): Record<string, unknown> {
  return {
    rule_id: value.ruleId,
    category: value.category,
    title: value.title,
    severity: value.severity,
    confidence: value.confidence,
    description: value.description,
    exploit: value.exploit,
    breaker: value.breaker,
    remediation: value.remediation,
    cwe: [...value.cwe],
    rule_sources: [...value.sources],
    evidence: evidenceToDict(value.evidence),
  };
}

export function bySeverity(findings: readonly Finding[], severity: string): Finding[] {
  return findings.filter((item) => item.severity === severity);
}

export function sortFindings(findings: readonly Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    // `severityRank` is higher-is-worse, so negate to put the worst first.
    const rank = severityRank(b.severity) - severityRank(a.severity);
    if (rank !== 0) return rank;
    if (a.ruleId !== b.ruleId) return a.ruleId < b.ruleId ? -1 : 1;
    if (a.evidence.file !== b.evidence.file) return a.evidence.file < b.evidence.file ? -1 : 1;
    return a.evidence.line - b.evidence.line;
  });
}
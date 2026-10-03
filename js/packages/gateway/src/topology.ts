/**
 * The topology graph: who talks to the gateway, and where the gateway sends
 * them, laid out as nodes and edges the dashboard can draw.
 *
 * Everything here is deterministic code. There is no model and no inference:
 * the same config, the same occupied services and the same discovery result
 * always produce byte-identical YAML. That is the point of generating a file
 * rather than computing a picture -- the operator can read `graph.yaml`, diff
 * it between runs, keep it in an incident report, and know that the picture on
 * screen is a rendering of that file and nothing else.
 *
 * A node's `layer` is its column: actors, the gateway, the way in (hosts and
 * ports), and the container an upstream lives in. Edges point along the
 * direction a request travels.
 */

import type { GatewayConfig, PortRoute } from './config.js';
import type { DiscoveryCandidate } from './discovery.js';
import type { Gateway } from './gateway.js';

export interface GraphNode {
  /** Stable across a regeneration, so a diff of two YAMLs lines up. */
  id: string;
  label: string;
  /** actor | team | gateway | host | port | candidate | upstream */
  kind: string;
  /** Column: 0 actors, 1 gateway, 2 way in, 3 upstream. */
  layer: number;
  /** The address, service or group a human needs to make sense of the label. */
  detail: string;
}

export interface GraphEdge {
  from: string;
  to: string;
  /** What the edge means: `трафик`, `host`, `порт`, `свободен`, a service name. */
  label: string;
}

export interface Topology {
  version: number;
  generatedAt: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface TopologyInput {
  config: GatewayConfig;
  /** Only `network` is read; the map is the ground truth for actors. */
  ingress: Pick<Gateway, 'network'>;
  /** The services the gateway is currently listening for. */
  services: readonly PortRoute[];
  /** Discovery output; ports already occupied are not repeated. */
  candidates?: readonly DiscoveryCandidate[];
  now?: Date;
}

export function buildTopology(input: TopologyInput): Topology {
  const { config, ingress, services } = input;
  const candidates = input.candidates ?? [];
  const now = input.now ?? new Date();

  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const nodeIds = new Set<string>();
  const edgeKeys = new Set<string>();

  function addNode(node: GraphNode): boolean {
    if (nodeIds.has(node.id)) return false;
    nodeIds.add(node.id);
    nodes.push(node);
    return true;
  }
  function addEdge(edge: GraphEdge): void {
    const key = `${edge.from}\u0000${edge.to}\u0000${edge.label}`;
    if (edgeKeys.has(key)) return;
    edgeKeys.add(key);
    edges.push(edge);
  }

  // Actors come from the network map, not from observed traffic: the config is
  // written down before the run, so a team that has not sent a packet yet is
  // still a path on the diagram.
  const described = ingress.network.describe();
  for (const kind of ['checker', 'admin'] as const) {
    const cidrs = described.filter((d) => d.kind === kind).map((d) => d.cidr);
    if (cidrs.length > 0) {
      addNode({ id: `actor:${kind}`, label: kind, kind: 'actor', layer: 0, detail: cidrs.join(', ') });
    }
  }
  const teamNames = [...new Set(described.filter((d) => d.kind === 'team').map((d) => d.team ?? 'team'))].sort();
  for (const team of teamNames) {
    const cidrs = described
      .filter((d) => d.kind === 'team' && (d.team ?? 'team') === team)
      .map((d) => d.cidr);
    addNode({ id: `actor:team:${team}`, label: `team ${team}`, kind: 'team', layer: 0, detail: cidrs.join(', ') });
  }

  const redirect = config.redirectOffset > 0 ? ` (+${config.redirectOffset})` : '';
  addNode({
    id: 'gateway',
    label: 'gateway',
    kind: 'gateway',
    layer: 1,
    detail: `ingress ${config.listen.host}:${config.listen.port}${redirect}, analytics ${config.analyticsListen.host}:${config.analyticsListen.port}`,
  });
  for (const node of nodes.filter((n) => n.kind === 'actor')) {
    addEdge({ from: node.id, to: 'gateway', label: 'трафик' });
  }

  function upstream(upstreamAddr: string, service: string): string {
    const id = `up:${upstreamAddr}`;
    addNode({ id, label: upstreamAddr, kind: 'upstream', layer: 3, detail: `service ${service}` });
    return id;
  }

  // Hostname routes: the client asks for a name, the config resolves it.
  const routes = [...config.routes.values()].sort((a, b) => a.host.localeCompare(b.host));
  for (const route of routes) {
    const hostId = `host:${route.host}`;
    addNode({ id: hostId, label: route.host, kind: 'host', layer: 2, detail: `service ${route.service}` });
    addEdge({ from: 'gateway', to: hostId, label: 'host' });
    addEdge({ from: hostId, to: upstream(route.upstream, route.service), label: route.service });
  }

  // Port routes: the client dials a port, the listener decides.
  const occupied = new Set(services.map((s) => s.publicPort));
  for (const entry of [...services].sort((a, b) => a.publicPort - b.publicPort)) {
    const portId = `port:${entry.publicPort}`;
    addNode({ id: portId, label: `:${entry.publicPort}`, kind: 'port', layer: 2, detail: `service ${entry.service}` });
    addEdge({ from: 'gateway', to: portId, label: 'порт' });
    addEdge({ from: portId, to: upstream(entry.upstream, entry.service), label: entry.service });
  }

  // Discovered but not occupied: a dashed possibility, not a live path. Drawn
  // so the operator can see what the scan found before occupying it.
  for (const candidate of candidates) {
    if (occupied.has(candidate.publicPort)) continue;
    const id = `svc:${candidate.group}:${candidate.service}:${candidate.publicPort}`;
    addNode({
      id,
      label: `${candidate.service}:${candidate.publicPort}`,
      kind: 'candidate',
      layer: 2,
      detail: candidate.group,
    });
    addEdge({ from: 'gateway', to: id, label: 'свободен' });
    addEdge({ from: id, to: upstream(candidate.upstream, candidate.service), label: candidate.service });
  }

  // Deterministic order: layer first, then label, then id to break ties.
  nodes.sort((a, b) => a.layer - b.layer || a.label.localeCompare(b.label) || a.id.localeCompare(b.id));
  return { version: 1, generatedAt: now.toISOString(), nodes, edges };
}

/** A scalar as YAML: every string is a JSON string, so quoting is never a guess. */
function yamlScalar(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return JSON.stringify(String(value));
}

function yamlPair(key: string, value: unknown, indent: number): string[] {
  const pad = ' '.repeat(indent);
  if (value !== null && typeof value === 'object') {
    return [`${pad}${key}:`, ...toYaml(value, indent + 2)];
  }
  return [`${pad}${key}: ${yamlScalar(value)}`];
}

/**
 * A small block-style YAML emitter. It handles exactly the shapes this file
 * produces -- objects, arrays and scalars -- and quotes every string, so the
 * output is valid YAML with no reliance on a parser guessing types.
 */
export function toYaml(value: unknown, indent = 0): string[] {
  const pad = ' '.repeat(indent);
  if (Array.isArray(value)) {
    const lines: string[] = [];
    for (const item of value) {
      if (item !== null && typeof item === 'object' && !Array.isArray(item)) {
        const entries = Object.entries(item as Record<string, unknown>);
        const first = entries[0];
        if (first === undefined) {
          lines.push(`${pad}- {}`);
          continue;
        }
        const [firstKey, firstValue] = first;
        if (firstValue !== null && typeof firstValue === 'object') {
          lines.push(`${pad}- ${firstKey}:`);
          lines.push(...toYaml(firstValue, indent + 4));
        } else {
          lines.push(`${pad}- ${firstKey}: ${yamlScalar(firstValue)}`);
        }
        for (const [key, val] of entries.slice(1)) {
          lines.push(...yamlPair(key, val, indent + 2));
        }
      } else {
        lines.push(`${pad}- ${yamlScalar(item)}`);
      }
    }
    return lines;
  }
  if (value !== null && typeof value === 'object') {
    return Object.entries(value as Record<string, unknown>).flatMap(([key, val]) =>
      yamlPair(key, val, indent),
    );
  }
  return [`${pad}${yamlScalar(value)}`];
}

export function topologyToYaml(topology: Topology): string {
  return `${toYaml(topology).join('\n')}\n`;
}

interface YamlLine {
  indent: number;
  text: string;
}

/**
 * The reader for the emitter above. It lives here, next to the writer, so a
 * round-trip test can prove they agree; the dashboard carries the same routine
 * so it can draw straight from the served YAML.
 */
export function parseYaml(text: string): unknown {
  const lines: YamlLine[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const trimmed = raw.trim();
    if (trimmed === '' || trimmed.startsWith('#')) continue;
    lines.push({ indent: raw.length - raw.replace(/^\s+/, '').length, text: trimmed });
  }

  function scalar(token: string): unknown {
    if (token.startsWith('"')) return JSON.parse(token) as unknown;
    if (token === 'null' || token === '~') return null;
    if (token === 'true') return true;
    if (token === 'false') return false;
    if (/^-?\d+$/.test(token)) return Number.parseInt(token, 10);
    if (/^-?\d+\.\d+$/.test(token)) return Number.parseFloat(token);
    return token;
  }

  function block(indent: number): unknown {
    const at = lines[index];
    if (at !== undefined && at.indent === indent && at.text.startsWith('- ')) {
      const list: unknown[] = [];
      while (index < lines.length && lines[index]!.indent === indent && lines[index]!.text.startsWith('- ')) {
        const content = lines[index]!.text.slice(2);
        index += 1;
        const colon = content.indexOf(': ');
        if (colon > 0 && !content.startsWith('"')) {
          const item: Record<string, unknown> = {};
          item[content.slice(0, colon)] = scalar(content.slice(colon + 2));
          while (index < lines.length && lines[index]!.indent > indent) {
            const next = lines[index]!;
            const split = next.text.indexOf(': ');
            if (split < 0) break;
            item[next.text.slice(0, split)] = scalar(next.text.slice(split + 2));
            index += 1;
          }
          list.push(item);
        } else {
          list.push(scalar(content));
        }
      }
      return list;
    }

    const map: Record<string, unknown> = {};
    while (index < lines.length && lines[index]!.indent === indent && !lines[index]!.text.startsWith('- ')) {
      const line = lines[index]!;
      const colon = line.text.indexOf(':');
      const key = line.text.slice(0, colon);
      const rest = line.text.slice(colon + 1).trim();
      index += 1;
      if (rest === '') {
        map[key] = block(index < lines.length ? lines[index]!.indent : indent + 2);
      } else {
        map[key] = scalar(rest);
      }
    }
    return map;
  }

  let index = 0;
  return block(lines[0]?.indent ?? 0);
}

/** Read back a generated topology, with just enough checking to catch a stale schema. */
export function parseTopologyYaml(text: string): Topology {
  const value = parseYaml(text) as Partial<Topology>;
  if (typeof value.version !== 'number' || !Array.isArray(value.nodes) || !Array.isArray(value.edges)) {
    throw new Error('not a topology document');
  }
  return {
    version: value.version,
    generatedAt: typeof value.generatedAt === 'string' ? value.generatedAt : '',
    nodes: value.nodes as GraphNode[],
    edges: value.edges as GraphEdge[],
  };
}

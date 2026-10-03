/**
 * Bringing a watched service project up (and down) from the dashboard.
 *
 * The stand may run with the host Docker socket mounted, so the operator can
 * start a service project with its own compose file without leaving the
 * dashboard: the UI scans the services folder, shows one card per folder, and
 * the launch button here runs `docker compose up -d --build` in that folder.
 *
 * The module is deliberately small and paranoid:
 *
 *  - A group name is only ever joined to the scan root after it is checked to be
 *    one plain path segment, and the resolved child is checked to still sit
 *    under the root, so a request can never walk out of the services directory.
 *  - Only a real compose file makes a folder launchable; a directory with no
 *    compose is not offered.
 *  - The launched project does not publish its ports on the host. The gateway
 *    owns the port a checker dials; a service that published `0.0.0.0:8083`
 *    would be a way around the gateway. An override file resets `ports` off, so
 *    the service is reachable only by its compose name on its own network.
 *  - After `up`, the container this process runs in is attached to whatever
 *    networks the project created, because the gateway can only reach a service
 *    by its compose DNS name if it is on the same network.
 *
 * Everything runs the `docker` CLI against the mounted socket. A missing socket
 * is reported as an error result rather than thrown, so a stand without the
 * socket keeps working for everything except launching.
 */

import { execFile } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

const COMPOSE_FILES = ['docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml'];
/** One path segment: a service folder name the operator chose, nothing else. */
const GROUP_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]*$/;

/**
 * An override that keeps the watched project off the host ports.
 *
 * A service compose publishes its ports (`0.0.0.0:8083:8083`) so it can be
 * reached from the host. On the stand that is a second way in that bypasses the
 * gateway entirely, and on a real network it does not exist: the port belongs to
 * whoever stands in front. Lists merge across compose files, so a plain
 * `ports: []` would remove nothing -- the `!reset` tag replaces the list with an
 * empty one. The service stays reachable by its compose name on the networks it
 * creates, which is all the gateway needs.
 */
function internalOverride(names: readonly string[]): string {
  return [
    'services:',
    ...names.flatMap((name) => [`  ${JSON.stringify(name)}:`, '    ports: !reset []']),
    '',
  ].join('\n');
}

/** Service names a compose file declares, read through the CLI so env/interpolation are honoured. */
async function composeServiceNames(compose: string, run: Exec): Promise<string[]> {
  const res = await run('docker', ['compose', '-f', compose, 'config', '--services'], 60_000);
  if (res.code !== 0) return [];
  return res.stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

/** A bind mount as the resolved compose model reports it. */
interface BindVolume {
  type?: string;
  source?: string;
  target?: string;
}

/**
 * Bind volumes of every service with their sources already resolved by the CLI.
 *
 * A service is started from inside this container, so the CLI resolves a
 * relative source like `./database/data` against this container's view of the
 * services folder (`/services/...`). The Docker daemon runs elsewhere and reads
 * that as a path of its own -- an empty directory -- so the service would start
 * with no data. These volumes are what gets re-pointed at the host path.
 */
async function composeBindVolumes(
  compose: string,
  run: Exec,
): Promise<Record<string, BindVolume[]>> {
  const res = await run('docker', ['compose', '-f', compose, 'config', '--format', 'json'], 60_000);
  if (res.code !== 0) return {};
  let model: { services?: Record<string, { volumes?: BindVolume[] }> };
  try {
    model = JSON.parse(res.stdout) as { services?: Record<string, { volumes?: BindVolume[] }> };
  } catch {
    return {};
  }
  const out: Record<string, BindVolume[]> = {};
  for (const [name, service] of Object.entries(model.services ?? {})) {
    const binds = (service?.volumes ?? []).filter(
      (v): v is Required<BindVolume> =>
        v?.type === 'bind' && typeof v.source === 'string' && typeof v.target === 'string',
    );
    if (binds.length > 0) out[name] = binds;
  }
  return out;
}

/** Forward-slash host path with no trailing separator, the form the daemon takes. */
function hostPath(value: string): string {
  return value.replace(/\\/g, '/').replace(/\/+$/, '');
}

/**
 * The host folder the scan root is mounted from.
 *
 * This process sees the services folder at `root`; the daemon does not. The
 * mapping is read from this container's own bind mounts, whose source is the
 * real host path. The configured host directory is only a fallback for a
 * container whose mounts cannot be inspected.
 */
async function hostServicesRoot(root: string, self: string, run: Exec): Promise<string | null> {
  const wanted = hostPath(root);
  const res = await run('docker', ['inspect', '--format', '{{json .Mounts}}', self], 30_000);
  if (res.code === 0) {
    try {
      const mounts = JSON.parse(res.stdout) as Array<{ Source?: string; Destination?: string }>;
      for (const mount of mounts) {
        if (typeof mount.Source !== 'string') continue;
        if (hostPath(mount.Destination ?? '') === wanted) return hostPath(mount.Source);
      }
    } catch {
      /* an unreadable inspect falls through to the environment hint */
    }
  }
  const hint = hostPath(process.env.AD_SERVICES_HOST_DIR ?? '');
  if (hint.length > 0 && hint !== wanted && /^([A-Za-z]:\/|\/)/.test(hint)) return hint;
  return null;
}

/**
 * An override that re-points every relative bind volume at its host path.
 *
 * Lists merge by mount target, so an entry here replaces the base one rather
 * than adding a second mount. Only sources under the scan root are rewritten;
 * a named volume or a path the operator wrote absolute is left alone.
 */
function hostVolumeOverride(
  volumes: Record<string, BindVolume[]>,
  root: string,
  hostRoot: string,
): string | null {
  const wanted = hostPath(root);
  const lines: string[] = ['services:'];
  for (const [name, binds] of Object.entries(volumes)) {
    const rewritten: string[] = [];
    for (const bind of binds) {
      const source = hostPath(bind.source ?? '');
      if (!source.startsWith(wanted + '/')) continue;
      rewritten.push('      - type: bind');
      rewritten.push(`        source: ${JSON.stringify(hostRoot + source.slice(wanted.length))}`);
      rewritten.push(`        target: ${JSON.stringify(bind.target)}`);
    }
    if (rewritten.length > 0) {
      lines.push(`  ${JSON.stringify(name)}:`);
      lines.push('    volumes:');
      lines.push(...rewritten);
    }
  }
  return lines.length > 1 ? lines.join('\n') + '\n' : null;
}

export interface LaunchResult {
  ok: boolean;
  group: string;
  dir: string | null;
  compose: string | null;
  /** Networks the monitoring container was attached to for this project. */
  networks: string[];
  stdout: string;
  stderr: string;
  error?: string;
}

interface ExecResult {
  code: number;
  stdout: string;
  stderr: string;
}

export type Exec = (file: string, args: string[], timeoutMs: number) => Promise<ExecResult>;

function exec(file: string, args: string[], timeoutMs: number): Promise<ExecResult> {
  return new Promise((resolve) => {
    execFile(
      file,
      args,
      { timeout: timeoutMs, maxBuffer: 8 * 1024 * 1024, windowsHide: true },
      (err, stdout, stderr) => {
        const code =
          err === null
            ? 0
            : typeof (err as { code?: unknown }).code === 'number'
              ? ((err as { code: number }).code)
              : 1;
        resolve({ code, stdout: String(stdout ?? ''), stderr: String(stderr ?? '') });
      },
    );
  });
}

/** One service folder and the compose file that would launch it. */
export interface ServiceProject {
  group: string;
  dir: string;
  compose: string;
}

/**
 * Resolve a group name to its folder, or null when it is not a launchable
 * service. The name must be a single segment and the resolved path must still be
 * under the root; both checks are kept even though one would usually imply the
 * other, because this is the one place a user string becomes a filesystem path.
 */
export function serviceProject(root: string, group: string): ServiceProject | null {
  if (!GROUP_RE.test(group)) return null;
  const base = path.resolve(root);
  const dir = path.resolve(base, group);
  if (dir !== base && !dir.startsWith(base + path.sep)) return null;
  let stat;
  try {
    stat = statSync(dir);
  } catch {
    return null;
  }
  if (!stat.isDirectory()) return null;
  for (const name of COMPOSE_FILES) {
    const compose = path.join(dir, name);
    if (existsSync(compose)) return { group, dir, compose };
  }
  return null;
}

/** Every direct child of the scan root that carries a compose file. */
export function listServiceProjects(root: string): ServiceProject[] {
  let entries: string[];
  try {
    entries = readdirSync(root);
  } catch {
    return [];
  }
  const out: ServiceProject[] = [];
  for (const name of entries) {
    const project = serviceProject(root, name);
    if (project !== null) out.push(project);
  }
  out.sort((a, b) => a.group.localeCompare(b.group));
  return out;
}

/** Networks the containers of a compose project are attached to. */
async function projectNetworks(compose: string, run: Exec): Promise<string[]> {
  const ps = await run('docker', ['compose', '-f', compose, 'ps', '-q'], 30_000);
  const ids = ps.stdout.split(/\s+/).filter(Boolean);
  if (ids.length === 0) return [];
  const inspect = await run(
    'docker',
    ['inspect', '--format', '{{json .NetworkSettings.Networks}}', ...ids],
    30_000,
  );
  const names = new Set<string>();
  for (const line of inspect.stdout.split(/\r?\n/)) {
    const text = line.trim();
    if (text.length === 0) continue;
    try {
      for (const key of Object.keys(JSON.parse(text) as Record<string, unknown>)) names.add(key);
    } catch {
      /* an unparsable inspect line is skipped, never fatal */
    }
  }
  return [...names];
}

/** Attach this container to each network, tolerating "already connected". */
async function attachSelf(networks: string[], self: string, run: Exec): Promise<string[]> {
  const attached: string[] = [];
  for (const network of networks) {
    const res = await run('docker', ['network', 'connect', network, self], 30_000);
    if (res.code === 0 || /already (exists|connected)/i.test(res.stderr)) attached.push(network);
  }
  return attached;
}

export interface LaunchOptions {
  /** Container name of the process doing the launching (the gateway itself). */
  self: string;
  /** Injectable for tests; defaults to the real docker CLI. */
  run?: Exec;
  build?: boolean;
  /**
   * Publish the project's ports on the host. Off by default: the gateway owns
   * the ports, and a host-published port is a way around it. Set true only to
   * debug a service directly.
   */
  publishPorts?: boolean;
}

export async function launchService(
  root: string,
  group: string,
  options: LaunchOptions,
): Promise<LaunchResult> {
  const run = options.run ?? exec;
  const project = serviceProject(root, group);
  if (project === null) {
    return {
      ok: false,
      group,
      dir: null,
      compose: null,
      networks: [],
      stdout: '',
      stderr: '',
      error: `no compose file for service "${group}" under ${root}`,
    };
  }
  const composeArgs = ['-f', project.compose];
  const tempDirs: string[] = [];
  const addOverride = (name: string, text: string): void => {
    try {
      const dir = mkdtempSync(path.join(tmpdir(), 'ad-launch-'));
      const file = path.join(dir, name);
      writeFileSync(file, text, 'utf8');
      tempDirs.push(dir);
      composeArgs.push('-f', file);
    } catch {
      /* an override that cannot be written is skipped, never fatal */
    }
  };

  const hostRoot = await hostServicesRoot(root, options.self, run);
  if (hostRoot !== null) {
    const hostOverride = hostVolumeOverride(
      await composeBindVolumes(project.compose, run),
      root,
      hostRoot,
    );
    if (hostOverride !== null) addOverride('volumes-host.yml', hostOverride);
  }

  if (options.publishPorts !== true) {
    const names = await composeServiceNames(project.compose, run);
    if (names.length > 0) addOverride('ports-internal.yml', internalOverride(names));
  }

  const args = ['compose', ...composeArgs, 'up', '-d'];
  if (options.build !== false) args.push('--build');
  let res: ExecResult;
  try {
    res = await run('docker', args, 600_000);
  } finally {
    for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
  }
  if (res.code !== 0) {
    return {
      ok: false,
      group,
      dir: project.dir,
      compose: project.compose,
      networks: [],
      stdout: res.stdout,
      stderr: res.stderr,
      error: (res.stderr || res.stdout || `docker compose exited with ${res.code}`).trim(),
    };
  }
  const networks = await projectNetworks(project.compose, run);
  const attached = await attachSelf(networks, options.self, run);
  return {
    ok: true,
    group,
    dir: project.dir,
    compose: project.compose,
    networks: attached,
    stdout: res.stdout,
    stderr: res.stderr,
  };
}

export async function stopService(
  root: string,
  group: string,
  options: LaunchOptions,
): Promise<LaunchResult> {
  const run = options.run ?? exec;
  const project = serviceProject(root, group);
  if (project === null) {
    return {
      ok: false,
      group,
      dir: null,
      compose: null,
      networks: [],
      stdout: '',
      stderr: '',
      error: `no compose file for service "${group}" under ${root}`,
    };
  }
  const res = await run('docker', ['compose', '-f', project.compose, 'down'], 300_000);
  if (res.code !== 0) {
    return {
      ok: false,
      group,
      dir: project.dir,
      compose: project.compose,
      networks: [],
      stdout: res.stdout,
      stderr: res.stderr,
      error: (res.stderr || res.stdout || `docker compose exited with ${res.code}`).trim(),
    };
  }
  return {
    ok: true,
    group,
    dir: project.dir,
    compose: project.compose,
    networks: [],
    stdout: res.stdout,
    stderr: res.stderr,
  };
}

/** Whether a project currently has running containers, for the UI's badge. */
export interface ServiceStatus {
  group: string;
  running: boolean;
  containers: number;
}

/**
 * Is this project up? `docker compose ps -q` lists only running containers, so
 * a non-empty id list means the project was launched (and not stopped since).
 * A missing compose file or a docker error reads as "not running" rather than
 * failing, because the badge is advisory and the stand may run without a socket.
 */
export async function serviceStatus(
  root: string,
  group: string,
  options: { run?: Exec } = {},
): Promise<ServiceStatus> {
  const run = options.run ?? exec;
  const project = serviceProject(root, group);
  if (project === null) return { group, running: false, containers: 0 };
  const res = await run('docker', ['compose', '-f', project.compose, 'ps', '-q'], 30_000);
  const ids = res.stdout.split(/\s+/).filter((id) => id.length > 0);
  return { group, running: ids.length > 0, containers: ids.length };
}

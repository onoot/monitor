import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';

import { launchService, listServiceProjects, serviceProject, serviceStatus, stopService } from '../src/launcher.js';

function fixture(): string {
  const root = mkdtempSync(path.join(tmpdir(), 'ad-services-'));
  mkdirSync(path.join(root, 'curs'));
  writeFileSync(path.join(root, 'curs', 'docker-compose.yml'), 'services: {}\n');
  mkdirSync(path.join(root, 'coins'));
  writeFileSync(path.join(root, 'coins', 'compose.yaml'), 'services: {}\n');
  mkdirSync(path.join(root, 'empty'));
  mkdirSync(path.join(root, 'notes'));
  writeFileSync(path.join(root, 'notes', 'readme.md'), 'no compose here\n');
  return root;
}

describe('service launcher', () => {
  it('lists only folders that carry a compose file', () => {
    const root = fixture();
    try {
      assert.deepEqual(
        listServiceProjects(root).map((p) => p.group),
        ['coins', 'curs'],
      );
      assert.equal(serviceProject(root, 'empty'), null);
      assert.equal(serviceProject(root, 'notes'), null);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('refuses a name that is not one plain path segment', () => {
    const root = fixture();
    try {
      assert.equal(serviceProject(root, '..'), null);
      assert.equal(serviceProject(root, '../etc'), null);
      assert.equal(serviceProject(root, 'curs/../coins'), null);
      assert.equal(serviceProject(root, '/etc'), null);
      assert.notEqual(serviceProject(root, 'curs'), null);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('launches a project, then attaches to the networks it created', async () => {
    const root = fixture();
    const calls: string[][] = [];
    const run = async (file: string, args: string[]): Promise<{ code: number; stdout: string; stderr: string }> => {
      calls.push([file, ...args]);
      const command = args.join(' ');
      if (command.startsWith('compose') && command.includes('up')) return { code: 0, stdout: 'started', stderr: '' };
      if (command.includes('ps -q')) return { code: 0, stdout: 'abc123\n', stderr: '' };
      if (command.includes('inspect')) return { code: 0, stdout: '{"cursnet":{}}\n', stderr: '' };
      return { code: 0, stdout: '', stderr: '' };
    };
    try {
      const result = await launchService(root, 'curs', { self: 'ad-monitoring', run });
      assert.equal(result.ok, true);
      assert.deepEqual(result.networks, ['cursnet']);
      assert.equal(result.compose, path.join(root, 'curs', 'docker-compose.yml'));
      const connect = calls.find((c) => c[1] === 'network' && c[2] === 'connect');
      assert.deepEqual(connect, ['docker', 'network', 'connect', 'cursnet', 'ad-monitoring']);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('launches with host ports reset off, so only the gateway owns them', async () => {
    const root = fixture();
    const calls: string[][] = [];
    let overrideText = '';
    const run = async (file: string, args: string[]): Promise<{ code: number; stdout: string; stderr: string }> => {
      calls.push([file, ...args]);
      const command = args.join(' ');
      if (command.includes('config --services')) return { code: 0, stdout: 'postgres\nweb\n', stderr: '' };
      if (command.includes('up')) {
        overrideText = readFileSync(args[args.lastIndexOf('-f') + 1] as string, 'utf8');
        return { code: 0, stdout: 'started', stderr: '' };
      }
      return { code: 0, stdout: '', stderr: '' };
    };
    try {
      const result = await launchService(root, 'curs', { self: 'ad-monitoring', run });
      assert.equal(result.ok, true);
      const up = calls.find((c) => c.join(' ').includes('up')) as string[];
      const firstF = up.indexOf('-f');
      const lastF = up.lastIndexOf('-f');
      assert.equal(up[firstF + 1], path.join(root, 'curs', 'docker-compose.yml'));
      assert.notEqual(lastF, firstF);
      assert.match(overrideText, /ports: !reset \[\]/);
      assert.match(overrideText, /"postgres":/);
      assert.match(overrideText, /"web":/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('keeps the host ports when asked to publish them', async () => {
    const root = fixture();
    const calls: string[][] = [];
    const run = async (file: string, args: string[]): Promise<{ code: number; stdout: string; stderr: string }> => {
      calls.push([file, ...args]);
      return { code: 0, stdout: '', stderr: '' };
    };
    try {
      await launchService(root, 'curs', { self: 'ad-monitoring', run, publishPorts: true });
      const up = calls.find((c) => c.join(' ').includes('up')) as string[];
      assert.equal(up.filter((a) => a === '-f').length, 1);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('rewrites relative bind volumes to the host path they are mounted from', async () => {
    const root = fixture();
    const calls: string[][] = [];
    const hostServices = 'C:\\host\\services';
    let override = '';
    const run = async (
      file: string,
      args: string[],
    ): Promise<{ code: number; stdout: string; stderr: string }> => {
      calls.push([file, ...args]);
      const command = args.join(' ');
      if (command.includes('inspect') && command.includes('Mounts')) {
        return {
          code: 0,
          stdout: JSON.stringify([{ Source: hostServices, Destination: root }]),
          stderr: '',
        };
      }
      if (command.includes('config --format json')) {
        return {
          code: 0,
          stdout: JSON.stringify({
            services: {
              db: {
                volumes: [
                  {
                    type: 'bind',
                    source: `${root.replace(/\\/g, '/')}/database/data`,
                    target: '/var/lib/db',
                  },
                ],
              },
            },
          }),
          stderr: '',
        };
      }
      if (command.includes('up')) {
        override = readFileSync(args[args.lastIndexOf('-f') + 1] as string, 'utf8');
        return { code: 0, stdout: 'started', stderr: '' };
      }
      return { code: 0, stdout: '', stderr: '' };
    };
    try {
      const result = await launchService(root, 'curs', {
        self: 'ad-monitoring',
        run,
        publishPorts: true,
      });
      assert.equal(result.ok, true);
      assert.match(override, /source: "C:\/host\/services\/database\/data"/);
      assert.match(override, /target: "\/var\/lib\/db"/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('reports a compose failure instead of throwing', async () => {
    const root = fixture();
    const run = async (): Promise<{ code: number; stdout: string; stderr: string }> => ({
      code: 1,
      stdout: '',
      stderr: 'no space left on device',
    });
    try {
      const result = await launchService(root, 'curs', { self: 'ad-monitoring', run });
      assert.equal(result.ok, false);
      assert.match(result.error ?? '', /no space left/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('reports a project as running when compose lists container ids', async () => {
    const root = fixture();
    const run = async (): Promise<{ code: number; stdout: string; stderr: string }> => ({
      code: 0,
      stdout: 'abc123\ndef456\n',
      stderr: '',
    });
    try {
      const status = await serviceStatus(root, 'curs', { run });
      assert.deepEqual(status, { group: 'curs', running: true, containers: 2 });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('reports a folder with no compose as not running without calling docker', async () => {
    const root = fixture();
    let called = false;
    const run = async (): Promise<{ code: number; stdout: string; stderr: string }> => {
      called = true;
      return { code: 0, stdout: '', stderr: '' };
    };
    try {
      const status = await serviceStatus(root, 'notes', { run });
      assert.deepEqual(status, { group: 'notes', running: false, containers: 0 });
      assert.equal(called, false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('stops a project with its own compose file', async () => {
    const root = fixture();
    const calls: string[][] = [];
    const run = async (file: string, args: string[]): Promise<{ code: number; stdout: string; stderr: string }> => {
      calls.push([file, ...args]);
      return { code: 0, stdout: '', stderr: '' };
    };
    try {
      const result = await stopService(root, 'coins', { self: 'ad-monitoring', run });
      assert.equal(result.ok, true);
      assert.deepEqual(calls[0], [
        'docker',
        'compose',
        '-f',
        path.join(root, 'coins', 'compose.yaml'),
        'down',
      ]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

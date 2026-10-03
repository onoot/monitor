#!/usr/bin/env node
/** Thin entry point: all behaviour lives in dist/cli.js. */

import process from 'node:process';
import { run } from '../dist/cli.js';

const { code, out, err } = run(process.argv.slice(2));
for (const line of out) process.stdout.write(`${line}\n`);
for (const line of err) process.stderr.write(`${line}\n`);
process.exitCode = code;

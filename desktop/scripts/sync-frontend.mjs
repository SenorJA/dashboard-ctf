#!/usr/bin/env node
/**
 * sync-frontend.mjs — copy the canonical MIRV SPA into desktop/src
 *
 * Tauri bundles whatever is in desktop/src (tauri.conf.json -> frontendDist).
 * Instead of maintaining a divergent copy by hand, we copy from the repo's
 * canonical frontend/ (index.html, css/, js/, img/) before each build.
 *
 * The canonical main.v2.js already contains the Tauri API/WS base detection,
 * so no per-file rewrite is required. Credits to the upstream sources.
 */

import { cpSync, mkdirSync, existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const desktopRoot = resolve(here, '..');
const repoRoot = resolve(desktopRoot, '..');
const srcRoot = resolve(desktopRoot, 'src');

const sources = ['index.html', 'css', 'js', 'img'];
const missing = [];

for (const item of sources) {
  const from = resolve(repoRoot, 'frontend', item);
  const to = resolve(srcRoot, item);
  if (!existsSync(from)) {
    missing.push(from);
    continue;
  }
  mkdirSync(dirname(to), { recursive: true });
  cpSync(from, to, { recursive: true, force: true });
}

if (missing.length) {
  console.error('[sync-frontend] Missing frontend sources:\n  ' + missing.join('\n  '));
  process.exit(1);
}

console.log('[sync-frontend] Copied frontend/ -> desktop/src/ (ok)');

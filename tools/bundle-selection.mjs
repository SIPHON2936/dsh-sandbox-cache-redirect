#!/usr/bin/env node
/**
 * Offline bundle selection for profiles without a GUI (e.g. headless).
 *
 * Calls the DSH bundle-list write interfaces directly — it changes only the
 * profile's bundle SELECTION, never dependencies or YAML, and it is not a
 * resident guard. Run it only while the profile's Host/HMR is stopped and a
 * backup exists; afterwards restart the profile and verify with
 * --dump-config that the bundle layer actually (un)loaded — a saved
 * selection is not proof that the enhancement changed state.
 *
 * Usage:
 *   node tools/bundle-selection.mjs <dsh-cli-path> <profile-dir> enable|disable
 *
 * enable reads the profile's existing exact-version exemptions from
 * compatibility.json (identical to the manager); it never grants, widens,
 * or edits exemptions. disable does not import the target entry and does
 * not require the bundle to be compatible or even loadable, so it stays a
 * usable recovery operation when the bundle's YAML or entry is broken.
 */
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
const [cli, dir, action] = process.argv.slice(2);
if (!['enable', 'disable'].includes(action)) throw new Error('invalid action');
const require = createRequire(fs.realpathSync.native(cli));
const boot = await import(pathToFileURL(require.resolve('@deepseek-ai/dsh-app-boot')).href);
const { withFileLock } = await import(pathToFileURL(require.resolve('@deepseek-ai/dsh-atomic-write')).href);
const name = 'dsh-sandbox-cache-redirect';
await withFileLock(path.join(dir, 'package.json'), async () => {
  const manifest = boot.readProfileManifest('dsh-v7-selection', dir);
  const before = manifest.dsh?.profile?.bundles;
  if (!Array.isArray(before)) throw new Error('profile has no bundle list');
  if (action === 'enable') {
    const file = path.join(dir, 'node_modules', name, 'package.json');
    const installed = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (installed.name !== name || !installed.dsh?.bundle) throw new Error('bundle not installed');
    const issue = boot.evaluatePluginCompatibility(installed, boot.readProfileVersionExemptions(dir));
    if (issue && !issue.exempted) throw new Error('bundle incompatible with this Host');
  }
  const next = action === 'disable' ? before.filter(value => value !== name)
    : before.includes(name) ? before : [...before, name];
  if (JSON.stringify(before) !== JSON.stringify(next)) {
    boot.writeProfileBundles(dir, manifest, next);
  }
}, { waitMs: 1000 });
console.log('BUNDLE_SELECTION_SAVED; restart this stopped profile');

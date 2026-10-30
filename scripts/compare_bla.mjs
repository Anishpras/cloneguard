#!/usr/bin/env node
/** Optional comparison against user-supplied, pinned temporary BLA/REA checkouts. */
import {readFileSync, writeFileSync, chmodSync, existsSync} from 'node:fs';
import {resolve, join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';

const args = process.argv.slice(2);
function argument(name, required = true) {
  const index = args.indexOf(name);
  const value = index >= 0 ? args[index + 1] : null;
  if (required && (!value || value.startsWith('--'))) throw new Error(`Missing ${name}`);
  return value;
}
function run(command, parameters, options = {}) {
  const result = spawnSync(command, parameters, {encoding: 'utf8', timeout: 120000, maxBuffer: 2 * 1024 * 1024, ...options});
  return {exit: result.status, signal: result.signal, error: result.error?.code ?? null,
    stdout: (result.stdout ?? '').trim(), stderr: (result.stderr ?? '').trim()};
}
function exclusiveJson(path, data) {
  writeFileSync(path, JSON.stringify(data, null, 2) + '\n', {flag: 'wx'});
}

try {
  const bla = resolve(argument('--bla-root'));
  const swift = resolve(argument('--swift-dir'));
  const out = resolve(argument('--out'));
  const reaValue = argument('--rea-root', false);
  const rea = reaValue ? resolve(reaValue) : null;
  if (existsSync(out)) throw new Error('Output already exists');
  const {protectNativeBinary} = await import(pathToFileURL(join(bla, 'dist/shields/formats/native.js')));
  const {protectApplePlistBuffer} = await import(pathToFileURL(join(bla, 'dist/shields/formats/apple-plist.js')));
  const original = readFileSync(join(swift, 'fixture-release'));
  const native = protectNativeBinary(original, {intensity: 'bankrupt', seed: 'cloneguard-reproduction'});
  const modified = join(swift, 'comparison-bla-native');
  writeFileSync(modified, native.buffer, {flag: 'wx'});
  chmodSync(modified, 0o755);
  const rawPlist = readFileSync(join(swift, 'plist-original.bin'));
  const transformed = protectApplePlistBuffer(rawPlist, {intensity: 'bankrupt', seed: 'cloneguard-reproduction'});
  const plist = join(swift, 'comparison-bla-plist.bin');
  writeFileSync(plist, transformed.buffer, {flag: 'wx'});
  const sourceHash = createHash('sha256').update(original).digest('hex');
  const result = {
    schema: 'cloneguard.bla-comparison.v1', generated_utc: new Date().toISOString(), node: process.version,
    bla_version: JSON.parse(readFileSync(join(bla, 'package.json'))).version,
    swift: {original_sha256: sourceHash, original_bytes: original.length, transformed_bytes: native.buffer.length,
      original_signature: run('codesign', ['--verify', '--strict', join(swift, 'fixture-release')]).exit,
      transformed_signature: run('codesign', ['--verify', '--strict', modified]).exit,
      original_behavior: run(join(swift, 'fixture-release'), ['10000', '2']).stdout,
      transformed_behavior: run(modified, ['10000', '2']).stdout},
    plist: {original_bytes: rawPlist.length, transformed_bytes: transformed.buffer.length,
      original_apple_parser_exit: run('plutil', ['-lint', join(swift, 'plist-original.bin')]).exit,
      transformed_apple_parser_exit: run('plutil', ['-lint', plist]).exit},
    rea: {status: 'unrun'},
    limitations: ['Synthetic fixtures only', 'No model reconstruction trial', 'No actual App Store signing or device validation',
      'Native transform applied after local toolchain signing; re-signing before distribution is a separate workflow']
  };
  if (args.includes('--run-rea')) {
    if (!rea) throw new Error('--run-rea requires --rea-root');
    const probe = run(process.execPath, ['scripts/redteam/run.mjs'], {cwd: bla, env: {...process.env, REA_ROOT: rea}});
    const reportPath = join(bla, 'docs/redteam/empirical-rea-validation.json');
    result.rea = {status: probe.exit === 0 ? 'completed' : 'failed', exit: probe.exit, stderr: probe.stderr.slice(0, 500)};
    if (existsSync(reportPath) && probe.exit === 0) {
      const report = JSON.parse(readFileSync(reportPath));
      result.rea.pairs = report.pairs.map(pair => ({format: pair.format,
        evidence_type: pair.after.status === 'skipped' ? 'skipped' : ({flutter_pool: 'reimplemented-projection', evm_bytecode: 'input-cap-approach', gpu_ptx: 'inspection-only', wasm_module: pair.after.metrics?.wabtAvailable ? 'Wabt-provider-probe' : 'projected-REA-budget-without-Wabt'}[pair.format] ?? 'REA-module-probe'),
        before: {status: pair.before.status, bytes: pair.before.inputBytes},
        after: {status: pair.after.status, bytes: pair.after.inputBytes, budgetHit: pair.after.budgetHit, budgetName: pair.after.budgetName}}));
    }
  }
  exclusiveJson(out, result);
  console.log(JSON.stringify(result, null, 2));
  if (result.rea.status === 'failed') process.exitCode = 1;
} catch (error) {
  console.error(error.message);
  process.exitCode = 2;
}

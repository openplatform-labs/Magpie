const { mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');
const { buildSync } = require('esbuild');

const directory = mkdtempSync(join(tmpdir(), 'magpie-session-test-'));
try {
  for (const name of ['session-lifecycle', 'key-issuance', 'catalog-loading', 'model-provider-selection', 'provider-discovery', 'provider-group-edit', 'edit-selection']) {
    const output = join(directory, `${name}.cjs`);
    buildSync({ entryPoints: [`tests/${name}.test.ts`], outfile: output,
      bundle: true, platform: 'node', format: 'cjs', logLevel: 'warning',
      alias: {'@clr/angular': './tests/clarity-test-stub.ts'} });
    const result = spawnSync(process.execPath, [output], { stdio: 'inherit' });
    if (result.error) throw result.error;
    if (result.status !== 0) { process.exitCode = result.status ?? 1; break; }
  }
} finally {
  rmSync(directory, { recursive: true, force: true });
}

/**
 * 测试入口：运行 test/ 下所有 *.test.cjs 并汇总结果（`yarn test` / `npm test`）。
 *
 * 每个 suite 是独立子进程，沿用各文件自己的退出码约定（0 = 通过）。新增测试只需
 * 往 test/ 里放一个 *.test.cjs，无需改这里。全部离线、确定性，无需真实 IdP 凭证。
 *
 * 用法：node test/run-all.cjs
 * 退出码 0 = 全部 suite 通过。
 */
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const testDir = __dirname;
const suites = fs
  .readdirSync(testDir)
  .filter((f) => f.endsWith('.test.cjs'))
  .sort();

if (suites.length === 0) {
  console.error('No *.test.cjs suites found in test/');
  process.exit(1);
}

const results = [];
for (const suite of suites) {
  console.log(`\n=== ${suite} ===`);
  const proc = spawnSync(process.execPath, [path.join(testDir, suite)], {
    stdio: 'inherit',
    cwd: path.join(testDir, '..'),
  });
  results.push({ suite, pass: proc.status === 0 });
}

console.log('\n=== summary ===');
for (const { suite, pass } of results) {
  console.log(`${pass ? 'PASS' : 'FAIL'} ${suite}`);
}

const failed = results.filter((r) => !r.pass).length;
console.log(`\n${results.length - failed}/${results.length} suites passed`);
process.exit(failed === 0 ? 0 : 1);

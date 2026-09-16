/**
 * 端到端冒烟测试：经 lambda-local 跑 index.js 的真实 handler，逐个 fixture 断言
 * 「路由决策日志」与「最终拒绝」。
 *
 * 为什么断言的是拒绝而不是放行：fixture 里的 token 都不是真实 IdP 签发的，正确结果
 * 必然是 Unauthorized（handler 调 context.fail → lambda-local 退出码 1）。原 `test`
 * 脚本期望退出码 0，因此在任何无真实凭证的环境下都不可能通过——这正是它长期为红的
 * 原因。这里改为断言「它被拒绝了，且拒绝的理由是预期的那个」，于是既确定性又能真正
 * 回归路由分派。
 *
 * 覆盖 index.js 的事件解析 + 验签分派这一层（纯函数测试覆盖不到）。
 *
 * 用法：node test/smoke.test.cjs
 * 退出码 0 = 全部符合预期。
 */
const path = require('path');
const { spawnSync } = require('child_process');

const LAMBDA_LOCAL = path.join(__dirname, '..', 'node_modules', '.bin', 'lambda-local');

/** fixture → 必须出现在输出里的日志片段（按顺序全部需出现）。 */
const CASES = [
  ['event.json', ['unrecognized token issuer']],
  ['event-msal.json', ['Authorizer resolved by iss: MSAL', 'Decoded MSAL token is invalid']],
  ['event-msal-cn.json', ['Authorizer resolved by iss: MSAL-CN', 'Decoded MSAL-CN token is invalid']],
  ['event-okta.json', ['Authorizer resolved by iss: OKTA']],
  ['event-unknown.json', ['unrecognized token issuer']],
  ['event-legacy-header.json', ['falling back to legacy header authorizer: MSAL']],
];

const results = [];
for (const [fixture, expectedLogs] of CASES) {
  const proc = spawnSync(
    LAMBDA_LOCAL,
    ['--timeout', '300', '-l', 'index.js', '-h', 'handler', '-e', path.join('test', fixture)],
    { encoding: 'utf8', cwd: path.join(__dirname, '..') },
  );
  const output = `${proc.stdout || ''}${proc.stderr || ''}`;
  const missing = expectedLogs.filter((s) => !output.includes(s));
  const denied = proc.status !== 0;
  const pass = missing.length === 0 && denied;
  results.push(pass);

  const detail = missing.length
    ? `missing log: ${missing.join(', ')}`
    : denied
      ? 'ok'
      : 'expected Unauthorized, got success';
  console.log(`${pass ? 'PASS' : 'FAIL'} ${fixture} → ${detail}`);
}

const failed = results.filter((r) => !r).length;
console.log(`\n${results.length - failed}/${results.length} passed`);
process.exit(failed === 0 ? 0 : 1);

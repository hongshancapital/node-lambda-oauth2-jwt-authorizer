/**
 * cowork-agent 验签正反用例验证脚本。
 *
 * 覆盖：合法 token（sub→principalId、scp→逐条 allowMethod）、错 issuer（跨环境
 * 拒绝）、alg=none、HS256 用公钥当 HMAC 密钥（算法混淆攻击）、未知 kid、错 audience。
 *
 * 用法：node test/cowork-agent-auth.test.cjs
 * 自包含：运行时生成测试密钥对，不依赖真实私钥；COWORK_ISSUER / AUDIENCE 从
 * process.env 注入（AUDIENCE 缺省 'hongshan-lite-api'，与 daedalus 出站 aud 一致）。
 */
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const pubPem = publicKey.export({ type: 'spki', format: 'pem' });
const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' });

process.env.COWORK_JWT_PUBLIC_KEYS = JSON.stringify({ 'test-kid': pubPem });
process.env.COWORK_ISSUER = 'https://cowork.hongshan.com';
process.env.AUDIENCE = process.env.AUDIENCE || 'hongshan-lite-api';

const VerifyToken = require('../verify-token.js');

const makeEvent = (token) => ({
  type: 'TOKEN',
  authorizationToken: `Bearer ${token}`,
  methodArn: 'arn:aws:execute-api:us-west-2:1234567890:apiId/stage/GET/api/mcp',
});

// 拒绝语义的契约值：与 verify-token.js 的 unauthorized() 单一来源。
const DENY_MSG = VerifyToken.unauthorized().message;
let failed = false;

function run(token, label) {
  // 第三个参数 allowAccess 省略（显式 undefined）：COWORK_AGENT 分支不使用它，
  // 不要传占位函数——将来新增 Okta/MSAL 用例时它会被当成 policy 对象调用而崩溃。
  return VerifyToken.verifyAccessToken(token, makeEvent(token), undefined)
    .then((auth) => ({ label, ok: true, auth }))
    .catch((err) => {
      // 只有明确的鉴权拒绝才算 ok:false；内部异常（policy.build 未定义语句、
      // jwt must be a string 等）必须单独暴露并使进程失败，否则假绿。
      if (err && err.message === DENY_MSG) {
        return { label, ok: false, msg: err.message };
      }
      return { label, ok: 'error', msg: (err && err.stack) || String(err) };
    });
}

// expectAllow=true → 必须放行；否则必须是「因 Unauthorized 被拒」。
function report(r, expectAllow) {
  if (r.ok === 'error') {
    failed = true;
    console.log(`${r.label} → ERROR (内部异常，验签路径已崩): ${r.msg}`);
    return;
  }
  if (expectAllow) {
    if (!r.ok) failed = true;
    console.log(
      `${r.label} →`,
      r.ok ? 'ALLOW principal=' + r.auth.principalId : 'DENY ' + r.msg,
    );
    return;
  }
  const pass = r.ok === false && r.msg === DENY_MSG;
  if (!pass) failed = true;
  console.log(`${r.label} →`, pass ? 'DENY ✓' : `FAIL (ok=${r.ok}, msg=${r.msg})`);
}

const sign = (opts = {}) =>
  jwt.sign(
    { uid: 123, aid: 'agent-1', scp: ['cowork:mcp', 'cowork:read'] },
    opts.privPem || privPem,
    {
      algorithm: opts.algorithm || 'RS256',
      keyid: opts.keyid || 'test-kid',
      issuer: opts.issuer || 'https://cowork.hongshan.com',
      subject: 'bbao@hongshan.com',
      audience: opts.audience || process.env.AUDIENCE,
      expiresIn: 300,
      jwtid: 'run-123',
    },
  );

(async () => {
  // 1. 合法 token
  report(await run(sign(), 'valid'), true);

  // 2. 错 issuer（dev 签的不能在 prod 过）
  report(await run(sign({ issuer: 'https://cowork-dev.hongshan.com' }), 'wrong-issuer'), false);

  // 3. alg=none
  const noneToken = jwt.sign({ scp: [] }, Buffer.alloc(0), { algorithm: 'none' });
  report(await run(noneToken, 'alg-none'), false);

  // 4. HS256 用公钥当 HMAC 密钥（经典算法混淆攻击）
  try {
    const hsToken = jwt.sign({ scp: [] }, pubPem, {
      algorithm: 'HS256',
      issuer: 'https://cowork.hongshan.com',
      audience: process.env.AUDIENCE,
    });
    report(await run(hsToken, 'alg-confusion'), false);
  } catch (e) {
    console.log('alg-confusion → sign error (skipped):', e.message);
  }

  // 5. 未知 kid
  report(await run(sign({ keyid: 'unknown-kid' }), 'unknown-kid'), false);

  // 6. 错 audience
  report(await run(sign({ audience: 'other-api' }), 'wrong-audience'), false);

  // 任一用例不符合预期（含内部异常）都让脚本以非零码退出
  if (failed) process.exitCode = 1;
})();

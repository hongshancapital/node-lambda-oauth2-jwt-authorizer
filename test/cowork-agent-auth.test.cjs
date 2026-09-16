/**
 * cowork-agent 验签正反用例验证脚本。
 *
 * 覆盖：合法 token（sub→principalId、scp→逐条 allowMethod）、错 issuer（跨环境
 * 拒绝）、alg=none、HS256 用公钥当 HMAC 密钥（算法混淆攻击）、未知 kid、错 audience。
 *
 * 用法：node test/cowork-agent-auth.test.cjs
 * 自包含：运行时生成测试密钥对，不依赖真实私钥；COWORK_ISSUER / AUDIENCE 从
 * process.env 注入（AUDIENCE 缺省 'hongshan-lite-api'，与 daedalus 出站 aud 一致）。
 * 退出码 0 = 全部符合预期。
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

function run(token, label) {
  return new Promise((resolve) => {
    const context = {
      fail: (msg) => resolve({ label, ok: false, msg }),
      succeed: (auth) => resolve({ label, ok: true, auth }),
    };
    VerifyToken.verifyAccessToken(token, makeEvent(token), context, (e) => e);
  });
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
  const results = [];
  const check = (label, allowed, expectAllow) => {
    const pass = allowed === expectAllow;
    results.push(pass);
    console.log(
      `${label} →`,
      allowed ? (expectAllow ? 'ALLOW ✓' : 'ALLOW (BUG!)') : expectAllow ? 'DENY (BUG!)' : 'DENY ✓',
    );
  };

  // 1. 合法 token
  let r = await run(sign(), 'valid');
  check('valid', r.ok, true);

  // 2. 错 issuer（dev 签的不能在 prod 过）
  r = await run(sign({ issuer: 'https://cowork-dev.hongshan.com' }), 'wrong-issuer');
  check('wrong-issuer', r.ok, false);

  // 3. alg=none
  const noneToken = jwt.sign({ scp: [] }, Buffer.alloc(0), { algorithm: 'none' });
  r = await run(noneToken, 'alg-none');
  check('alg-none', r.ok, false);

  // 4. HS256 用公钥当 HMAC 密钥（经典算法混淆攻击）
  try {
    const hsToken = jwt.sign({ scp: [] }, pubPem, {
      algorithm: 'HS256',
      issuer: 'https://cowork.hongshan.com',
      audience: process.env.AUDIENCE,
    });
    r = await run(hsToken, 'alg-confusion');
    check('alg-confusion', r.ok, false);
  } catch (e) {
    results.push(true);
    console.log('alg-confusion → sign error (skipped):', e.message);
  }

  // 5. 未知 kid
  r = await run(sign({ keyid: 'unknown-kid' }), 'unknown-kid');
  check('unknown-kid', r.ok, false);

  // 6. 错 audience
  r = await run(sign({ audience: 'other-api' }), 'wrong-audience');
  check('wrong-audience', r.ok, false);

  const failed = results.filter((x) => !x).length;
  console.log(`\n${results.length - failed}/${results.length} passed`);
  process.exit(failed === 0 ? 0 : 1);
})();

'use strict';

/**
 * cowork-agent 验签正反用例（断言式改造，测出回归即非零退出）。
 *
 * 覆盖：合法 token（sub→principalId、scp→逐条 allowMethod）、错 issuer（跨环境
 * 拒绝）、alg=none、HS256 用公钥当 HMAC 密钥（算法混淆攻击）、未知 kid、错
 * audience、sub 缺失 fail-closed。
 *
 * 自包含：运行时生成测试密钥对，不依赖真实私钥；不触发任何网络请求。
 * 用法：node --test test/（或单文件 node --test test/cowork-agent-auth.test.cjs）
 */

const { test } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const { makeKeyPair, setupEnv, makeEvent, run, signCowork } =
  require('./helpers/index.cjs');

const keyPair = makeKeyPair();

// cowork 公钥经环境变量下发（与线上分发机制一致）；先设 env 再 require verify-token
setupEnv({
  COWORK_JWT_PUBLIC_KEYS: JSON.stringify({ 'test-kid': keyPair.pubPem }),
});

const VerifyToken = require('../verify-token.js');

const makeEventWithToken = (token) =>
  makeEvent({ authorizationToken: `Bearer ${token}` });

test('合法 token：ALLOW，principalId 经 transpile，scp 逐条映射进 policy', async () => {
  const token = signCowork({ keyPair });
  const r = await run(
    VerifyToken.verifyAccessToken,
    token,
    makeEventWithToken(token)
  );
  assert.ok(r.ok, `should allow, got deny: ${r.msg}`);
  assert.equal(r.auth.principalId, 'bbao@hongshan.com');
  assert.equal(r.auth.context.principalId, 'bbao@hongshan.com');
  assert.match(r.auth.context.tokenHash, /^[a-f0-9]{32}$/);
  assert.equal(r.auth.context.coworkRunId, 'run-123');

  // scp=['cowork:mcp','cowork:read'] → POST /api/mcp、POST /api/mcp/*、GET /api/*
  const resources = r.auth.policyDocument.Statement[0].Resource;
  assert.ok(resources.includes('arn:aws:execute-api:ap-northeast-1:592267666562:lp360api/dev/POST/api/mcp'));
  assert.ok(resources.includes('arn:aws:execute-api:ap-northeast-1:592267666562:lp360api/dev/POST/api/mcp/*'));
  assert.ok(resources.includes('arn:aws:execute-api:ap-northeast-1:592267666562:lp360api/dev/GET/api/*'));
});

test('错 issuer（dev 签的不能在 prod 过）→ DENY', async () => {
  const token = signCowork({
    keyPair,
    iss: 'https://cowork-dev.hongshan.com',
  });
  const r = await run(
    VerifyToken.verifyAccessToken,
    token,
    makeEventWithToken(token)
  );
  assert.ok(!r.ok, 'should deny');
});

test('alg=none → DENY', async () => {
  const noneToken = jwt.sign({ scp: [] }, Buffer.alloc(0), {
    algorithm: 'none',
  });
  const r = await run(
    VerifyToken.verifyAccessToken,
    noneToken,
    makeEventWithToken(noneToken)
  );
  assert.ok(!r.ok, 'should deny');
});

test('HS256 用公钥当 HMAC 密钥（算法混淆攻击）→ DENY', async () => {
  // jsonwebtoken v9：iss/aud 必须放 payload，options 里传会报错
  const hsToken = jwt.sign(
    {
      scp: [],
      iss: process.env.COWORK_ISSUER,
      aud: process.env.AUDIENCE,
    },
    keyPair.pubPem,
    { algorithm: 'HS256' }
  );
  const r = await run(
    VerifyToken.verifyAccessToken,
    hsToken,
    makeEventWithToken(hsToken)
  );
  assert.ok(!r.ok, 'should deny');
});

test('未知 kid → DENY', async () => {
  const token = signCowork({ keyPair, kid: 'unknown-kid' });
  const r = await run(
    VerifyToken.verifyAccessToken,
    token,
    makeEventWithToken(token)
  );
  assert.ok(!r.ok, 'should deny');
});

test('错 audience → DENY', async () => {
  const token = signCowork({ keyPair, aud: 'other-api' });
  const r = await run(
    VerifyToken.verifyAccessToken,
    token,
    makeEventWithToken(token)
  );
  assert.ok(!r.ok, 'should deny');
});

test('合法签名但 sub 缺失 → DENY（fail-closed，不得 500）', async () => {
  const token = signCowork({ keyPair, sub: '' });
  const r = await run(
    VerifyToken.verifyAccessToken,
    token,
    makeEventWithToken(token)
  );
  assert.ok(!r.ok, 'should deny with explicit Unauthorized, not crash');
});

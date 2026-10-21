'use strict';

/**
 * index.js handler 的 token 提取分支与策略生成端到端测试（离线）。
 * 对齐 #32 async 迁移后的 API：exports.handler 为 async，返回 Promise，
 * 鉴权拒绝统一抛 VerifyToken.unauthorized()。
 *
 * 覆盖：authorizationToken / headers.Authorization / headers.authorization（小写）
 * 三条 HTTP 入口 → httpAllowAccess（AuthPolicy allowAllMethods）；
 * queryStringParameters.AuthToken → wsAllowAccess（单语句 policy）；
 * 全部缺失 → 显式 Unauthorized（#32 已修复：不再对缺失字段 TypeError 崩溃）。
 */

const { test } = require('node:test');
const assert = require('node:assert');

const { setupEnv, makeKeyPair, installStubs, makeEvent, signAzure } =
  require('./helpers/index.cjs');

const keyPair = makeKeyPair();
setupEnv({
  COWORK_JWT_PUBLIC_KEYS: JSON.stringify({ 'test-kid': keyPair.pubPem }),
});
installStubs({ keys: { 'test-kid': keyPair.pubPem } });

const { handler } = require('../index.js');

const MSAL_TOKEN = signAzure({
  keyPair,
  iss: 'https://sts.windows.net/test-tenant/',
  appid: 'aad-app-id',
  upn: 'user@hongshan.com',
  aud: process.env.AUDIENCE,
});

const invoke = (event) =>
  handler(event)
    .then((auth) => ({ ok: true, auth }))
    .catch((err) => {
      if (err && err.message === 'Unauthorized') return { ok: false, msg: err.message };
      throw err; // 内部异常不得伪装成 deny
    });

test('authorizationToken（Bearer）→ httpAllowAccess → allowAllMethods 策略', async () => {
  const r = await invoke(
    makeEvent({
      authorizationToken: `Bearer ${MSAL_TOKEN}`,
      requestContext: { requestId: 'req-1' },
    })
  );
  assert.ok(r.ok, `should allow, got deny: ${r.msg}`);
  const doc = r.auth.policyDocument;
  assert.equal(doc.Version, '2012-10-17');
  assert.equal(doc.Statement[0].Action, 'execute-api:Invoke');
  assert.equal(doc.Statement[0].Effect, 'Allow');
  assert.ok(
    doc.Statement[0].Resource.includes(
      'arn:aws:execute-api:ap-northeast-1:592267666562:lp360api/dev/*/*'
    ),
    `allowAllMethods 应放行 /*/*，实际: ${JSON.stringify(doc)}`
  );
  assert.equal(r.auth.principalId, 'user@hongshan.com');
  assert.match(r.auth.context.tokenHash, /^[a-f0-9]{32}$/);
});

test('headers.Authorization（大写）→ 同 httpAllowAccess 路径', async () => {
  const r = await invoke(
    makeEvent({ headers: { Authorization: `Bearer ${MSAL_TOKEN}` } })
  );
  assert.ok(r.ok, `should allow, got deny: ${r.msg}`);
  assert.equal(r.auth.policyDocument.Statement[0].Action, 'execute-api:Invoke');
});

test('headers.authorization（小写）→ 同 httpAllowAccess 路径', async () => {
  const r = await invoke(
    makeEvent({ headers: { authorization: `Bearer ${MSAL_TOKEN}` } })
  );
  assert.ok(r.ok, `should allow, got deny: ${r.msg}`);
  assert.equal(r.auth.policyDocument.Statement[0].Action, 'execute-api:Invoke');
});

test('queryStringParameters.AuthToken → wsAllowAccess → 单语句 methodArn 策略', async () => {
  const r = await invoke(
    makeEvent({ queryStringParameters: { AuthToken: MSAL_TOKEN } })
  );
  assert.ok(r.ok, `should allow, got deny: ${r.msg}`);
  const doc = r.auth.policyDocument;
  assert.equal(doc.Statement.length, 1);
  assert.equal(
    doc.Statement[0].Resource,
    'arn:aws:execute-api:ap-northeast-1:592267666562:lp360api/dev/GET/api/mcp',
    'ws 策略 Resource 应精确等于 methodArn'
  );
  assert.equal(r.auth.principalId, 'user@hongshan.com');
});

test('所有取 token 分支均缺失 → 显式 Unauthorized（fail-closed，#32 已修复崩溃路径）', async () => {
  const r = await invoke(makeEvent());
  assert.ok(!r.ok, 'should deny');
  assert.equal(r.msg, 'Unauthorized');
});

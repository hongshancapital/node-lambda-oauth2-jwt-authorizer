'use strict';

/**
 * ws-handler.js 的 token 提取分支测试。
 * 对齐 #32 async 迁移后的 API：wshandler 为 async，双路径缺失时显式抛
 * VerifyToken.unauthorized()（#32 已修复既存的同步 TypeError 崩溃）。
 *
 * 覆盖：AuthToken query 优先；缺失时 Authorization header 兜底；
 * headers 亦缺失时显式 Unauthorized。
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

const { wshandler } = require('../ws-handler.js');

const MSAL_TOKEN = signAzure({
  keyPair,
  iss: 'https://sts.windows.net/test-tenant/',
  appid: 'aad-app-id',
  upn: 'user@hongshan.com',
  aud: process.env.AUDIENCE,
});

const invoke = (event) =>
  wshandler(event)
    .then((auth) => ({ ok: true, auth }))
    .catch((err) => {
      if (err && err.message === 'Unauthorized') return { ok: false, msg: err.message };
      throw err; // 内部异常不得伪装成 deny
    });

test('AuthToken query 参数优先', async () => {
  const r = await invoke(
    makeEvent({
      queryStringParameters: { AuthToken: MSAL_TOKEN },
      headers: { Authorization: 'Bearer something-ignored' },
    })
  );
  assert.ok(r.ok, `should allow, got deny: ${r.msg}`);
  assert.equal(
    r.auth.policyDocument.Statement[0].Resource,
    'arn:aws:execute-api:ap-northeast-1:592267666562:lp360api/dev/GET/api/mcp'
  );
});

test('AuthToken 缺失时回退 Authorization header', async () => {
  const r = await invoke(
    makeEvent({
      queryStringParameters: {},
      headers: { Authorization: `Bearer ${MSAL_TOKEN}` },
    })
  );
  assert.ok(r.ok, `should allow, got deny: ${r.msg}`);
});

test('两条路径都缺失（含 headers 整体缺失）→ 显式 Unauthorized（#32 修复回归守卫）', async () => {
  // 此前为同步 TypeError（500）；#32 改为干净的 401 语义拒绝
  const r = await invoke(
    makeEvent({ queryStringParameters: {}, headers: {} })
  );
  assert.ok(!r.ok, 'should deny');
  assert.equal(r.msg, 'Unauthorized');

  // headers 字段完全缺失（无 headers key）同样显式拒绝
  const r2 = await invoke(
    makeEvent({ queryStringParameters: {} })
  );
  assert.ok(!r2.ok, 'should deny');
  assert.equal(r2.msg, 'Unauthorized');
});

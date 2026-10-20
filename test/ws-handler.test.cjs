'use strict';

/**
 * ws-handler.js 的 token 提取分支测试。
 *
 * 覆盖：AuthToken query 优先；缺失时 Authorization header 兜底。
 * 已知既存缺陷（未改源码，仅固化现状）：两条路径都缺失时
 * event.headers.Authorization.split 会同步抛 TypeError（500 而非 401）。
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
  new Promise((resolve) => {
    const context = {
      fail: (msg) => resolve({ ok: false, msg }),
      succeed: (auth) => resolve({ ok: true, auth }),
    };
    wshandler(event, context);
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

test('两条路径都缺失 → 既存行为：同步 TypeError（已知缺陷，未改源码）', () => {
  assert.throws(
    () =>
      wshandler(
        makeEvent({ queryStringParameters: {}, headers: {} }),
        { fail: () => {}, succeed: () => {} }
      ),
    TypeError,
    'headers.Authorization 为 undefined 时 .split 抛 TypeError'
  );
});

'use strict';

/**
 * verify-token.js 全路径单元测试（离线，JWKS/Okta 全部桩化）。
 * 对齐 #32 async 迁移后的 API：verifyAccessToken 返回 Promise，
 * 拒绝统一为 VerifyToken.unauthorized()（message='Unauthorized'）。
 *
 * 覆盖：iss 自动路由（4 类 + 未知兜底 + legacy header 回退）、MSAL / MSAL-CN /
 * OKTA 三条验签路径的成败分支、appid 校验、transpileToComEmail、tokenHash。
 *
 * 已知既存弱点（此处固化现状、不修改源码，见 verify-token.js Azure 分支注释）：
 * Azure 分支的 issuer/audience 校验用 decoded 自证声明，非 env 白名单。
 */

const { test } = require('node:test');
const assert = require('node:assert');

const { setupEnv, makeKeyPair, installStubs, makeEvent, run, signAzure } =
  require('./helpers/index.cjs');

const keyPair = makeKeyPair();

// 桩必须在 require('../verify-token.js') 之前装好（verify-token 模块顶层
// 即实例化 jwks-rsa 客户端与 OktaJwtVerifier）
setupEnv({
  COWORK_JWT_PUBLIC_KEYS: JSON.stringify({ 'test-kid': keyPair.pubPem }),
});
const { oktaState } = installStubs({ keys: { 'test-kid': keyPair.pubPem } });

const VerifyToken = require('../verify-token.js');

const MSAL = {
  iss: 'https://sts.windows.net/test-tenant/',
  appid: 'aad-app-id',
  upn: 'user@hongshan.com',
};
const MSAL_CN = {
  iss: 'https://sts.chinacloudapi.cn/test-tenant/',
  appid: 'aad-cn-app-id',
  upn: 'user@hongshan.cn',
};

/** 捕获 allowAccess 收到的原始 email；build 回带 context 便于断言 */
const captureAllowAccess = (event, email) => ({
  build: (ctx) => ({ rawEmail: email, context: ctx }),
});

const verify = (token, event) =>
  run(VerifyToken.verifyAccessToken, token, event, captureAllowAccess);

// ---------- 纯函数：iss 路由 ----------

test('resolveAuthorizerTypeByIssuer：四类前缀正确分类', () => {
  assert.equal(
    VerifyToken.resolveAuthorizerTypeByIssuer({ iss: 'https://sts.windows.net/x' }),
    'MSAL'
  );
  assert.equal(
    VerifyToken.resolveAuthorizerTypeByIssuer({ iss: 'https://sts.chinacloudapi.cn/x' }),
    'MSAL-CN'
  );
  assert.equal(
    VerifyToken.resolveAuthorizerTypeByIssuer({ iss: 'https://hongshan.okta.com/x' }),
    'OKTA'
  );
  assert.equal(
    VerifyToken.resolveAuthorizerTypeByIssuer({ iss: 'https://cowork.hongshan.com' }),
    'COWORK_AGENT'
  );
});

test('resolveAuthorizerTypeByIssuer：无 iss / 未知 iss / 非字符串 → null', () => {
  assert.equal(VerifyToken.resolveAuthorizerTypeByIssuer(null), null);
  assert.equal(VerifyToken.resolveAuthorizerTypeByIssuer({}), null);
  assert.equal(VerifyToken.resolveAuthorizerTypeByIssuer({ iss: 42 }), null);
  assert.equal(
    VerifyToken.resolveAuthorizerTypeByIssuer({ iss: 'https://evil.example.com' }),
    null
  );
});

test('transpileToComEmail：hongshan.cn 归一，其余原样', () => {
  assert.equal(
    VerifyToken.transpileToComEmail('user@hongshan.cn'),
    'user@hongshan.com'
  );
  assert.equal(
    VerifyToken.transpileToComEmail('user@hongshan.com'),
    'user@hongshan.com'
  );
  assert.equal(
    VerifyToken.transpileToComEmail('user@example.org'),
    'user@example.org'
  );
});

test('unauthorized() 工厂产出 401 契约字面量（拒绝文案的契约守卫）', () => {
  assert.equal(VerifyToken.unauthorized().message, 'Unauthorized');
});

// ---------- MSAL（Azure 全球）----------

test('MSAL 合法 token → ALLOW：principalId=upn 不 transpile，tokenHash 32 位', async () => {
  const token = signAzure({ keyPair, ...MSAL, aud: process.env.AUDIENCE });
  const r = await verify(token, makeEvent({ authorizationToken: `Bearer ${token}` }));

  assert.ok(r.ok, `should allow, got deny: ${r.msg}`);
  assert.equal(r.auth.rawEmail, 'user@hongshan.com'); // upn 原样传给 allowAccess
  assert.equal(r.auth.context.principalId, 'user@hongshan.com'); // MSAL 不 transpile
  assert.match(r.auth.context.tokenHash, /^[a-f0-9]{32}$/);
});

test('MSAL appid 不匹配 → DENY（Unauthorized）', async () => {
  const token = signAzure({
    keyPair,
    ...MSAL,
    appid: 'wrong-app-id',
    aud: process.env.AUDIENCE,
  });
  const r = await verify(token, makeEvent({ authorizationToken: `Bearer ${token}` }));
  assert.ok(!r.ok, 'should deny');
  assert.equal(r.msg, 'Unauthorized');
});

// ---------- MSAL-CN（Azure 中国）----------

test('MSAL-CN 合法 token → ALLOW：principalId 经 transpileToComEmail', async () => {
  const token = signAzure({ keyPair, ...MSAL_CN, aud: process.env.AUDIENCE });
  const r = await verify(token, makeEvent({ authorizationToken: `Bearer ${token}` }));

  assert.ok(r.ok, `should allow, got deny: ${r.msg}`);
  assert.equal(r.auth.rawEmail, 'user@hongshan.cn');
  assert.equal(r.auth.context.principalId, 'user@hongshan.com'); // MSAL-CN transpile
});

// ---------- OKTA ----------

test('OKTA 合法 token → ALLOW：principalId 取 claims.sub', async () => {
  oktaState.verifyAccessToken = async () => ({ claims: { sub: 'okta-user@hongshan.com' } });
  const token = signAzure({
    keyPair,
    iss: 'https://hongshan.okta.com/oauth2/default',
    appid: 'irrelevant',
    upn: 'irrelevant',
    aud: process.env.AUDIENCE,
  });
  const r = await verify(token, makeEvent({ authorizationToken: `Bearer ${token}` }));

  assert.ok(r.ok, `should allow, got deny: ${r.msg}`);
  assert.equal(r.auth.context.principalId, 'okta-user@hongshan.com');
});

test('OKTA 验签失败 → DENY（Unauthorized）', async () => {
  oktaState.verifyAccessToken = async () => {
    throw new Error('invalid okta token');
  };
  const token = signAzure({
    keyPair,
    iss: 'https://hongshan.okta.com/oauth2/default',
    appid: 'irrelevant',
    upn: 'irrelevant',
    aud: process.env.AUDIENCE,
  });
  const r = await verify(token, makeEvent({ authorizationToken: `Bearer ${token}` }));
  assert.ok(!r.ok, 'should deny');
});

// ---------- 未知 iss 的兜底路径 ----------

test('未知 iss + New-Authorizer: MSAL header → legacy 回退走 MSAL 验签', async () => {
  // 既存行为：legacy 回退信任 header 指定；issuer 校验用 decoded 自证（见文件头注释）
  const token = signAzure({
    keyPair,
    iss: 'https://login.example.com/unknown',
    appid: 'aad-app-id',
    upn: 'legacy-user@hongshan.com',
    aud: process.env.AUDIENCE,
  });
  const r = await verify(
    token,
    makeEvent({
      authorizationToken: `Bearer ${token}`,
      headers: { 'New-Authorizer': 'MSAL' },
    })
  );
  assert.ok(r.ok, `legacy header fallback should route to MSAL, got deny: ${r.msg}`);
  assert.equal(r.auth.rawEmail, 'legacy-user@hongshan.com');
});

test('New-Authorizer 值非法（非 MSAL/MSAL-CN）→ 不回退，DENY', async () => {
  const token = signAzure({
    keyPair,
    iss: 'https://login.example.com/unknown',
    appid: 'aad-app-id',
    upn: 'user@hongshan.com',
    aud: process.env.AUDIENCE,
  });
  const r = await verify(
    token,
    makeEvent({
      authorizationToken: `Bearer ${token}`,
      headers: { 'New-Authorizer': 'GARBAGE' },
    })
  );
  assert.ok(!r.ok, 'garbage legacy header must not grant fallback');
});

test('未知 iss 且无 legacy header → DENY（fail-closed）', async () => {
  const token = signAzure({
    keyPair,
    iss: 'https://login.example.com/unknown',
    appid: 'aad-app-id',
    upn: 'user@hongshan.com',
    aud: process.env.AUDIENCE,
  });
  const r = await verify(token, makeEvent({ authorizationToken: `Bearer ${token}` }));
  assert.ok(!r.ok, 'should deny');
  assert.equal(r.msg, 'Unauthorized');
});

test('完全没有 token（handler 全分支缺失的下游）→ DENY 不崩溃', async () => {
  const r = await verify(undefined, makeEvent());
  assert.ok(!r.ok, 'should deny');
});

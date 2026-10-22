'use strict';

/**
 * auth-policy.js（AuthPolicy）单元测试（纯逻辑，无需桩）。
 *
 * 覆盖：allowAllMethods / allowMethod / denyMethod 的 ARN 拼接、policyDocument
 * 结构、无语句时 build 抛错、非法 verb / path 的入参校验。
 */

const { test } = require('node:test');
const assert = require('node:assert');

const AuthPolicy = require('../auth-policy.js');

const API = {
  start: 'arn:aws:execute-api:',
  region: 'ap-northeast-1',
  restApiId: 'lp360api',
  stage: 'dev',
};
const ARN = 'arn:aws:execute-api:ap-northeast-1:592267666562:lp360api';

test('allowAllMethods → 单条 Allow 语句放行 /*/*', () => {
  const policy = new AuthPolicy('u@hongshan.com', '592267666562', API);
  policy.allowAllMethods();
  const out = policy.build({ tokenHash: 'x' });

  assert.equal(out.principalId, 'u@hongshan.com');
  assert.equal(out.policyDocument.Version, '2012-10-17');
  assert.equal(out.policyDocument.Statement.length, 1);
  const st = out.policyDocument.Statement[0];
  assert.equal(st.Action, 'execute-api:Invoke');
  assert.equal(st.Effect, 'Allow');
  assert.deepEqual(st.Resource, [`${ARN}/dev/*/*`]);
  assert.equal(out.context.tokenHash, 'x'); // authorizer context 透传后端
});

test('allowMethod(POST, /api/mcp) → ARN 逐字拼接（路径不带前导斜杠进 ARN）', () => {
  const policy = new AuthPolicy('u', '592267666562', API);
  policy.allowMethod('POST', '/api/mcp');
  const out = policy.build({});
  assert.deepEqual(out.policyDocument.Statement[0].Resource, [
    `${ARN}/dev/POST/api/mcp`,
  ]);
});

test('allow 与 deny 混合 → 两条语句按 effect 分组', () => {
  const policy = new AuthPolicy('u', '592267666562', API);
  policy.allowMethod('GET', '/api/*');
  policy.denyMethod('POST', '/api/secret');
  const out = policy.build({});
  const stmts = out.policyDocument.Statement;

  assert.equal(stmts.length, 2);
  assert.equal(stmts[0].Effect, 'Allow');
  assert.equal(stmts[1].Effect, 'Deny');
});

test('无任何语句 → build 抛错（fail-closed）', () => {
  const policy = new AuthPolicy('u', '592267666562', API);
  assert.throws(() => policy.build({}), /No statements defined/);
});

test('非法 verb / path → 抛错（入参校验）', () => {
  const policy = new AuthPolicy('u', '592267666562', API);
  assert.throws(() => policy.allowMethod('FETCH', '/api'), /Invalid HTTP verb/);
  assert.throws(() => policy.allowMethod('GET', 'bad path'), /Invalid resource path/);
});

'use strict';

/**
 * cowork-scope-policy.js 单元测试（纯逻辑，无需桩）。
 *
 * 覆盖：scp → SCOPE_ALLOWLIST 逐条映射进 policyDocument；未知 scope fail-closed
 * （放行集为空——注意既存行为：AuthPolicy.build 此时抛错而非干净 401，
 * 已在用例中固化现状并注明）。
 */

const { test } = require('node:test');
const assert = require('node:assert');

const { buildCoworkPolicy, SCOPE_ALLOWLIST } = require('../cowork-scope-policy.js');

const EVENT = {
  methodArn:
    'arn:aws:execute-api:ap-northeast-1:592267666562:lp360api/dev/GET/api/mcp',
};

test('SCOPE_ALLOWLIST 形状：mcp→POST /api/mcp*，read→GET /api/*', () => {
  assert.deepEqual(SCOPE_ALLOWLIST['cowork:mcp'], [
    { verb: 'POST', path: '/api/mcp' },
    { verb: 'POST', path: '/api/mcp/*' },
  ]);
  assert.deepEqual(SCOPE_ALLOWLIST['cowork:read'], [
    { verb: 'GET', path: '/api/*' },
  ]);
});

test('scp=[cowork:mcp, cowork:read] → 三条 allow 语句，含 methodArn 解析出的 api/stage', () => {
  const policy = buildCoworkPolicy(EVENT, 'user@hongshan.com', [
    'cowork:mcp',
    'cowork:read',
  ]);
  const doc = policy.build({}).policyDocument;
  const resources = doc.Statement[0].Resource;

  assert.equal(doc.Version, '2012-10-17');
  assert.deepEqual(resources.sort(), [
    'arn:aws:execute-api:ap-northeast-1:592267666562:lp360api/dev/GET/api/*',
    'arn:aws:execute-api:ap-northeast-1:592267666562:lp360api/dev/POST/api/mcp',
    'arn:aws:execute-api:ap-northeast-1:592267666562:lp360api/dev/POST/api/mcp/*',
  ]);
});

test('未知 scope → 放行集为空（fail-closed；既存行为：build 抛错，见注释）', () => {
  const policy = buildCoworkPolicy(EVENT, 'user@hongshan.com', ['cowork:bogus']);
  // 放行集为空 → AuthPolicy.build 抛 "No statements defined"，
  // 线上表现为 Lambda 5xx 而非 401——安全上 fail-closed，运维上是错误率噪音。
  // 此处固化现状；若日后改为显式 context.fail，更新本用例。
  assert.throws(() => policy.build({}), /No statements defined/);
});

test('scp 缺失 / 非数组 → 同样 fail-closed', () => {
  assert.throws(
    () => buildCoworkPolicy(EVENT, 'u@hongshan.com', undefined).build({}),
    /No statements defined/
  );
  assert.throws(
    () => buildCoworkPolicy(EVENT, 'u@hongshan.com', 'not-array').build({}),
    /No statements defined/
  );
});

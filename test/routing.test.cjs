/**
 * issuer → authorizer 路由的单元测试（纯函数，无网络、无进程派生）。
 *
 * 背景：路由表由「按 iss 声明自动路由」那次改动引入，但当时只做了手工验证、没有
 * 留下回归测试。这里既覆盖 test/event-*.json 各 fixture 的预期路由结果，也覆盖
 * fixture 无法表达的边界（缺失/非字符串 iss、AAD v2.0 issuer、相似域名）。
 *
 * 用法：node test/routing.test.cjs
 * 退出码 0 = 全部符合预期。
 */
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');

const { resolveAuthorizerTypeByIssuer } = require('../verify-token.js');

/** fixture 文件名 → 期望的路由结果（null = 无法识别，最终会被拒）。 */
const FIXTURE_EXPECTATIONS = {
  'event-msal.json': 'MSAL',
  'event-msal-cn.json': 'MSAL-CN',
  'event-okta.json': 'OKTA',
  'event-unknown.json': null,
  'event-legacy-header.json': null, // iss 未知，靠 header 兜底
  'event.json': null, // 上游遗留样例，iss 不匹配任何前缀
};

/** iss 值 → 期望的路由结果。 */
const ISSUER_CASES = [
  // 三个（现为四个）已知前缀
  ['https://sts.windows.net/72f9abcdef/', 'MSAL'],
  ['https://sts.chinacloudapi.cn/abcd1234/', 'MSAL-CN'],
  ['https://hongshan.okta.com/oauth2/aus123', 'OKTA'],
  ['https://cowork.hongshan.com', 'COWORK_AGENT'],
  // 不支持的 AAD v2.0 issuer（无 appid 声明，现有 appid 校验本就拒它）
  ['https://login.microsoftonline.com/tenant/v2.0', null],
  // 非生产 Okta 域名
  ['https://example.oktapreview.com/oauth2/aus8o56xh1qncrlwT0h7', null],
  // 相似域名不该被前缀匹配吞进来（路由只是第一道，签名才是真正的门）
  ['https://sts.windows.net.evil.com/', 'MSAL'],
  ['https://evil.example.com/', null],
];

const results = [];
const check = (label, actual, expected) => {
  const pass = actual === expected;
  results.push(pass);
  console.log(`${pass ? 'PASS' : 'FAIL'} ${label} → ${actual} (want ${expected})`);
};

// 1. fixture 表
for (const [file, expected] of Object.entries(FIXTURE_EXPECTATIONS)) {
  const full = path.join(__dirname, file);
  if (!fs.existsSync(full)) {
    results.push(false);
    console.log(`FAIL ${file} → missing fixture`);
    continue;
  }
  const raw = JSON.parse(fs.readFileSync(full, 'utf8')).authorizationToken;
  const token = raw.includes(' ') ? raw.split(' ')[1] : raw;
  check(file, resolveAuthorizerTypeByIssuer(jwt.decode(token)), expected);
}

// 2. iss 取值表
for (const [iss, expected] of ISSUER_CASES) {
  check(`iss=${iss}`, resolveAuthorizerTypeByIssuer(jwt.decode(jwt.sign({ iss }, 'k'))), expected);
}

// 3. 边界：decode 失败或非对象输入
for (const input of [null, undefined, {}, { iss: 123 }, { iss: '' }, { iss: null }]) {
  check(`edge ${JSON.stringify(input)}`, resolveAuthorizerTypeByIssuer(input), null);
}

const failed = results.filter((r) => !r).length;
console.log(`\n${results.length - failed}/${results.length} passed`);
process.exit(failed === 0 ? 0 : 1);

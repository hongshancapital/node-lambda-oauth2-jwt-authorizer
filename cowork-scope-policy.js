/**
 * Cowork Agent scope → (verb, path) 静态允许表。
 *
 * 与真实用户 token 的 `allowAllMethods()` 不同：cowork-agent 票按 `scp` 声明
 * 逐条 `allowMethod`。容器里是 LLM 驱动的任意代码（有 Bash 工具），一张等同
 * 用户全权的票风险过大——scope 白名单是「用户授权了什么」唯一能落到网关执行点
 * 的地方。未知 scope 名映射不到任何 method → 放行集为空（fail-closed）。
 *
 * 新增 scope 需要改这张表（变更频率低、表小，可接受）。真实用户 Okta/MSAL 分支
 * 保持 allowAllMethods() 不变。
 *
 * ⚠️ 路径匹配前提（部署时必须核验）：下面 path 是 `AuthPolicy.allowMethod` 拼进
 * IAM policy 的 resource 段，必须与 API Gateway authorizer 事件 `methodArn` 里
 * 的 resource path **逐字一致**。cowork 生产访问走 `normalizeLiteApiPath`（前缀
 * `/v1`），但 `/v1` 通常是自定义域名的 base path mapping 或 stage 名，**不进入**
 * methodArn 的 resource 段——此时 `/api/mcp` 是对的。若实际网关把 `/v1` 当作了
 * 资源路径本身（resource 段是 `/v1/api/mcp`），则本表全部 miss → 所有 cowork-agent
 * 请求被拒（fail-closed，安全但功能失效）。上线前用真实 methodArn 验证一次。
 */

const AuthPolicy = require('./auth-policy');

const SCOPE_ALLOWLIST = {
  // 内部 MCP：hong-internal / outlook / onenote / 等 POST /api/mcp*
  'cowork:mcp': [
    { verb: 'POST', path: '/api/mcp' },
    { verb: 'POST', path: '/api/mcp/*' },
  ],
  // 只读：GET /api/*
  'cowork:read': [{ verb: 'GET', path: '/api/*' }],
  // 写能力（如 lite 业务对象创建/更新）：默认不给，按需在此逐条列出后，
  // 由 daedalus 显式传对应 scope 才会放行。
  // 'cowork:lite-write': [
  //   { verb: 'POST', path: '/api/note/*' },
  //   { verb: 'PUT', path: '/api/note/*' },
  // ],
};

/**
 * 构建 cowork-agent 的 AuthPolicy：只放行 scp 里声明的 scope 对应的 method。
 *
 * @param {object} event — API Gateway authorizer event（含 methodArn）
 * @param {string} principalId — 归一后的用户邮箱（principalId）
 * @param {string[]|undefined} scp — token 的 scope 声明数组
 * @returns {AuthPolicy}
 */
function buildCoworkPolicy(event, principalId, scp) {
  const arnParts = event.methodArn.split(':');
  const apiGatewayArnPart = arnParts[5].split('/');
  const awsAccountId = arnParts[4];
  const apiOptions = {
    start: arnParts[0] + ':' + arnParts[1] + ':' + arnParts[2] + ':',
    region: arnParts[3],
    restApiId: apiGatewayArnPart[0],
    stage: apiGatewayArnPart[1],
  };

  const policy = new AuthPolicy(principalId, awsAccountId, apiOptions);

  const scopes = Array.isArray(scp) ? scp : [];
  for (const scope of scopes) {
    const entries = SCOPE_ALLOWLIST[scope];
    if (!entries) {
      continue; // 未知 scope → 不放行任何 method（fail-closed）
    }
    for (const entry of entries) {
      policy.allowMethod(entry.verb, entry.path);
    }
  }

  return policy;
}

module.exports = { buildCoworkPolicy, SCOPE_ALLOWLIST };

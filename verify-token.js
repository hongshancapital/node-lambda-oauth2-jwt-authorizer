require("dotenv").config();

const OktaJwtVerifier = require("@okta/jwt-verifier");
const jsonWebToken = require("jsonwebtoken");
const crypto = require("crypto");
const jwksClient = require("jwks-rsa");
const keyCache = require("./key-cache");
const coworkKeys = require("./cowork-keys");
const { buildCoworkPolicy } = require("./cowork-scope-policy");

const tokenHash = (token) =>
  crypto.createHash("sha256").update(token).digest("hex").substring(0, 32);

/******************************************************/

const oktaJwtVerifier = new OktaJwtVerifier({
  issuer: process.env.ISSUER, // required
  clientId: process.env.CLIENT_ID, // required
  assertClaims: {
    aud: process.env.AUDIENCE,
  },
});

const transpileToComEmail = (email) =>
  email.endsWith("@hongshan.cn")
    ? email.replace("@hongshan.cn", "@hongshan.com")
    : email;

// 初始化 JWKS 客户端
const jwksClients = {
  azure: jwksClient({
    jwksUri: "https://login.microsoftonline.com/common/discovery/keys",
  }),
  azureCN: jwksClient({
    jwksUri: "https://login.partner.microsoftonline.cn/common/discovery/keys",
  }),
};

const AUTHORIZER_TYPE = {
  MSAL: "MSAL",
  MSAL_CN: "MSAL-CN",
  OKTA: "OKTA",
  COWORK_AGENT: "COWORK_AGENT",
};

// Azure AD 两个 cloud 的 issuer base。路由前缀（下方 ISSUER_PREFIXES）与精确
// issuer 校验（buildAzureValidationOptions）共用，避免两处字符串各写一份而漂移。
const AZURE_ISSUER_BASE = "https://sts.windows.net";
const AZURE_CN_ISSUER_BASE = "https://sts.chinacloudapi.cn";

// issuer 前缀 → authorizer 类型，按声明 `iss` 自动路由验签方式
const ISSUER_PREFIXES = [
  { prefix: AZURE_ISSUER_BASE, type: AUTHORIZER_TYPE.MSAL },
  { prefix: AZURE_CN_ISSUER_BASE, type: AUTHORIZER_TYPE.MSAL_CN },
  { prefix: "https://hongshan.okta.com", type: AUTHORIZER_TYPE.OKTA },
  { prefix: "https://cowork.hongshan.com", type: AUTHORIZER_TYPE.COWORK_AGENT },
];

/**
 * 通用的从 JWKS 端点获取密钥的函数
 * @param {string} provider - 提供商标识（'azure' 或 'azureCN'）
 * @param {string} kid - 密钥ID
 * @returns {Promise<string>} - 返回密钥
 */
const fetchKey = (provider, kid) => {
  return new Promise((resolve, reject) => {
    if (!jwksClients[provider]) {
      return reject(new Error(`未知的提供商: ${provider}`));
    }

    jwksClients[provider].getSigningKey(kid, (err, key) => {
      if (err) {
        return reject(err);
      }
      const signingKey = key.publicKey || key.rsaPublicKey;
      resolve(signingKey);
    });
  });
};

const getSigningKeys = (header, callback) => {
  keyCache
    .getKey("azure", header.kid, (kid) => fetchKey("azure", kid))
    .then((signingKey) => callback(null, signingKey))
    .catch((err) => callback(err));
};

const getSigningKeysForAzureCN = (header, callback) => {
  keyCache
    .getKey("azureCN", header.kid, (kid) => fetchKey("azureCN", kid))
    .then((signingKey) => callback(null, signingKey))
    .catch((err) => callback(err));
};

/**
 * 根据 token 的 `iss` 声明前缀判断应使用的 authorizer 类型
 * @param {object|null} decoded - jsonWebToken.decode 的结果
 * @returns {string|null} - AUTHORIZER_TYPE 之一，无法识别时返回 null
 */
const resolveAuthorizerTypeByIssuer = (decoded) => {
  const iss = decoded && decoded.iss;
  if (typeof iss !== "string") return null;
  const matched = ISSUER_PREFIXES.find((entry) => iss.startsWith(entry.prefix));
  return matched ? matched.type : null;
};

/**
 * 过渡期兜底：`iss` 无法识别时回退到 New-Authorizer header / newAuthorizer query。
 * 仅识别显式指定的 MSAL / MSAL-CN，语义与改动前一致。
 * @returns {string|null}
 */
const resolveAuthorizerTypeByHeader = (event) => {
  const headers = event.headers || {};
  const query = event.queryStringParameters || {};
  const raw =
    headers["New-Authorizer"] ||
    headers["new-authorizer"] ||
    query["newAuthorizer"];
  return raw === AUTHORIZER_TYPE.MSAL || raw === AUTHORIZER_TYPE.MSAL_CN
    ? raw
    : null;
};

// 两种 Azure 验签方式共用一个流程，仅 issuer base / appId / tenantId / audience /
// 密钥来源 / principalId 生成方式不同。env 一律惰性读取（`() => process.env.X`），
// 便于测试在 require 之后再改环境变量。
const AZURE_AUTHORIZERS = {
  [AUTHORIZER_TYPE.MSAL]: {
    label: "MSAL",
    issuerBase: AZURE_ISSUER_BASE,
    getAppId: () => process.env.AAD_APPLICATION_ID,
    getTenantId: () => process.env.AAD_TENANT_ID,
    getAudience: () => process.env.AAD_AUDIENCE,
    tenantEnvName: "AAD_TENANT_ID",
    audienceEnvName: "AAD_AUDIENCE",
    getSigningKeys,
    toPrincipalId: (upn) => upn, // 保持原行为：不 transpile
  },
  [AUTHORIZER_TYPE.MSAL_CN]: {
    label: "MSAL-CN",
    issuerBase: AZURE_CN_ISSUER_BASE,
    getAppId: () => process.env.AAD_CN_APPLICATION_ID,
    getTenantId: () => process.env.AAD_CN_TENANT_ID,
    getAudience: () => process.env.AAD_CN_AUDIENCE,
    tenantEnvName: "AAD_CN_TENANT_ID",
    audienceEnvName: "AAD_CN_AUDIENCE",
    getSigningKeys: getSigningKeysForAzureCN,
    toPrincipalId: transpileToComEmail, // 保持原行为：transpile
  },
};

/**
 * 按 flavor 构造 jsonwebtoken 的 validationOptions（tenant + audience + 算法）。
 *
 * 改动前这里是 `issuer: decoded.iss, audience: decoded.aud`——拿 token 自己声明的值
 * 校验自己，恒真，实际从未拒绝过任何 token。改为比对配置值后才真正锁定 tenant
 * （AAD v1.0 的 iss 形如 `${base}/${tid}/`，故精确校验 issuer 即校验 tenant）与目标资源。
 *
 * tenant/audience 未配置时**跳过该项并打 warn**（fail-open）：不传该 key 时
 * jsonwebtoken 整项跳过校验，与改动前的净效果等价，因此发布不会造成行为回归。
 * 代价是配置未就位前洞仍开着——warn 日志即该待办的追踪信号。
 *
 * issuer 同时接受带/不带尾斜杠两种形式：AAD v1.0 实际签发的是带尾斜杠的
 * `${base}/${tid}/`，两种形式锁定的都是同一个 tenant。接受两者可消除「配置时漏写
 * 尾斜杠 → 全量 401」这个最可能的自伤事故，代价仅是多接受一个 AAD 从不签发的等价形式。
 *
 * @param {string} type - AUTHORIZER_TYPE.MSAL 或 AUTHORIZER_TYPE.MSAL_CN
 * @returns {object} - 传给 jsonWebToken.verify 的 options
 */
const buildAzureValidationOptions = (type) => {
  const config = AZURE_AUTHORIZERS[type];
  const options = { algorithms: ["RS256"] };

  const tenantId = config.getTenantId();
  if (tenantId) {
    options.issuer = [
      `${config.issuerBase}/${tenantId}/`,
      `${config.issuerBase}/${tenantId}`,
    ];
  } else {
    console.warn(
      `${config.label}: ${config.tenantEnvName} not configured, skipping tenant validation`
    );
  }

  // 逗号分隔多值 → 数组。AAD 的 aud 常见 GUID 与 api://{guid} 两种等价形态，
  // jsonwebtoken 对数组走 some() 任一匹配，无需自定义比对。
  const audience = config.getAudience();
  if (audience) {
    options.audience = audience
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean);
  } else {
    console.warn(
      `${config.label}: ${config.audienceEnvName} not configured, skipping audience validation`
    );
  }

  return options;
};

const verifyAzureToken = (
  type,
  accessToken,
  decoded,
  event,
  context,
  allowAccess
) => {
  const config = AZURE_AUTHORIZERS[type];

  // appid 是「请求 token 的客户端」，aud 是「token 的目标资源」，两个不同声明，都校验。
  if (!decoded || config.getAppId() !== decoded.appid) {
    console.error(
      `Decoded ${config.label} token is invalid: ` + JSON.stringify(decoded)
    );
    return context.fail("Unauthorized");
  }

  const validationOptions = buildAzureValidationOptions(type);

  jsonWebToken.verify(
    accessToken,
    config.getSigningKeys,
    validationOptions,
    (err, payload) => {
      if (err) {
        console.log(err);
        console.log(JSON.stringify(payload));
        return context.fail("Unauthorized");
      } else {
        const policy = allowAccess(event, decoded.upn);
        console.log(`Auth succeed as ${decoded.upn}`);
        const newContext = policy.build({
          principalId: config.toPrincipalId(decoded.upn),
          tokenHash: tokenHash(accessToken),
        });
        return context.succeed(newContext);
      }
    }
  );
};

const getSigningKeysForCowork = (header, callback) => {
  coworkKeys
    .getPublicKey(header.kid)
    .then((signingKey) => callback(null, signingKey))
    .catch((err) => callback(err));
};

/**
 * 校验 daedalus 签发的 cowork run token（RS256，outbound aud = hongshan-lite-api）。
 *
 * 与 Okta/MSAL 分支的关键差异：
 * - 强制 `algorithms: ['RS256']`。
 * - `issuer` 用 process.env.COWORK_ISSUER 精确比对——绝不能用 decoded.iss
 *   （token 自证），否则 dev 签的 token 能在 prod 通过。
 * - policy 不用 allowAllMethods，改按 `scp` 声明经 cowork-scope-policy 逐条放行。
 * - principalId = transpileToComEmail(sub)，与 daedalus 的 sub 归一对齐。
 */
const verifyCoworkAgentToken = (accessToken, event, context) => {
  const issuer = process.env.COWORK_ISSUER;
  if (!issuer) {
    console.error("COWORK_ISSUER not configured");
    return context.fail("Unauthorized");
  }

  jsonWebToken.verify(
    accessToken,
    getSigningKeysForCowork,
    {
      algorithms: ["RS256"],
      issuer,
      audience: process.env.AUDIENCE,
    },
    (err, payload) => {
      if (err) {
        console.log(err);
        return context.fail("Unauthorized");
      }
      // sub 是身份主依据，缺失/非字符串时 fail-closed——否则 transpileToComEmail
      // 会对 undefined 抛 TypeError，令 Lambda 报 500 而非显式 Unauthorized。
      if (typeof payload.sub !== "string" || payload.sub.trim() === "") {
        console.error("cowork-agent token missing/invalid sub claim");
        return context.fail("Unauthorized");
      }
      const principalId = transpileToComEmail(payload.sub);
      const policy = buildCoworkPolicy(event, principalId, payload.scp);
      console.log(`Auth succeed as cowork-agent ${principalId}`);
      const newContext = policy.build({
        principalId,
        tokenHash: tokenHash(accessToken),
        coworkRunId: payload.jti,
      });
      return context.succeed(newContext);
    }
  );
};

const verifyOktaToken = (accessToken, event, context, allowAccess) => {
  oktaJwtVerifier
    .verifyAccessToken(accessToken, process.env.AUDIENCE)
    .then((jwt) => {
      // the token is valid (per definition of 'valid' above)
      console.log("okta request principal: " + JSON.stringify(jwt.claims));

      const policy = allowAccess(event, jwt.claims.sub);
      console.log(`Auth succeed as ${jwt.claims.sub}`);
      const newContext = policy.build({
        principalId: jwt.claims.sub,
        tokenHash: tokenHash(accessToken),
      });
      return context.succeed(newContext);
    })
    .catch((err) => {
      console.log(err);
      const decoded = jsonWebToken.decode(accessToken);

      console.error("Decoded Okta token is " + JSON.stringify(decoded));
      return context.fail("Unauthorized");
    });
};

module.exports.transpileToComEmail = transpileToComEmail;
module.exports.resolveAuthorizerTypeByIssuer = resolveAuthorizerTypeByIssuer;
module.exports.buildAzureValidationOptions = buildAzureValidationOptions;
module.exports.verifyAccessToken = function verifyAccessToken(
  accessToken,
  event,
  context,
  allowAccess
) {
  let decoded = null;
  try {
    decoded = jsonWebToken.decode(accessToken);
  } catch (err) {
    console.error("Failed to decode access token: " + err.message);
  }

  let authorizerType = resolveAuthorizerTypeByIssuer(decoded);

  if (authorizerType) {
    console.log(
      `Authorizer resolved by iss: ${authorizerType} (iss=${decoded.iss})`
    );
  } else {
    const legacyType = resolveAuthorizerTypeByHeader(event);
    if (legacyType) {
      console.warn(
        `Unrecognized iss (${
          (decoded && decoded.iss) || "<none>"
        }), falling back to legacy header authorizer: ${legacyType}`
      );
      authorizerType = legacyType;
    } else {
      console.error(
        `Unauthorized: unrecognized token issuer: ${
          (decoded && decoded.iss) || "<none>"
        }`
      );
      return context.fail("Unauthorized");
    }
  }

  if (authorizerType === AUTHORIZER_TYPE.OKTA) {
    return verifyOktaToken(accessToken, event, context, allowAccess);
  }
  if (authorizerType === AUTHORIZER_TYPE.COWORK_AGENT) {
    return verifyCoworkAgentToken(accessToken, event, context);
  }
  return verifyAzureToken(
    authorizerType,
    accessToken,
    decoded,
    event,
    context,
    allowAccess
  );
};

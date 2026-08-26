require("dotenv").config();

const OktaJwtVerifier = require("@okta/jwt-verifier");
const jsonWebToken = require("jsonwebtoken");
const crypto = require("crypto");
const jwksClient = require("jwks-rsa");
const keyCache = require("./key-cache");

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
};

// issuer 前缀 → authorizer 类型，按声明 `iss` 自动路由验签方式
const ISSUER_PREFIXES = [
  { prefix: "https://sts.windows.net", type: AUTHORIZER_TYPE.MSAL },
  { prefix: "https://sts.chinacloudapi.cn", type: AUTHORIZER_TYPE.MSAL_CN },
  { prefix: "https://hongshan.okta.com", type: AUTHORIZER_TYPE.OKTA },
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

// 两种 Azure 验签方式共用一个流程，仅 appId / 密钥来源 / principalId 生成方式不同
const AZURE_AUTHORIZERS = {
  [AUTHORIZER_TYPE.MSAL]: {
    label: "MSAL",
    getAppId: () => process.env.AAD_APPLICATION_ID,
    getSigningKeys,
    toPrincipalId: (upn) => upn, // 保持原行为：不 transpile
  },
  [AUTHORIZER_TYPE.MSAL_CN]: {
    label: "MSAL-CN",
    getAppId: () => process.env.AAD_CN_APPLICATION_ID,
    getSigningKeys: getSigningKeysForAzureCN,
    toPrincipalId: transpileToComEmail, // 保持原行为：transpile
  },
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

  if (!decoded || config.getAppId() !== decoded.appid) {
    console.error(
      `Decoded ${config.label} token is invalid: ` + JSON.stringify(decoded)
    );
    return context.fail("Unauthorized");
  }

  const validationOptions = {
    audience: decoded.aud,
    issuer: decoded.iss,
  };

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
  return verifyAzureToken(
    authorizerType,
    accessToken,
    decoded,
    event,
    context,
    allowAccess
  );
};

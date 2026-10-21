'use strict';

/**
 * 自包含测试基建：环境预设、RSA 密钥对、JWT 构造、离线桩、context/run 工具。
 *
 * 桩注入原理：verify-token.js 在模块顶层实例化 jwks-rsa 客户端与
 * @okta/jwt-verifier，因此桩必须在首次 require('../verify-token.js') 之前
 * 经 Module._load 拦截安装。node --test 每个测试文件独立进程，helpers
 * 可被多个测试文件安全复用。
 *
 * @okta/jwt-verifier 4.0.1 的 CJS require 直接返回 class（已实测），
 * 桩导出形状与之对齐。
 */

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const Module = require('module');

/** 环境预设：先于 dotenv 与 verify-token 的模块顶层读取生效 */
function setupEnv(overrides = {}) {
  process.env.AAD_APPLICATION_ID = 'aad-app-id';
  process.env.AAD_CN_APPLICATION_ID = 'aad-cn-app-id';
  process.env.ISSUER = 'https://hongshan.okta.com/oauth2/default';
  process.env.CLIENT_ID = 'okta-client-id';
  process.env.AUDIENCE = 'hongshan-lite-api';
  process.env.COWORK_ISSUER = 'https://cowork.hongshan.com';
  Object.assign(process.env, overrides);
}

/** 生成测试 RSA 密钥对（与线上 RS256 验签算法一致） */
function makeKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });
  return {
    pubPem: publicKey.export({ type: 'spki', format: 'pem' }),
    privPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  };
}

/**
 * 安装离线桩（必须在 require verify-token.js 之前调用）。
 *
 * @param {object} keys - kid → 公钥 PEM 的内存 JWKS（Azure / Azure CN 共用）
 * @returns {object} oktaState - 可在用例间改写 verifyAccessToken 的行为
 */
function installStubs({ keys }) {
  // jwks-rsa 3.x 的 CJS require 返回可调用函数（已实测），桩形状与之对齐
  const jwksFake = () => ({
    getSigningKey: (kid, cb) => {
      const key = keys[kid];
      if (!key) return cb(new Error(`Unknown kid: ${kid}`));
      cb(null, { publicKey: key });
    },
  });

  const oktaState = {
    // 默认 fail：用例显式改写才走 allow，避免误放行
    verifyAccessToken: async () => {
      throw new Error('okta stub not programmed for this case');
    },
  };

  const oktaFake = class OktaJwtVerifierStub {
    constructor() {}
    verifyAccessToken(...args) {
      return oktaState.verifyAccessToken(...args);
    }
  };

  const originalLoad = Module._load;
  Module._load = function (request, parent, isMain) {
    if (request === 'jwks-rsa') return jwksFake;
    if (request === '@okta/jwt-verifier') return oktaFake;
    return originalLoad.call(this, request, parent, isMain);
  };

  return { oktaState };
}

/** 标准 API Gateway authorizer 事件（methodArn 形状与线上一致） */
function makeEvent(overrides = {}) {
  return {
    type: 'TOKEN',
    methodArn:
      'arn:aws:execute-api:ap-northeast-1:592267666562:lp360api/dev/GET/api/mcp',
    ...overrides,
  };
}

/**
 * 以 Promise 风格包装 verify 调用（#32 async 迁移后的新 API）。
 * resolve → { ok:true, auth }；message==='Unauthorized' 的拒绝 → { ok:false, msg }
 * （这是 API Gateway 映射 401 的外部契约字面量，测试侧硬编码）；
 * 其余内部异常原样抛出——不能伪装成 deny 造成假绿。
 */
function run(verifyFn, token, event, allowAccess) {
  return verifyFn(token, event, allowAccess)
    .then((auth) => ({ ok: true, auth }))
    .catch((err) => {
      if (err && err.message === 'Unauthorized') {
        return { ok: false, msg: err.message };
      }
      throw err;
    });
}

/** Azure(MSAL) 访问令牌 */
function signAzure({ keyPair, iss, appid, upn, aud, kid = 'test-kid' }) {
  return jwt.sign({ iss, appid, upn, aud }, keyPair.privPem, {
    algorithm: 'RS256',
    keyid: kid,
    expiresIn: 300,
  });
}

/** cowork-agent run token（对齐 daedalus 签发形状） */
function signCowork({ keyPair, kid = 'test-kid', ...claimOverrides } = {}) {
  return jwt.sign(
    {
      uid: 123,
      aid: 'agent-1',
      scp: ['cowork:mcp', 'cowork:read'],
      iss: process.env.COWORK_ISSUER,
      sub: 'bbao@hongshan.com',
      aud: process.env.AUDIENCE,
      ...claimOverrides,
    },
    keyPair.privPem,
    {
      algorithm: 'RS256',
      keyid: kid,
      expiresIn: 300,
      jwtid: 'run-123',
    }
  );
}

module.exports = {
  setupEnv,
  makeKeyPair,
  installStubs,
  makeEvent,
  run,
  signAzure,
  signCowork,
};

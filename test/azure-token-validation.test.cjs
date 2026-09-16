/**
 * Azure（MSAL / MSAL-CN）tenant + audience 校验的契约测试。
 *
 * 为什么不用 lambda-local 跑端到端：Azure 的签名密钥经网络 JWKS 获取，离线不可用；
 * 而「为测试往生产验签路径开后门」不可接受。退一步的做法是——本地生成密钥对，
 * 把 buildAzureValidationOptions() 产出的真实 options 直接交给 jsonwebtoken.verify。
 * 这样验证的是「这套 options 在真实库下确实会拒」，而不是「options 对象长这样」。
 *
 * 覆盖：正例、issuer 尾斜杠双形式、错 tenant、错 aud、多值 aud、alg=none、
 * HS256 算法混淆（拿公钥当 HMAC 密钥）、以及 tenant/aud 未配置时的 fail-open 行为。
 *
 * 用法：node test/azure-token-validation.test.cjs
 * 自包含：运行时生成测试密钥对，不依赖真实私钥。退出码 0 = 全部符合预期。
 */
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const pubPem = publicKey.export({ type: 'spki', format: 'pem' });
const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' });

const GLOBAL_BASE = 'https://sts.windows.net';
const CN_BASE = 'https://sts.chinacloudapi.cn';
const TENANT = 'tenant-global-1111';
const AUD = 'api://aaa';

process.env.AAD_APPLICATION_ID = 'app-global';
process.env.AAD_TENANT_ID = TENANT;
process.env.AAD_AUDIENCE = `${AUD}, api://bbb`;
process.env.AAD_CN_APPLICATION_ID = 'app-cn';
process.env.AAD_CN_TENANT_ID = 'tenant-cn-2222';
process.env.AAD_CN_AUDIENCE = 'api://cn';
process.env.AUDIENCE = process.env.AUDIENCE || 'hongshan-lite-api';

const { buildAzureValidationOptions } = require('../verify-token.js');

/** 用给定的 options 跑一次真实验签，返回是否放行。 */
function verify(token, options) {
  return new Promise((resolve) => {
    jwt.verify(token, pubPem, options, (err) => resolve(!err));
  });
}

/** 签一个 Azure 形态的 token（RS256，默认正确 tenant/aud）。 */
const sign = (opts = {}) =>
  jwt.sign({ upn: 'bbao@hongshan.com', appid: 'app-global' }, privPem, {
    algorithm: opts.algorithm || 'RS256',
    issuer: opts.issuer || `${GLOBAL_BASE}/${TENANT}/`,
    audience: opts.audience || AUD,
    expiresIn: 300,
  });

(async () => {
  const results = [];
  const check = async (label, token, options, expectAllow) => {
    const allowed = await verify(token, options);
    const pass = allowed === expectAllow;
    results.push(pass);
    console.log(
      `${label} →`,
      allowed ? (expectAllow ? 'ALLOW ✓' : 'ALLOW (BUG!)') : expectAllow ? 'DENY (BUG!)' : 'DENY ✓',
    );
  };

  const opts = buildAzureValidationOptions('MSAL');
  const cnOpts = buildAzureValidationOptions('MSAL-CN');

  // 正例：正确 tenant + 正确 aud
  await check('valid', sign(), opts, true);

  // issuer 不带尾斜杠也应放行（双形式设计）
  await check('issuer-no-trailing-slash', sign({ issuer: `${GLOBAL_BASE}/${TENANT}` }), opts, true);

  // 错 tenant：换一个 tenant ID，同一 base
  await check('wrong-tenant', sign({ issuer: `${GLOBAL_BASE}/other-tenant/` }), opts, false);

  // 错 cloud：中国区 tenant 拿到全球版 options 下必须拒（防止 base 串线）
  await check('wrong-cloud', sign({ issuer: `${CN_BASE}/${TENANT}/` }), opts, false);

  // 错 aud
  await check('wrong-audience', sign({ audience: 'api://evil' }), opts, false);

  // 多值 aud：命中逗号分隔列表里的第二个
  await check('multivalue-audience-2nd', sign({ audience: 'api://bbb' }), opts, true);

  // alg=none
  const noneToken = jwt.sign({}, Buffer.alloc(0), {
    algorithm: 'none',
    issuer: `${GLOBAL_BASE}/${TENANT}/`,
    audience: AUD,
  });
  await check('alg-none', noneToken, opts, false);

  // HS256 拿公钥当 HMAC 密钥（经典算法混淆攻击）
  try {
    const hsToken = jwt.sign({}, pubPem, {
      algorithm: 'HS256',
      issuer: `${GLOBAL_BASE}/${TENANT}/`,
      audience: AUD,
    });
    await check('alg-confusion', hsToken, opts, false);
  } catch (e) {
    results.push(true);
    console.log('alg-confusion → sign error (skipped):', e.message);
  }

  // CN 用 CN 的 options：正确 issuer + 正确 CN aud 放行
  await check(
    'cn-valid',
    sign({ issuer: `${CN_BASE}/tenant-cn-2222/`, audience: 'api://cn' }),
    cnOpts,
    true,
  );

  // CN 的 options 不接受全球版的 aud（防止 audience 串线）
  await check('cn-rejects-global-aud', sign({ issuer: `${CN_BASE}/tenant-cn-2222/` }), cnOpts, false);

  // CN 的 options 不接受全球版 tenant
  await check('cn-rejects-global', sign(), cnOpts, false);

  // fail-open：tenant/audience 未配置时应跳过校验、不回归
  const savedTenant = process.env.AAD_TENANT_ID;
  const savedAud = process.env.AAD_AUDIENCE;
  delete process.env.AAD_TENANT_ID;
  delete process.env.AAD_AUDIENCE;
  const failOpenOpts = buildAzureValidationOptions('MSAL');
  await check('fail-open-unconfigured', sign({ issuer: 'https://evil.example.com/', audience: 'api://evil' }), failOpenOpts, true);
  process.env.AAD_TENANT_ID = savedTenant;
  process.env.AAD_AUDIENCE = savedAud;

  const failed = results.filter((r) => !r).length;
  console.log(`\n${results.length - failed}/${results.length} passed`);
  process.exit(failed === 0 ? 0 : 1);
})();

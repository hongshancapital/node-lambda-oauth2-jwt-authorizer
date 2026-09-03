/**
 * Cowork Run JWT 公钥解析与缓存。
 *
 * 公钥经 Lambda 环境变量 COWORK_JWT_PUBLIC_KEYS 下发：kid → PEM 的 JSON map。
 * 多 kid 并存支持密钥轮换（新旧并存期两把都在 map 里，无需代码发布）。
 * 未知 kid → 拒（fail-closed）。
 *
 * 与 key-cache.js 的 JWKS 模式不同：这里不依赖网络端点。若把 JWKS 端点挂在
 * daedalus（同一网关之后），会形成「验签依赖被验签的服务」的循环——冷 Lambda
 * 遇 daedalus 抖动会整片 401。环境变量无网络依赖、无循环。
 *
 * PEM 含换行，环境变量里用 \n 转义；此处读取后原样交给 jsonwebtoken（它接受
 * PEM 公钥字符串）。
 */

const COWORK_PUBLIC_KEYS_JSON = process.env.COWORK_JWT_PUBLIC_KEYS || "{}";

let cachedKeys = null;

const parseKeys = () => {
  if (cachedKeys) {
    return cachedKeys;
  }
  try {
    cachedKeys = JSON.parse(COWORK_PUBLIC_KEYS_JSON);
  } catch (err) {
    console.error("Failed to parse COWORK_JWT_PUBLIC_KEYS:", err);
    cachedKeys = {};
  }
  return cachedKeys;
};

/**
 * 按 kid 取公钥 PEM。返回 Promise，签名与 jsonwebtoken 的 getKey 回调协议对齐
 * （`jsonWebToken.verify(token, getKey, options, cb)`）。
 */
const getPublicKey = (kid) => {
  return new Promise((resolve, reject) => {
    const keys = parseKeys();
    const key = kid ? keys[kid] : undefined;
    if (!key) {
      return reject(new Error(`Unknown cowork JWT kid: ${kid}`));
    }
    resolve(key);
  });
};

module.exports = { getPublicKey };

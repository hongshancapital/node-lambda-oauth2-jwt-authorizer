const CACHE_TTL_IN_MS = 3 * 60 * 60 * 1000;

const keyCache = {
  // Azure 全球版的密钥缓存
  azure: {},
  // Azure 中国版的密钥缓存
  azureCN: {},
};

/**
 * 从缓存获取密钥，如果缓存未命中则通过回调函数获取
 * @param {string} provider - 提供商标识（'azure' 或 'azureCN'）
 * @param {string} kid - 密钥ID
 * @param {Function} fetchCallback - 缓存未命中时用于获取密钥的回调函数
 * @returns {Promise<string>} - 返回密钥
 */
const getKey = async (provider, kid, fetchCallback) => {
  // 检查参数
  if (!provider || !kid || typeof fetchCallback !== "function") {
    throw new Error("无效的参数");
  }

  // 检查提供商是否有效
  if (!keyCache[provider]) {
    throw new Error(`未知的提供商: ${provider}`);
  }

  // 检查缓存是否命中
  if (
    keyCache[provider][kid] &&
    keyCache[provider][kid].expiresAt > Date.now()
  ) {
    console.log(`缓存命中: ${provider} 密钥 ${kid}`);
    return keyCache[provider][kid].publicKey;
  }

  // 缓存未命中，调用回调函数获取密钥
  console.log(`缓存未命中: ${provider} 密钥 ${kid}，从远程获取`);
  try {
    const signingKey = await fetchCallback(kid);

    // 更新缓存
    keyCache[provider][kid] = {
      publicKey: signingKey,
      expiresAt: Date.now() + CACHE_TTL_IN_MS,
    };

    console.log(
      `已缓存 ${provider} 密钥 ${kid}，有效期至 ${new Date(
        keyCache[provider][kid].expiresAt
      ).toISOString()}`
    );
    return signingKey;
  } catch (error) {
    console.error(`获取 ${provider} 密钥失败: ${error.message}`);
    throw error;
  }
};

module.exports = {
  getKey,
};

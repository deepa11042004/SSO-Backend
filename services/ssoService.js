import crypto from "crypto";
import redis from "../config/redis.js";

const SSO_TTL_SECONDS = 15;
const ssoKey = (token) => `sso:${token}`;

export const generateSsoToken = async ({ userId, userAgent, ip, siteBUrl }) => {
  const token = crypto.randomBytes(32).toString("hex");
  const payload = JSON.stringify({ userId, userAgent, ip });
  await redis.set(ssoKey(token), payload, "EX", SSO_TTL_SECONDS);

  const redirectBase = siteBUrl || "https://siteB.com/sso-login";
  const separator = redirectBase.includes("?") ? "&" : "?";
  const redirectUrl = `${redirectBase}${separator}token=${token}`;

  return { token, redirectUrl, expiresInSeconds: SSO_TTL_SECONDS };
};

export const consumeSsoToken = async (token, { userAgent, ip }) => {
  if (!token) return null;

  const key = ssoKey(token);
  const payload = await redis.get(key);
  if (!payload) return null;

  await redis.del(key); // one-time use

  try {
    const parsed = JSON.parse(payload);
    // Optional binding check: user-agent/ip
    if (parsed.userAgent && userAgent && parsed.userAgent !== userAgent) return null;
    if (parsed.ip && ip && parsed.ip !== ip) return null;
    return parsed.userId;
  } catch (err) {
    return null;
  }
};

import redis from "../config/redis.js";

const SESSION_TTL_SECONDS = parseInt(process.env.SESSION_TTL_SECONDS || "604800", 10); // 7 days

const sessionKey = (sessionId) => `session:${sessionId}`;
const userSessionsKey = (userId) => `user:${userId}:sessions`;

export const createSession = async (userId, sessionId, createdAt = Date.now()) => {
  await redis
    .multi()
    .hset(sessionKey(sessionId), {
      user_id: String(userId),
      session_id: sessionId,
      created_at: String(createdAt)
    })
    .expire(sessionKey(sessionId), SESSION_TTL_SECONDS)
    .zadd(userSessionsKey(userId), createdAt, sessionId)
    .exec();

  return { session_id: sessionId, created_at: createdAt };
};

export const getSession = async (sessionId) => {
  const session = await redis.hgetall(sessionKey(sessionId));
  if (!session || !session.user_id) return null;
  return {
    session_id: session.session_id,
    user_id: session.user_id,
    created_at: Number(session.created_at || Date.now())
  };
};

export const deleteSession = async (sessionId) => {
  const session = await redis.hgetall(sessionKey(sessionId));
  if (!session || !session.user_id) {
    await redis.del(sessionKey(sessionId));
    return false;
  }

  await redis
    .multi()
    .del(sessionKey(sessionId))
    .zrem(userSessionsKey(session.user_id), sessionId)
    .exec();
  return true;
};

export const getUserSessions = async (userId) => {
  const entries = await redis.zrange(userSessionsKey(userId), 0, -1, "WITHSCORES");
  if (!entries.length) return [];

  const sessions = [];
  for (let i = 0; i < entries.length; i += 2) {
    const value = entries[i];
    const score = Number(entries[i + 1]);
    const session = await redis.hgetall(sessionKey(value));
    sessions.push({
      session_id: value,
      user_id: session.user_id,
      created_at: Number(session.created_at || score)
    });
  }

  return sessions.filter((s) => s.user_id);
};

export const enforceSessionLimit = async (userId, limit = 2) => {
  const sessions = await getUserSessions(userId);
  if (sessions.length < limit) return;

  const sorted = [...sessions].sort((a, b) => a.created_at - b.created_at);
  const toRemove = sorted.slice(0, sessions.length - limit + 1); // remove oldest until one slot opens
  for (const sess of toRemove) {
    await deleteSession(sess.session_id);
  }
};

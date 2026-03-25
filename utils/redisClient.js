import redis from "../config/redis.js";
export { default as redisClient } from "../config/redis.js";
export {
  createSession,
  deleteSession,
  enforceSessionLimit,
  getSession,
  getUserSessions
} from "../services/sessionService.js";

export default redis;

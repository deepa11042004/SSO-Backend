import jwt from "jsonwebtoken";
import { getSession } from "../services/sessionService.js";

const jwtSecret = process.env.JWT_SECRET || "fallback-secret";

const authMiddleware = async (req, res, next) => {
  try {
    const bearer = req.headers.authorization || "";
    const tokenFromHeader = bearer.startsWith("Bearer ") ? bearer.slice(7) : null;
    const token = req.cookies?.token || tokenFromHeader;

    if (!token) return res.status(401).json({ error: "Authentication required" });

    const decoded = jwt.verify(token, jwtSecret);
    const { session_id: sessionId, id: userId } = decoded;
    if (!sessionId || !userId) return res.status(401).json({ error: "Invalid token" });

    const session = await getSession(sessionId);
    if (!session || session.user_id !== String(userId)) {
      return res.status(401).json({ error: "Session expired or invalid" });
    }

    req.user = { id: userId, session_id: sessionId };
    next();
  } catch (err) {
    console.error("Auth middleware error:", err.message);
    res.status(401).json({ error: "Unauthorized" });
  }
};

export default authMiddleware;

import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { randomBytes, randomUUID } from "crypto";
import User from "../models/User.js";
import {
  createSession,
  enforceSessionLimit,
  getSession
} from "../services/sessionService.js";
import { consumeSsoToken, generateSsoToken } from "../services/ssoService.js";

const jwtSecret = process.env.JWT_SECRET || "fallback-secret";
const jwtExpiresIn = process.env.JWT_EXPIRES_IN || "7d";
const cookieMaxAgeMs = parseInt(process.env.JWT_COOKIE_MAX_AGE || "604800000", 10); // 7 days default
const siteBUrl = process.env.SITE_B_SSO_URL || "https://siteB.com/sso-login";

const issueToken = (userId, sessionId) =>
  jwt.sign({ id: userId, session_id: sessionId }, jwtSecret, { expiresIn: jwtExpiresIn });

const setAuthCookie = (res, token) => {
  res.cookie("token", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: cookieMaxAgeMs
  });
};

const newSessionId = () => {
  try {
    return randomUUID();
  } catch (err) {
    return randomBytes(16).toString("hex");
  }
};

export const signup = async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email and password required" });

    const existing = await User.findOne({ email });
    if (existing) return res.status(409).json({ error: "User already exists" });

    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ email, password: hash, name });

    res.status(201).json({ message: "User registered", userId: user._id });
  } catch (err) {
    console.error("SignUp error:", err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
};

export const signin = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email and password required" });

    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: "Invalid credentials" });

    await enforceSessionLimit(user._id, 2);
    const sessionId = newSessionId();
    await createSession(user._id, sessionId);

    const token = issueToken(user._id, sessionId);
    setAuthCookie(res, token);

    res.json({
      message: "Login successful",
      user: { id: user._id, name: user.name, email: user.email },
      sessionId
    });
  } catch (err) {
    console.error("SignIn error:", err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
};

export const generateSsoTokenHandler = async (req, res) => {
  try {
    const { token, redirectUrl, expiresInSeconds } = await generateSsoToken({
      userId: req.user.id,
      userAgent: req.headers["user-agent"],
      ip: req.ip,
      siteBUrl
    });

    res.json({ token, redirectUrl, expiresInSeconds });
  } catch (err) {
    console.error("generateSsoToken error:", err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
};

export const ssoLogin = async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: "Token is required" });

    const userId = await consumeSsoToken(token, {
      userAgent: req.headers["user-agent"],
      ip: req.ip
    });

    if (!userId) return res.status(400).json({ error: "Invalid or expired token" });

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    await enforceSessionLimit(user._id, 2);
    const sessionId = newSessionId();
    await createSession(user._id, sessionId);

    const jwtToken = issueToken(user._id, sessionId);
    setAuthCookie(res, jwtToken);

    res.json({
      message: "SSO login successful",
      user: { id: user._id, name: user.name, email: user.email },
      sessionId,
      token: jwtToken
    });
  } catch (err) {
    console.error("ssoLogin error:", err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
};

export const validateSession = async (req, res) => {
  try {
    const { session_id: sessionId, id: userId } = req.user;
    const session = await getSession(sessionId);
    if (!session || session.user_id !== String(userId)) {
      return res.status(401).json({ error: "Session invalid" });
    }

    res.json({ message: "Session valid", session });
  } catch (err) {
    console.error("validateSession error:", err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
};

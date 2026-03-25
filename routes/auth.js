import express from "express";
import {
  generateSsoTokenHandler,
  signin,
  signup,
  validateSession,
  ssoLogin
} from "../controllers/authController.js";
import authMiddleware from "../middlewares/authMiddleware.js";

const router = express.Router();

router.post("/signup", signup);
router.post("/signin", signin);
router.post("/generate-sso-token", authMiddleware, generateSsoTokenHandler);
router.post("/sso-login", ssoLogin);
router.get("/session", authMiddleware, validateSession);

export default router;

import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import cookieParser from "cookie-parser";
import connectDB from "./config/mongodb.js";
import authRoutes from "./routes/auth.js";

dotenv.config();

const app = express();

// ✅ Enable JSON + cookies for POST requests
app.use(express.json());
app.use(cookieParser());

// ✅ Enable CORS for your frontend (local + deployed)
const allowedOrigins = [
  process.env.FRONTEND_URL,
  "http://localhost:5173",
  "https://quick-quiz-puce.vercel.app"
].filter(Boolean);

app.use(cors({
  origin: allowedOrigins,
  methods: ["GET", "POST", "PUT", "DELETE"],
  credentials: true
}));

// ✅ Routes
app.use("/api/auth", authRoutes);

// ✅ Connect to MongoDB
connectDB();

// ✅ Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Backend listening on port ${PORT}`);
});

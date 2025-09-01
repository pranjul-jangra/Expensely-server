import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import Redis from "ioredis";
import { RateLimiterRedis } from "rate-limiter-flexible";
import { connectDb } from './config/connectDb.js';
import userRouter from './routes/userRouter.js';
import expenseRouter from './routes/expenseRouter.js';
import { errorHandler } from './middlewares/errorHandler.js';
import cookieParser from "cookie-parser";
import jwt from 'jsonwebtoken';
import keepAliveRouter from './routes/keepAliveRouter.js';

// Configs ===========================================================================================
dotenv.config();
const app = express();
const port = process.env.PORT || 5200;

// Rate limiter ======================================================================================
// Redis client setup
// const redisClient = new Redis(process.env.UPSTASH_REDIS_URL);
// redisClient.on("connect", () => console.log("Connected to Redis"));
// redisClient.on("error", (err) => console.error("Redis Error:", err));

// // Extract user ID
// const getUserKey = async (req) => {
//     try {
//         const token = req.headers?.authorization?.split(" ")?.[1];
//         if (!token) return req.ip;

//         const decoded = await jwt.verify(token, process.env.ACCESS_SECRET);
//         return decoded.id || req.ip;

//     } catch (error) {
//         return req.ip;
//     }
// }

// // Sliding window rate limiting
// const rateLimiter = new RateLimiterRedis({
//     storeClient: redisClient,
//     keyPrefix: "rlflx",
//     points: 300,        // 300 requests
//     duration: 300,      // Per 300 seconds (5 minutes)
//     blockDuration: 60,  // Optional: block for 1 mins after limit exceeded
// });

// // Limiter middleware
// const rateLimiterMiddleware = async (req, res, next) => {
//     try {
//         const key = await getUserKey(req);
//         await rateLimiter.consume(key);
//         next();
//     } catch (rejRes) {
//         // Too many requests
//         res.status(429).json({
//             error: "Too many requests. Please wait before retrying.",
//             retryAfter: Math.ceil(rejRes.msBeforeNext / 1000) + "s",
//         });
//     }
// };

// Middlewares =======================================================================================
app.use(cookieParser());
// app.use(rateLimiterMiddleware);
connectDb();
app.use(express.json());

app.use(cors({
    origin: process.env.FRONTEND_URL,
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: [
        'Content-Type',
        'Authorization',
        'X-Requested-With',
        'Accept',
        'Origin',
        'Cache-Control',
        'X-File-Name'
    ],
}));
app.options(/.*/, cors());

app.set('trust proxy', true);


// Routes ============================================================================================
app.use('/api/user', userRouter);
app.use('/api/expense', expenseRouter);
app.use('/api/alive', keepAliveRouter);



// Error Handler =====================================================================================
app.use(errorHandler);

// Listen to port ====================================================================================
app.listen(port, () => console.log("Server is running", port));
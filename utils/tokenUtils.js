import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();


// Generate tokens
export const generateTokens = async ({ id }) => {
    const accessToken = await jwt.sign({ id }, process.env.ACCESS_SECRET, { expiresIn: "15m" });
    const refreshToken = await jwt.sign({ id }, process.env.REFRESH_SECRET, { expiresIn: "15d" });

    return { accessToken, refreshToken };
}

// Verify access token
export const verifyAccessToken = async (token) => {
    try {
        const decoded = await jwt.verify(token, process.env.ACCESS_SECRET);
        return decoded;
    } catch (error) {
        return null;
    }
};

// Verify refresh token
export const verifyRefreshToken = async (token) => {
    try {
        const decoded = await jwt.verify(token, process.env.REFRESH_SECRET);
        return decoded;
    } catch (error) {
        return null;
    }
};


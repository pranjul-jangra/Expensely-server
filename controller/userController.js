import userModel from "../models/userSchema.js";
import tokenModel from "../models/tokenSchema.js";
import transactionModel from "../models/transactionsSchema.js";
import mongoose from "mongoose";
import savingsModel from "../models/savingsSchema.js";
import fs from "fs/promises";
import bcrypt from "bcryptjs";
import { Mail } from "../utils/mail.js";
import { generateTokens, verifyAccessToken, verifyRefreshToken } from "../utils/tokenUtils.js";
import { extractPublicId } from "../utils/extractPublicId.js";
import cloudinary from "../middlewares/uploadImage.js";
import { validateEmail, validateProfileInfo, validateSignupFormData } from "../utils/zodValidation.js";
import jwt from "jsonwebtoken";


// New signup
export const registerUser = async (req, res) => {
    try {
        const validation = validateSignupFormData.safeParse(req.body);
        if (!validation.success) {
            const errors = validation.error.flatten().fieldErrors;
            return res.status(400).json({ error: "Validation failed", details: errors });
        }

        const { name, email, password } = validation.data;
        if (!name || !email || !password) return res.status(400).json({ error: "All fields are required" });

        // Check if email present?
        const isExists = await userModel.findOne({ email });
        if (isExists) return res.status(409).json({ error: "Email already in use." });

        // Hash token & create user
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await userModel.create({ name, email, password: hashedPassword });

        // Generate token
        const { accessToken, refreshToken } = await generateTokens({ id: newUser._id });

        // Hash refresh token & save session
        const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
        newUser.sessions = [hashedRefreshToken];
        await newUser.save();

        // Set cookie
        const secure = process.env.NODE_ENV === "production";
        res.cookie("refreshToken", refreshToken, { httpOnly: true, sameSite: secure ? "None" : "Lax", secure, maxAge: 15 * 24 * 60 * 60 * 1000 });
        res.status(200).json({ message: "User registered.", accessToken });

    } catch (error) {
        res.status(500).json({ error: "Error registering user due to server error" });
    }
}

// Login 
export const login = async (req, res) => {
    try {
        const validation = validateSignupFormData.safeParse(req.body);
        if (!validation.success) {
            const errors = validation.error.flatten().fieldErrors;
            return res.status(400).json({ error: "Validation failed", details: errors });
        }

        const { email, password } = validation.data;
        if (!email || !password) return res.status(400).json({ error: "All fields are required" });

        const user = await userModel.findOne({ email }).select("+password");
        if (!user) return res.status(404).json({ error: "No user found with this email." });

        // Comparing passwords
        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) return res.status(400).json({ error: "Invalid password" });

        // Generate tokens & hash refresh token
        const { accessToken, refreshToken } = await generateTokens({ id: user._id });
        const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);

        // Update session
        user.sessions = [...(user.sessions || []), hashedRefreshToken]
        await user.save();

        const secure = process.env.NODE_ENV === "production";
        res.cookie("refreshToken", refreshToken, { httpOnly: true, sameSite: secure ? "None" : "Lax", secure, maxAge: 15 * 24 * 60 * 60 * 1000 });
        res.status(200).json({ message: "Login successfully", accessToken });

    } catch (error) {
        res.status(500).json({ error: "Error loging user due to server error" })
    }
}

// Logout
export const logout = async (req, res) => {
    try {
        const refreshToken = req.cookies?.refreshToken;
        const accessToken = req.headers?.authorization?.split(" ")?.[1];
        if (!accessToken) return res.status(401).json({ error: "Unthauthorized. Token not available." });

        // Decode token
        const decoded = await verifyAccessToken(accessToken);
        if (!decoded || !decoded.id) return res.status(401).json({ error: "Invalid token" });

        // Find user
        const user = await userModel.findById(decoded.id).select("+sessions");
        if (!user) return res.status(404).json({ error: "No user found" });

        // Removing current session
        user.sessions = user.sessions.filter((s) => !bcrypt.compareSync(refreshToken, s));
        await user.save();

        res.clearCookie("refreshToken");
        res.status(200).json({ message: "Logout successfully" })

    } catch (error) {
        res.status(500).json({ error: "Error loging out user due to server error" });
    }
}

// Logout All
export const logoutAll = async (req, res) => {
    try {
        const { password } = req.body;
        if (!password) return res.status(400).json({ error: "Password is required" });
        const accessToken = req.headers?.authorization?.split(" ")?.[1];
        if (!accessToken) return res.status(401).json({ error: "Unauthorized. Token not available." });

        // Verify token
        const decoded = await verifyAccessToken(accessToken);
        if (!decoded || !decoded.id) return res.status(401).json({ error: "Invalid token" });

        // Find user
        const user = await userModel.findById(decoded.id).select("+password +sessions");
        if (!user) return res.status(404).json({ error: "No user found" });

        // Validate user
        const isValidUser = await bcrypt.compare(password, user.password);
        if (!isValidUser) return res.status(400).json({ error: "Invalid password" });

        // Clear session
        user.sessions = [];
        await user.save();

        res.clearCookie("refreshToken");
        res.status(200).json({ message: "All sessions cleared" });

    } catch (error) {
        res.status(500).json({ error: "Error clearing sessions due to server error" });
    }
}

// Refresh token
export const refreshToken = async (req, res) => {
    try {
        const refreshToken = req.cookies?.refreshToken;
        if (!refreshToken) return res.status(401).json({ error: "Unauthorized. Session has expired." });
        const decoded = await verifyRefreshToken(refreshToken);
        if (!decoded || !decoded.id) return res.status(401).json({ error: "Unauthorized. Invalid session." });

        // Find user + sessions
        const user = await userModel.findById(decoded.id).select("+sessions");

        // Generate tokens & hash refresh token
        const { accessToken, refreshToken: newRefreshToken } = await generateTokens({ id: user._id });
        const hashedRefreshToken = await bcrypt.hash(newRefreshToken, 10);

        // Remove previous refresh token and add new session
        const matchedIndex = await Promise.all(user.sessions.map(s => bcrypt.compare(refreshToken, s))).then(matches => matches.findIndex(m => m));
        if (matchedIndex === -1) return res.status(401).json({ error: "Unauthorized. Invalid session." });

        user.sessions.splice(matchedIndex, 1);
        user.sessions = [...(user.sessions || []), hashedRefreshToken]
        await user.save();

        // Set cookie
        const secure = process.env.NODE_ENV === "production";
        res.cookie("refreshToken", newRefreshToken, { httpOnly: true, sameSite: secure ? "None" : "Lax", secure, maxAge: 15 * 24 * 60 * 60 * 1000 });
        res.status(200).json({ message: "Token refreshed", accessToken });

    } catch (error) {
        res.status(500).json({ error: "Error refreshing token due to server error." });
    }
}

// Change email (Send link)
export const sendEmailUpdationLink = async (req, res) => {
    try {
        const validation = validateEmail.safeParse(req.body);
        if (!validation.success) {
            return res.status(400).json({ error: "Invalid email structure", details: validation.error.flatten() });
        }
        const { email } = validation.data;
        if (!email || !email.trim()) return res.status(400).json({ error: "Email is required" });

        const accessToken = req.headers?.authorization?.split(" ")?.[1];
        if (!accessToken) return res.status(401).json({ error: "Unauthorized. Token is missing" });
        const decoded = await verifyAccessToken(accessToken);
        if (!decoded) return res.status(401).json({ error: "Unauthorized. Invalid token" });

        // Invalidate the previous token (Link) if exists
        await tokenModel.deleteOne({ userId: decoded.id, type: "emailUpdation" });

        // Generate & hash verification link & create link
        const emailUpdationToken = await jwt.sign({ id: decoded.id }, process.env.EMAIL_SECRET, { expiresIn: "15m" });
        const hashedToken = await bcrypt.hash(emailUpdationToken, 10);
        const link = `${process.env.FRONTEND_URL}/update-email?token=${emailUpdationToken}`;

        // Send mail
        await Mail({
            email,
            subject: "Email Updation Request",
            html: `<!DOCTYPE html>
                    <html lang="en">
                    <head>
                    <meta charset="UTF-8" />
                    <title>Email Updation Request</title>
                    <style>
                        body { font-family: Arial, sans-serif; color: #333; }
                        .container { max-width: 600px; margin: auto; padding: 20px; }
                        .btn {
                        display: inline-block;
                        padding: 12px 20px;
                        background-color: #4CAF50;
                        color: white;
                        text-decoration: none;
                        border-radius: 4px;
                        }
                        .footer { font-size: 12px; color: #777; margin-top: 30px; }
                    </style>
                    </head>
                    <body>
                    <div class="container">
                        <h2>Email Updation Request</h2>
                        <p>Hello,</p>
                        <p>You recently requested to update your email for your Expensely account. Click the button below to update it:</p>
                        <p><a class="btn" href="${link}" target="_blank">Update Email</a></p>
                        <p>Or, enter the following link in your browser:</p>
                        <p><a href="${link}" target="_blank">${link}</a></p>
                        <p>Your link will be valid for 15 minutes. If you didn't request email update, please ignore this email.</p>
                        <p>Do not share this email or link with anyone for your account safety.</p>
                        <div class="footer">
                            <p>Best regards,</p>
                            <p>Expensely</p>
                        </div>
                    </div>
                    </body>
                    </html>`
        })

        // Store the token
        await tokenModel.create({ userId: decoded.id, type: "emailUpdation", token: hashedToken });
        res.status(201).json({ message: "Link sent" });

    } catch (error) {
        res.status(500).json({ error: "Error sending mail (email updation link) due to server error" });
    }
}

// Change email (Verify link & update)
export const updateEmail = async (req, res) => {
    try {
        const { token, newEmail } = req.body;
        if (!token) return res.status(400).json({ error: "Token is missing." });
        if (!newEmail) return res.status(400).json({ error: "New email is required" });

        // Verify token
        const decoded = await jwt.verify(token, process.env.EMAIL_SECRET);
        if (!decoded || !decoded.id) return res.status(400).json({ error: "Invalid token or the link has expired." });

        // Find token and match
        const existingToken = await tokenModel.findOne({ userId: decoded.id, type: "emailUpdation" });
        if (!existingToken) return res.status(400).json({ error: "Link has expired." });

        const isSame = await bcrypt.compare(token, existingToken.token);
        if (!isSame) return res.status(400).json({ error: "Invalid token." });

        // Validate email uniqueness and update
        const isEmailExists = await userModel.findOne({ email: newEmail });
        if (isEmailExists) return res.status(409).json({ error: "Email already in use." });

        await userModel.findByIdAndUpdate(decoded.id, { $set: { email: newEmail } });
        await tokenModel.deleteOne({ userId: decoded.id, type: "emailUpdation" });
        res.status(200).json({ message: "Email updated" });

    } catch (error) {
        res.status(500).json({ error: "Error updating email due to server error" });
    }
}

// Change password
export const changePassword = async (req, res) => {
    try {
        const { password, newPassword } = req.body;
        if (!password || !newPassword) return res.status(400).json({ error: "Password and new password are required" });

        const accessToken = req.headers?.authorization?.split(" ")?.[1];
        if (!accessToken) return res.status(401).json({ error: "Unauthorized. Token is missing" });
        const decoded = await verifyAccessToken(accessToken);
        if (!decoded || !decoded.id) return res.status(401).json({ error: "Unauthorized. Invalid token" });

        // Find user
        const user = await userModel.findById(decoded.id).select("+password");
        if (!user) return res.status(404).json({ error: "User not found" });

        // Verify password
        const isVerified = await bcrypt.compare(password, user.password);
        if (!isVerified) return res.status(400).json({ error: "Invalid password" });
        if (password === newPassword) return res.status(400).json({ error: "You can't use your current password" });

        // Hash password and update in user document
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        await user.save();
        res.status(200).json({ message: "Password updated" });

    } catch (error) {
        res.status(500).json({ error: "Error changing password due to server error" });
    }
}

// Forgot password (Send link)
export const sendPasswordResetLink = async (req, res) => {
    try {
        const validation = validateEmail.safeParse(req.body);
        if (!validation.success) {
            return res.status(400).json({ error: "Validation failed", details: validation.error.flatten().fieldErrors });
        }
        const { email } = validation.data;
        if (!email) return res.status(400).json({ error: "Email is required" });

        // Find user to get _id & invalidate old token
        const user = await userModel.findOne({ email });
        if (!user) return res.status(404).json({ error: "No user associated with this email" });
        await tokenModel.deleteOne({ userId: user._id, type: "passwordReset" });

        // Generate & hash verification link & create link
        const passwordResetToken = await jwt.sign({ id: user._id }, process.env.PASSWORD_SECRET, { expiresIn: "15m" });
        const hashedToken = await bcrypt.hash(passwordResetToken, 10);
        const link = `${process.env.FRONTEND_URL}/reset-password?token=${passwordResetToken}`;

        // Create link & send via email
        await Mail({
            email,
            subject: "Password Reset Request",
            html: `<!DOCTYPE html>
                    <html lang="en">
                    <head>
                    <meta charset="UTF-8" />
                    <title>Reset Your Password</title>
                    <style>
                        body { font-family: Arial, sans-serif; color: #333; }
                        .container { max-width: 600px; margin: auto; padding: 20px; }
                        .btn {
                        display: inline-block;
                        padding: 12px 20px;
                        background-color: #4CAF50;
                        color: white;
                        text-decoration: none;
                        border-radius: 4px;
                        }
                        .footer { font-size: 12px; color: #777; margin-top: 30px; }
                    </style>
                    </head>
                    <body>
                    <div class="container">
                        <h2>Password Reset Request</h2>
                        <p>Hello,</p>
                        <p>You recently requested to reset your password for your Expensely account. Click the button below to reset it:</p>
                        <p><a class="btn" href="${link}" target="_blank">Reset Password</a></p>
                        <p>Or, enter the following link in your browser:</p>
                        <p><a href="${link}" target="_blank">${link}</a></p>
                        <p>Your link will be valid for 15 minutes. If you didn't request a password reset, please ignore this email.</p>
                        <p>Do not share this email or link with anyone for your account safety.</p>
                        <div class="footer">
                            <p>Best regards,</p>
                            <p>Expensely</p>
                        </div>
                    </div>
                    </body>
                    </html>`
        });

        // Store token
        await tokenModel.create({ userId: user._id, type: "passwordReset", token: hashedToken });
        res.status(201).json({ message: "Link sent" });

    } catch (error) {
        res.status(500).json({ error: "Error sending mail (password reset link) due to server error" });
    }
}

// Forgot password (Verify link & update)
export const resetPassword = async (req, res) => {
    try {
        const { token, newPassword } = req.body;
        if (!token) return res.status(400).json({ error: "Token is missing." });
        if (!newPassword) return res.status(400).json({ error: "New password is required" });

        // Verify token
        const decoded = await jwt.verify(token, process.env.PASSWORD_SECRET);
        if (!decoded || !decoded.id) return res.status(400).json({ error: "Invalid token or the link has expired." });

        // Find token
        const existingToken = await tokenModel.findOne({ userId: decoded.id, type: "passwordReset" });
        if (!existingToken) return res.status(400).json({ error: "Link has expired." });

        // Compare token
        const isSame = await bcrypt.compare(token, existingToken.token);
        if (!isSame) return res.status(400).json({ error: "Invalid token." });

        // Find user & validate password uniqueness
        const user = await userModel.findById(decoded.id).select("+password");
        if (!user) return res.status(404).json({ error: "User not found" });

        const isPasswordSame = await bcrypt.compare(newPassword, user.password);
        if (isPasswordSame) return res.status(409).json({ error: "You can't use your current password" });

        // Hash the password & update
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;

        await user.save();
        await tokenModel.deleteOne({ userId: decoded.id, type: "passwordReset" });

        res.status(200).json({ message: "Password updated" });

    } catch (error) {
        res.status(500).json({ error: "Error reseting password due to server error" });
    }
}

// Delete account (send OTP)
export const sendAccountDeletionOTP = async (req, res) => {
    try {
        const validation = validateEmail.safeParse(req.body);
        if (!validation.success) {
            return res.status(400).json({ error: "Validation failed", details: validation.error.flatten().fieldErrors });
        }
        const { email } = validation.data;
        if (!email) return res.status(400).json({ error: "Email is required" });

        const accessToken = req.headers?.authorization?.split(" ")?.[1];
        if (!accessToken) return res.status(401).json({ error: "Unauthorized. Token is missing" });
        const decoded = await verifyAccessToken(accessToken);
        if (!decoded || !decoded.id) return res.status(401).json({ error: "Unauthorized. Invalid token." });

        // Invalidate previous token if exists
        await tokenModel.deleteOne({ userId: decoded.id, type: "otp" });

        // Generate 8 digit otp & create hash
        const otp = Math.floor(Math.random(1) * 100000000);
        const hashedOTP = await bcrypt.hash(otp.toString(), 10);

        // Send mail
        await Mail({
            email,
            subject: "Account Deletion Request",
            html: `<!DOCTYPE html>
                    <html lang="en">
                    <head>
                    <meta charset="UTF-8" />
                    <title>Reset Your Password</title>
                    <style>
                        body { font-family: Arial, sans-serif; color: #333; }
                        .container { max-width: 600px; margin: auto; padding: 20px; }
                        .footer { font-size: 12px; color: #777; margin-top: 30px; }
                        .bigFont { font-size: 22px }
                    </style>
                    </head>
                    <body>
                    <div class="container">
                        <h2>Account Deletion Request</h2>
                        <p>Hello,</p>
                        <p>You recently requested to delete your account permanently. By proceeding with this action you will lose all your progress.</p>
                        <p>Your One-Time-Password is: </p>
                        <p class="bigFont">${otp}</p>
                        <p>This will only valid upto 15 minutes.</p>
                        <p>Do not share this email or OTP with anyone for your account safety.</p>
                        <p>If you didn’t request an account deletion, you can safely ignore this email.</p>
                        <div class="footer">
                            <p>We respects your decision and we are sorry to see you go.</p>
                            <p>Best regards,</p>
                            <p>Expensely</p>
                        </div>
                    </div>
                    </body>
                    </html>`
        });

        // Store otp
        await tokenModel.create({ userId: decoded.id, type: "otp", otp: hashedOTP });
        res.status(201).json({ message: "OTP sent" });

    } catch (error) {
        res.status(500).json({ error: "Error generating OTP due to server error" });
    }
}

// Delete account (Verify OTP & Delete account)
export const deleteAccount = async (req, res) => {
    try {
        const { otp } = req.body;
        if (!otp) return res.status(400).json({ error: "OTP is required" });

        // Verify user
        const accessToken = req.headers?.authorization?.split(" ")?.[1];
        if (!accessToken) return res.status(401).json({ error: "Unauthorized. Token is missing." });
        const decoded = await verifyAccessToken(accessToken);
        if (!decoded || !decoded.id) return res.status(401).json({ error: "Unauthorized. Invalid token." });

        // Find otp
        const storedOTP = await tokenModel.findOne({ userId: decoded.id, type: "otp" });
        if (!storedOTP) return res.status(404).json({ error: "OTP has expired." });

        // Compare OTP
        const isValid = await bcrypt.compare(otp, storedOTP.otp);
        if (!isValid) return res.status(400).json({ error: "Invalid or expired OTP" });

        // Find user
        const user = await userModel.findById(decoded.id);
        if (!user) return res.status(404).json({ error: "User not found" });

        // Delete profile image
        if (user.profileImage && user.profileImage !== "/user.png") {
            const profilePublicId = extractPublicId(user.profileImage);
            if (profilePublicId) await cloudinary.uploader.destroy(profilePublicId);
        }

        // Delete receipts from Cloudinary - receiptUrl
        const transactions = await transactionModel.find({ userId: decoded.id });
        const receiptUrls = transactions.map(t => t.receiptUrl).filter(url => url?.includes("cloudinary.com"));
        const publicIds = receiptUrls.map(url => extractPublicId(url)).filter(Boolean);
        const batchSize = 100;

        // Batch processing
        for (let i = 0; i < publicIds.length; i += batchSize) {
            const batch = publicIds.slice(i, i + batchSize);
            try {
                await cloudinary.api.delete_resources(batch);
            } catch (error) {
                console.warn("Batch image deletion failed:", error);
            }
        }

        // Clearing from database
        await transactionModel.deleteMany({ userId: decoded.id });
        await tokenModel.deleteMany({ userId: decoded.id });
        await savingsModel.deleteOne({ userId: decoded.id });
        await userModel.findByIdAndDelete(decoded.id);

        res.status(200).json({ message: "Account and all data deleted successfully." });

    } catch (error) {
        res.status(500).json({ error: "Error deleting account due to server error" });
    }
}

// Update profile image
export const updateProfileImage = async (req, res) => {
    try {
        const { removeProfileImage = false } = req.body;
        const localPath = req.file?.path;
        const accessToken = req.headers?.authorization?.split(" ")?.[1];
        if (!accessToken) return res.status(401).json({ error: "Unauthorized. Token is missing." });

        // Verify token
        const decoded = await verifyAccessToken(accessToken);
        if (!decoded || !decoded.id) return res.status(401).json({ error: "Unauthorized. Invalid token." });

        // Find user
        const user = await userModel.findById(decoded.id);
        if (!user) return res.status(404).json({ error: "No user found" });

        // Remove profile image
        if ((removeProfileImage || removeProfileImage === 'true') && user.profileImage !== "/user.png") {
            const publicId = extractPublicId(user.profileImage);
            await cloudinary.uploader.destroy(publicId);

            user.profileImage = "/user.png";
            await user.save();
            return res.status(200).json({ error: "Profile iamge removed" })
        };

        // Update profile image
        if (localPath) {
            if (user.profileImage && user.profileImage !== "/user.png") {
                const publicId = extractPublicId(user.profileImage);
                await cloudinary.uploader.destroy(publicId);
            }

            // Upload new image
            const result = await cloudinary.uploader.upload(localPath, {
                folder: "profile-images",
                public_id: `user_${user._id}_${Date.now()}`,
                format: "webp",
                transformation: [{
                    width: 400,
                    height: 400,
                    gravity: "face",
                    crop: "fill"
                }]
            });

            // Delete the temporary file
            if (localPath) {
                await fs.unlink(localPath);
            }

            user.profileImage = result.secure_url;
            await user.save();
            return res.status(200).json({ message: "Profile image updated", profileImage: user.profileImage });
        }

        res.status(400).json({ error: "No image provided or remove flag set incorrectly." });

    } catch (error) {
        res.status(500).json({ error: "Error updating profile image due to server error" })
    }
}

// Update profile info
export const updateProfile = async (req, res) => {
    try {
        // Validating data
        const validatedInfo = validateProfileInfo.safeParse(req.body);
        if (!validatedInfo.success) {
            return res.status(400).json({ error: "Invalid profile info structure", details: validatedInfo.error.flatten() });
        }

        // Extracting data
        const { name, income = 0, goal = 0 } = validatedInfo.data;
        const accessToken = req.headers?.authorization?.split(" ")?.[1];
        if (!accessToken) return res.status(401).json({ error: "Unauthorized. Token is missing." });
        const decoded = await verifyAccessToken(accessToken);
        if (!decoded || !decoded.id) return res.status(401).json({ error: "Unauthorized. Invalid token." });

        // Find user & update
        const userId = mongoose.Types.ObjectId.createFromHexString(decoded.id);
        const updated = await userModel.findOneAndUpdate(
            { _id: userId },
            { $set: { name, income, goal } },
            { new: true }
        );
        res.status(200).json({ message: "Profile updated", updated });

    } catch (error) {
        res.status(500).json({ error: "Error updating profile info due to server error" });
    }
}

// Get data
export const getData = async (req, res) => {
    try {
        const accessToken = req.headers?.authorization?.split(" ")?.[1];
        if (!accessToken) return res.status(401).json({ error: "Unauthorized. Token is missing." });
        const decoded = await verifyAccessToken(accessToken);
        if (!decoded || !decoded.id) return res.status(401).json({ error: "Invalid or expired token" });
        const userId = mongoose.Types.ObjectId.createFromHexString(decoded.id);

        // Find the user data
        const user = await userModel.aggregate([
            { $match: { _id: userId } },
            {
                $lookup: {
                    from: "transactions",
                    let: { userId: "$_id" },
                    pipeline: [
                        { $match: { $expr: { $eq: ["$userId", "$$userId"] } } },
                        { $sort: { date: -1 } },
                        { $limit: 12 }
                    ],
                    as: "transactions"
                }
            },
            {
                $lookup: {
                    from: "savings",
                    localField: "_id",
                    foreignField: "userId",
                    as: "savings"
                }
            }
        ]);

        const totalTransaction = await transactionModel.countDocuments();

        if (!user || user.length === 0) return res.status(404).json({ error: "User not found" });
        res.status(200).json({ message: "Data fetched", user: { ...user[0], totalTransaction } });

    } catch (error) {
        res.status(500).json({ error: "Error getting data due to server error" });
    }
}

// Get filtered transaction
export const getFilteredTransactions = async (req, res) => {
    try {
        const accessToken = req.headers?.authorization?.split(" ")?.[1];
        if (!accessToken) return res.status(401).json({ error: "Unauthorized. Token is missing." });
        const decoded = await verifyAccessToken(accessToken);
        if (!decoded || !decoded.id) return res.status(401).json({ error: "Invalid or expired token" });

        const userId = mongoose.Types.ObjectId.createFromHexString(decoded.id);
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 12;
        const skip = (page - 1) * limit;

        // Extract queries
        const { search = "", filter = "all", accounts = "" } = req.query;
        const accountsArray = accounts ? accounts.split(",") : [];

        const query = { userId };

        // Filter: this month
        if (filter === "month") {
            const startOfMonth = new Date();
            startOfMonth.setDate(1);
            startOfMonth.setHours(0, 0, 0, 0);
            query.date = { $gte: startOfMonth };
        }

        // Account filter
        if (accountsArray.length > 0) {
            query.account = { $in: accountsArray };
        }

        // Search by category, description, or account
        if (search) {
            query.$or = [
                { category: new RegExp(search, "i") },
                { description: new RegExp(search, "i") },
                { account: new RegExp(search, "i") }
            ];
        }

        const total = await transactionModel.countDocuments(query);
        const transactions = await transactionModel.find(query).sort({ date: -1 }).skip(skip).limit(limit);

        res.status(200).json({ transactions, total, page, pages: Math.ceil(total / limit) });

    } catch (error) {
        res.status(500).json({ error: "Internal server error" });
    }
};









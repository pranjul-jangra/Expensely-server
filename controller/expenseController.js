import savingsModel from "../models/savingsSchema.js";
import userModel from "../models/userSchema.js";
import transactionModel from "../models/transactionsSchema.js";
import { verifyAccessToken } from "../utils/tokenUtils.js";
import fs from "fs/promises";
import { validateSavings, validateTransactions } from "../utils/zodValidation.js";
import cloudinary from "../middlewares/uploadImage.js";
import { extractPublicId } from "../utils/extractPublicId.js";
import mongoose from "mongoose";
import crypto from "crypto";


// Update savings
export const updateSavings = async (req, res) => {
    try {
        // Validating data type
        const validatedSavings = validateSavings.safeParse(req.body);
        if (!validatedSavings.success) {
            return res.status(400).json({ error: "Invalid savings structure", details: validatedSavings.error.flatten() });
        }

        // Extracting data
        const { savings } = validatedSavings.data;
        if (!savings) return res.status(400).json({ error: "Savings are required" });
        const accessToken = req.headers?.authorization?.split(" ")?.[1];
        if (!accessToken) return res.status(401).json({ error: "Unauthorized. Token is missing." });

        // Verify token
        const decoded = await verifyAccessToken(accessToken);
        if (!decoded || !decoded.id) return res.status(401).json({ error: "Unauthorized. Invalid token." });

        // Upsert document
        await savingsModel.findOneAndUpdate(
            { userId: mongoose.Types.ObjectId.createFromHexString(decoded.id) },
            { $set: { savings } },
            { upsert: true }
        );
        return res.status(200).json({ message: "Savings updated" });

    } catch (error) {
        res.status(500).json({ error: "Error updating savings due to server error" });
    }
}

// Utility function to update user's synced total expense
const updateUserSyncedExpense = async (userId) => {
    const totalSynced = await transactionModel.aggregate([
        { $match: { userId: mongoose.Types.ObjectId.createFromHexString(userId), type: "expense", syncExpense: true } },
        { $group: { _id: null, total: { $sum: "$amount" } } }
    ]);

    const total = totalSynced?.[0]?.total || 0;
    await userModel.findByIdAndUpdate(mongoose.Types.ObjectId.createFromHexString(userId), { expense: total });
};

// Upsert transaction
export const upsertTransactions = async (req, res) => {
    try {
        const { transactionId } = req.body;
        const accessToken = req.headers?.authorization?.split(" ")?.[1];
        if (!accessToken) return res.status(401).json({ error: "Unauthorized. Token is missing" });

        const decoded = await verifyAccessToken(accessToken);
        if (!decoded || !decoded.id) return res.status(401).json({ error: "Unauthorized. Invalid token" });

        // Validate data
        if (req.body.date) {
            const parsedDate = new Date(req.body.date);
            if (!isNaN(parsedDate)) req.body.date = parsedDate;
        }

        const validation = validateTransactions.safeParse(req.body);
        if (!validation.success) {
            return res.status(400).json({ error: "Invalid data", details: validation.error.flatten() });
        }

        // Extracting data
        const { type, category, account, amount = 0, date = Date.now(), description = "", syncExpense = "false" } = validation.data;
        const shouldSync = (type === "expense") && (syncExpense === "true");
        const removeReceipt = req.body?.removeReceipt === "true";
        const localPath = req.file?.path;

        // Upload image
        let uploadedImage;
        if (localPath && !removeReceipt) {
            uploadedImage = await cloudinary.uploader.upload(localPath, {
                folder: 'expensely-receipts',
                public_id: `transaction_${decoded.id}_${Date.now()}`,
                format: "webp",
                transformation: [{
                    width: 400,
                    height: 400,
                    gravity: "face",
                    crop: "fill"
                }]
            });
        }

        // Delete temporary files
        await fs.unlink(localPath);

        // Update existing transaction
        if (transactionId) {
            const existingDoc = await transactionModel.findOne({ userId: mongoose.Types.ObjectId.createFromHexString(decoded.id), transactionId });
            if (!existingDoc) return res.status(404).json({ error: "Transaction not found" });

            if (removeReceipt || (uploadedImage?.secure_url && existingDoc.receiptUrl)) {
                const publicId = extractPublicId(existingDoc.receiptUrl);
                await cloudinary.uploader.destroy(publicId);
            }

            existingDoc.type = type;
            existingDoc.category = category;
            existingDoc.account = account;
            existingDoc.amount = amount;
            existingDoc.description = description || null;
            existingDoc.syncExpense = shouldSync;
            existingDoc.receiptUrl = removeReceipt ? null : (uploadedImage?.secure_url || existingDoc.receiptUrl);
            existingDoc.date = date || existingDoc.date;

            await existingDoc.save();
            if (shouldSync) await updateUserSyncedExpense(decoded.id);
            return res.status(200).json({ message: "Transaction updated" });
        }

        // Create new transaction
        const newTransactionId = crypto.randomBytes(16).toString("hex").slice(0, 8);

        await transactionModel.create({
            userId: decoded.id,
            transactionId: newTransactionId,
            type,
            category,
            account,
            amount,
            description: description || null,
            syncExpense: shouldSync,
            receiptUrl: uploadedImage?.secure_url || null,
            date: date || Date.now(),
        });

        if (shouldSync) await updateUserSyncedExpense(decoded.id);
        res.status(201).json({ message: "Transaction added" });

    } catch (error) {
        res.status(500).json({ error: "Server error while processing transaction" });
    }
};

// Delete transaction
export const deleteTransaction = async (req, res) => {
    try {
        const { id } = req.params;
        if (!id) return res.status(400).json({ error: "Transaction ID is missing" });

        const accessToken = req.headers?.authorization?.split(" ")?.[1];
        if (!accessToken) return res.status(401).json({ error: "Unauthorized. Token is missing" });
        const decoded = await verifyAccessToken(accessToken);
        if (!decoded || !decoded.id) return res.status(401).json({ error: "Unauthorized. Invalid token" });

        const userId = mongoose.Types.ObjectId.createFromHexString(decoded.id);

        // Find transaction & delete receipt from cloudinary
        const transaction = await transactionModel.findOne({ userId, transactionId: id });
        if (!transaction) return res.status(404).json({ error: "Transaction not found" });

        // Delete receipt from cloudinary
        if (transaction.receiptUrl?.includes("cloudinary")) {
            const publicId = extractPublicId(transaction.receiptUrl);
            await cloudinary.uploader.destroy(publicId);
        }

        // Delete transaction
        await transactionModel.deleteOne({ userId, transactionId: id });

        // Decreament the user's expense if the synced expense is deleted
        if (transaction.type === "expense" && transaction.syncExpense === true) {
            await userModel.updateOne(
                { _id: userId },
                { $inc: { expense: -Math.abs(transaction.amount) } }
            );
        }

        res.status(200).json({ message: "Transaction deleted" });

    } catch (error) {
        res.status(500).json({ error: "Error deleting transaction due to server error" });
    }
}

// Get the total expense for each month (from transaction model)
export const getTotalExpenses = async (req, res) => {
    try {
        // Authorize user
        const accessToken = req.headers?.authorization?.split(" ")?.[1];
        if (!accessToken) return res.status(401).json({ error: "Unauthorized. Token is missing" });
        const decoded = await verifyAccessToken(accessToken);
        if (!decoded || !decoded.id) return res.status(401).json({ error: "Unauthorized. Invalid token" });

        // Extract year
        const { year = new Date().getFullYear() } = req.body;

        const result = await transactionModel.aggregate([
            {
                $match: {
                    userId: mongoose.Types.ObjectId.createFromHexString(decoded.id),
                    type: "expense",
                    date: {
                        $gte: new Date(`${year}-01-01`),
                        $lte: new Date(`${year}-12-31T23:59:59`)
                    }
                }
            },
            {
                $group: {
                    _id: { $month: "$date" },  // extract month with "$month" operator using date field
                    total: { $sum: "$amount" }
                }
            }
        ]);

        res.status(200).json({
            expenses: result.map(item => ({
                month: item._id,  // 1 (Jan) to 12 (Dec)
                total: item.total
            }))
        });

    } catch (error) {
        res.status(500).json({ error: "Error getting expenses due to server error" });
    }
}

// Get top 5 expenses by category
export const getTopExpenseCategories = async (req, res) => {
    try {
        const accessToken = req.headers?.authorization?.split(" ")?.[1];
        if (!accessToken) return res.status(401).json({ error: "Unauthorized. Token is missing" });
        const decoded = await verifyAccessToken(accessToken);
        if (!decoded?.id) return res.status(401).json({ error: "Unauthorized. Invalid token" });

        // Get current month's date range
        const now = new Date();
        const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
        const endOfMonth = new Date(now.getFullYear(), now.getMonth() + 1, 0, 23, 59, 59, 999);

        // Get expenses
        const result = await transactionModel.aggregate([
            {
                $match: {
                    userId: mongoose.Types.ObjectId.createFromHexString(decoded.id),
                    type: "expense",
                    createdAt: {
                        $gte: startOfMonth,
                        $lte: endOfMonth
                    }
                }
            },
            {
                $group: {
                    _id: "$category",
                    totalAmount: { $sum: "$amount" }
                }
            },
            {
                $sort: { totalAmount: -1 }
            },
            {
                $limit: 5
            }
        ]);

        // Format response
        const data = result.map(item => ({
            category: item._id,
            amount: item.totalAmount
        }));

        res.status(200).json({ categories: data });

    } catch (error) {
        res.status(500).json({ error: "Server error while fetching top categories" });
    }
};

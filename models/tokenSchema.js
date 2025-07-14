import mongoose from "mongoose";

const tokenSchema = new mongoose.Schema({
    type: { type: String, required: true, trim: true, enum: ["emailUpdation", "passwordReset", "otp"] },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    token: { type: String, trim: true },
    otp: { type: String, trim: true },
    createdAt: { type: Date, default: Date.now, expires: 60 * 15 },
});


const tokenModel = mongoose.model("Tokens", tokenSchema);
export default tokenModel;

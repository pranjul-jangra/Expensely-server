import mongoose from "mongoose";


const transactionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    transactionId: { type: String, required: true, trim: true, unique: true },
    type: { type: String, enum: ["income", "expense"], required: true },
    category: { type: String, trim: true, required: true },
    account: { type: String, trim: true, required: true },
    amount: { type: Number, default: 0, trim: true },
    description: { type: String, trim: true },
    receiptUrl: { type: String, trim: true },
    syncExpense: { type: Boolean, default: false },
    date: { type: Date, trim: true, required: true },
},
    {
        timestamps: true
    }
)


transactionSchema.index({ userId: 1, date: -1 });

const transactionModel = mongoose.model("Transaction", transactionSchema);
export default transactionModel;


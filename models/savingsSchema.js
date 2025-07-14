import mongoose from "mongoose";

const savingItemSchema = new mongoose.Schema({
    method: { type: String, required: true },
    label: { type: String, required: true },
    amount: { type: Number, default: null }
}, { _id: false });


const savingsSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },

    savings: {
        type: Map,
        of: [savingItemSchema]
    }

}, {
    timestamps: true
})


savingsSchema.index({ userId: 1 });

const savingsModel = mongoose.model("Savings", savingsSchema);
export default savingsModel;
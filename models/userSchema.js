import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, trim: true },
    password: { type: String, required: true, select: false, trim: true },
    profileImage: { type: String, trim: true, default: "/user.png" },
    sessions: { type: [String], select: false },
    income: { type: Number },
    expense: { type: Number, default: 0 },
    goal: { type: Number },
}, {
    timestamps: true
})


const userModel = mongoose.model('User', userSchema);
export default userModel;

import userModel from "../models/userSchema.js";

// Keep the server and atlas instance alive 
export const keepAlive = async (req, res) => {
  try {
    const isExists = await userModel.findOne({ email: "dummy@gmail.com" });
    res.status(200).json({ success: true, message: "Service is alive" });
  } catch (err) {
    res.status(500).json({ success: false, message: "Error in keep-alive endpoint" });
  }
};

import { v2 as cloudinary } from 'cloudinary';
import path from 'path';
import multer from 'multer';
import dotenv from "dotenv";
dotenv.config();

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Temporary local storage
const storage = multer.diskStorage({
    destination: "uploads/", // relative path
    filename: (req, file, cb) => {
        cb(null, "Local-image" + path.extname(file.originalname));  // locally stored file name
    }
});

const upload = multer({
    storage,
    limits: { fileSize: 10 * 1024 * 1024, files: 1 },
});

export default cloudinary;
export { upload };

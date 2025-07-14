import express from 'express';
import { 
    changePassword, deleteAccount, 
    getData, getFilteredTransactions, 
    login, logout, logoutAll, refreshToken, registerUser, 
    resetPassword, sendAccountDeletionOTP, sendEmailUpdationLink, 
    sendPasswordResetLink, updateEmail, updateProfile, updateProfileImage 
} from '../controller/userController.js';
import { upload } from '../middlewares/uploadImage.js';


const userRouter = express.Router();

// Session routes
userRouter.post('/register', registerUser);
userRouter.post('/login', login);
userRouter.post('/logout', logout);
userRouter.post('/logout-all', logoutAll);

// Refresh token
userRouter.get('/refresh', refreshToken);

// Get data
userRouter.get('/data', getData);
userRouter.get('/filtered-tnx', getFilteredTransactions);

// Update profile
userRouter.post('/update-profile-image', upload.single("image"), updateProfileImage);
userRouter.patch('/update-profile', updateProfile);

// Email updation
userRouter.post('/send-email-updation-link', sendEmailUpdationLink);
userRouter.post('/update-email', updateEmail);

// Change password
userRouter.post('/change-password', changePassword);

// Reset password
userRouter.post('/send-password-reset-link', sendPasswordResetLink);
userRouter.post('/reset-password', resetPassword);

// Send account deletion OTP
userRouter.post('/send-account-deletion-otp', sendAccountDeletionOTP);
userRouter.post('/delete-account', deleteAccount);



export default userRouter;
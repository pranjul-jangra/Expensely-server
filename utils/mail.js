import nodemailer from "nodemailer";
import dotenv from "dotenv";
dotenv.config();

const authEmail = process.env.EMAIL_USER;
const password = process.env.EMAIL_PASS;

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: authEmail,
        pass: password,
    },
});

export const Mail = async ({ email, subject, html }) => {
    try {
        const mailOptions = {
            from: `"Expensely" <${authEmail}>`,
            to: email,
            subject,
            html,
        };

        const sentMail = await transporter.sendMail(mailOptions);
        return sentMail;

    } catch (error) {
        console.log("Error sending mail:", error);
        return error;
    }
}

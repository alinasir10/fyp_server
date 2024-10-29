import { createTransporter } from '../lib/nodemailer'

export const sendEmailVerification = async (to: string, subject: string, html: string) => {
    try {
        const transporter = createTransporter();

        const mailOptions = {
            from: process.env.GMAIL_EMAIL,
            to: to,
            subject,
            html,
        }

        const info = await transporter.sendMail(mailOptions);

        console.log('Email sent: %s', info.messageId);
        return {
            success: true,
            messageId: info.messageId,
        };
    } catch (error: any) {
        console.error('Error sending email: ', error);
        return {
            success: false,
            error: error.message,
        };
    }
};

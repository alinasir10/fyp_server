import { Request, Response } from 'express';
import { lucia } from '../lib/auth/lucia';
import { db } from '../lib/db';
import {emailVerificationTable, users} from '../lib/db/schema';
import {and, eq, isNull} from 'drizzle-orm';
import { generateRandomString, alphabet } from 'oslo/crypto'
import { Argon2id } from 'oslo/password';
import {generateId, TimeSpan} from 'lucia';
import {sendEmailVerification} from "../utils/sendEmail";
import {createDate, isWithinExpirationDate} from "oslo";
import type { User } from "lucia";
import { redis } from "../lib/redis";
import {generateCodeVerifier, generateState} from "arctic";
import {google} from "../lib/auth/google";
import axios from 'axios';

const RATE_LIMIT = 3;
const RATE_LIMIT_WINDOW = 15 * 60;

const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';
const API_URL = process.env.API_URL || 'http://localhost:5000';

export class RateLimitError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'RateLimitError';
    }
}

async function isRateLimited(userId: string, type: "verification" | "passwordReset"): Promise<boolean> {
    const key = `rateLimit:${type}:${userId}`;
    const current = await redis.incr(key);

    if (current === 1) {
        await redis.expire(key, RATE_LIMIT_WINDOW);
    }

    return current > RATE_LIMIT;
}

async function generateEmailVerificationCode(userId: string): Promise<string> {
    await db.delete(emailVerificationTable).where(eq(emailVerificationTable.userId, userId)).execute();
    return generateRandomString(6, alphabet("0-9", "a-z"));
}

async function sendVerificationEmail(userId: string, email: string, type: "verification" | "passwordReset"): Promise<void> {
    if (await isRateLimited(userId, type)) {
        throw new RateLimitError("Rate limit exceeded. Please try again later.");
    }

    let code = '';
    let emailContent = '';
    let emailSubject = '';

    switch (type) {
        case "verification":
            // Generate email verification code
            code = await generateEmailVerificationCode(userId);
            emailSubject = 'Email Verification';
            emailContent = `Your email verification code is: <strong>${code}</strong>`;

            // Insert verification code into the database
            await db.insert(emailVerificationTable).values({
                code,
                userId,
                email,
                id: generateId(15),
                expiresAt: createDate(new TimeSpan(15, "m"))
            });
            break;

        case "passwordReset":
            // Generate password reset token
            code = generateRandomString(32, alphabet("0-9", "a-z"));

            // Store reset token in Redis with expiration
            await redis.set(`passwordReset:${code}`, userId, 'EX', 15 * 60);

            const resetLink = `${FRONTEND_URL}/reset-password?token=${code}`;
            emailSubject = 'Reset Your Password';
            emailContent = `Click the link to reset your password: <a href="${resetLink}">Reset Password</a>`;
            break;

        default:
            throw new Error("Invalid email type");
    }

    await sendEmailVerification(email, emailSubject, emailContent);
}

export const logout = async (req: Request, res: Response) => {
    try {
        const session = res.locals.session?.id;

        if (!session) {
            return res.status(401).json({ status: false, message: "Unauthorized" });
        }

        await lucia.invalidateSession(session);

        const blankSessionCookie = lucia.createBlankSessionCookie();

        res.cookie(blankSessionCookie.name, blankSessionCookie.value, blankSessionCookie.attributes);

        return res.status(200).json({ status: true, message: "Logout successful" });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ status: false, message: "An error occurred during logout" });
    }
};

export const fetchUserDetails = async (req: Request, res: Response) => {
    try {
        let user = res.locals?.user;
        if (!user) return res.status(401).json({ error: 'Unauthorized' });
        return res.status(200).json({ user });
    } catch (error: any) {
        console.error(error);
        return res.status(500).json({ error: 'Internal server error' });
    }
}

export const forgotPassword = async (req: Request, res: Response) => {
    const { email } = req.body;

    try {
        const user = await db.query.users.findFirst({
            where: (table) => and(eq(table.email, email), isNull(table.oauthProvider))
        });

        if (!user) {
            return res.status(400).json({ error: "No account found with this email" });
        }

        await sendVerificationEmail(user.id, email, "passwordReset");

        return res.status(200).json({ status: "Password reset email sent" });
    } catch (error) {
        if (error instanceof RateLimitError) {
            return res.status(429).json({ error: error.message });
        }
        console.error(error);
        return res.status(500).json({ error: "An error occurred" });
    }
};

export const verifyResetToken = async (req: Request, res: Response) => {
    const { resetToken } = req.query;

    try {
        const userId = await redis.get(`passwordReset:${resetToken}`);

        if (!userId) {
            return res.status(400).json({ error: "Invalid or expired reset token" });
        }

        const user = await db.query.users.findFirst({
            where: (table) => and(eq(table.id, userId), isNull(table.oauthProvider))
        });

        if (!user) {
            return res.status(400).json({ error: "Invalid reset token" });
        }

        return res.status(200).json({ status: true, message: "Reset token is valid", userId });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ error: "An error occurred while verifying reset token" });
    }
};

export const resetPassword = async (req: Request, res: Response) => {
    const { resetToken, newPassword } = req.body;

    try {
        const userId = await redis.get(`passwordReset:${resetToken}`);

        if (!userId) {
            return res.status(400).json({ error: "Invalid or expired reset token" });
        }

        const user = await db.query.users.findFirst({
            where: (table) => and(eq(table.id, userId), isNull(table.oauthProvider))
        });

        if (!user) {
            return res.status(400).json({ error: "Invalid reset token" });
        }

        const hashedPassword = await new Argon2id().hash(newPassword);

        await db.update(users)
            .set({ password: hashedPassword })
            .where(eq(users.id, userId))
            .execute();

        await redis.del(`passwordReset:${resetToken}`);

        return res.status(200).json({ status: "Password reset successfully" });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ error: "An error occurred during password reset" });
    }
};

export const register = async (req: Request, res: Response) => {
    const { email, username, password, profileUrl } = req.body;

    try {
        const existingUser = await db.query.users.findFirst({
            where: (table) => eq(table.email, email),
        });

        if (existingUser) {
            return res.status(400).json({
                status: false,
                message: "Email already in use.",
            });
        }

        const hashedPassword = await new Argon2id().hash(password);
        const userId = generateId(15);

        const user = await db.insert(users).values({
            id: userId,
            email,
            username,
            password: hashedPassword,
            profileUrl,
            isVerified: false,
            oauthProvider: null,
        }).returning({
            id: users.id,
            username: users.username,
        });

        if (!user) {
            return res.status(400).json({
                status: false,
                message: "Failed to create account. Please try again.",
            });
        }

        console.log('created user', user);

        await sendVerificationEmail(userId, email, "verification");

        const session = await lucia.createSession(userId, {});
        const sessionCookie = lucia.createSessionCookie(session.id);

        res.cookie(sessionCookie.name, sessionCookie.value, sessionCookie.attributes);

        return res.status(201).json({
            status: true,
            message: "Account created successfully.",
            redirect: "verify",
        });
    } catch (error) {
        if (error instanceof RateLimitError) {
            return res.status(429).json({
                status: false,
                message: error.message,
            });
        }

        console.error("Registration Error:", error);
        return res.status(500).json({
            status: false,
            message: "An unexpected error occurred. Please try again later.",
        });
    }
};

export const login = async (req: Request, res: Response) => {
    const { email, password } = req.body;

    try {
        const isExists = await db.query.users.findFirst({
            where: (table) => eq(table.email, email)
        })

        if (!isExists) {
            return res.status(400).json({ error: 'Invalid email or password' });
        }

        if (isExists.oauthProvider === 'google') {
            return res.status(400).json({ error: 'This email is associated with a Google login. Please use \'Continue with Google\' to log in.' });
        }

        if (!isExists.password) {
            return res.status(400).json({ error: 'Invalid email or password' });
        }

        const isPasswordValid = await new Argon2id().verify(isExists.password, password);

        if (!isPasswordValid) {
            return res.status(400).json({ error: 'Invalid email or password' });
        }

        if (!isExists.isVerified) {
            let userId = isExists.id;

            await sendVerificationEmail(userId, email, 'verification');

            const session = await lucia.createSession(userId, {})
            const sessionCookie = lucia.createSessionCookie(session.id)

            return res.status(400)
                .cookie(sessionCookie.name, sessionCookie.value, sessionCookie.attributes)
                .json({status: false, message: 'Account not Verified', redirect: 'verify'})
        }

        const session = await lucia.createSession(isExists.id, {})
        const sessionCookie = lucia.createSessionCookie(session.id)

        return res.status(200)
            .cookie(sessionCookie.name, sessionCookie.value, sessionCookie.attributes)
            .json({ status: true, message: 'Login Successful' });

    } catch (error) {
        if (error instanceof RateLimitError) {
            return res.status(429).json({ error: error.message });
        }

        console.error(error);
        return res.status(400).json({ error: 'Invalid email or password' });
    }
};

async function verifyVerificationCode(user: User, code: string): Promise<boolean> {
    try {
        const transaction = await db.transaction(async (tx) => {
            const dbCode = await tx
                .select()
                .from(emailVerificationTable)
                .where(eq(emailVerificationTable.userId, user.id))
                .limit(1)
                .execute();

            if (!dbCode.length || dbCode[0].code !== code) {
                return false;
            }

            const userData = await tx
                .select()
                .from(users)
                .where(eq(users.id, user.id))
                .limit(1)
                .execute();

            const userEmail = userData.length ? userData[0].email : null;

            if (!isWithinExpirationDate(dbCode[0].expiresAt)) {
                return false;
            }

            if (dbCode[0].email !== userEmail) {
                return false;
            }

            await tx.delete(emailVerificationTable)
                .where(eq(emailVerificationTable.id, dbCode[0].id))
                .execute();

            return true;
        });

        return transaction;
    } catch (error) {
        console.error("Error verifying code:", error);
        return false;
    }
}

export const verifyEmail = async (req: Request, res: Response) => {
    const session = res.locals.session?.id;
    const user = res.locals.user;
    const { code } = req.body;

    if (!session || !user) {
        return res.status(401).json({ error: "Unauthorized" });
    }

    if (typeof code !== "string") {
        return res.status(400).json({ error: "Invalid code format" });
    }

    try {

        const validCode = await verifyVerificationCode(user, code);
        if (!validCode) {
            return res.status(400).json({ error: "Invalid or expired verification code" });
        }

        await lucia.invalidateUserSessions(user.id);
        await db.update(users).set({ isVerified: true }).where(eq(users.id, user.id)).execute();

        const session = await lucia.createSession(user.id, {});
        const sessionCookie = lucia.createSessionCookie(session.id);

        res.cookie(sessionCookie.name, sessionCookie.value, sessionCookie.attributes);
        return res.status(200).json({ status: true, message: 'Email verified successfully', redirect: '/' });
    } catch (error) {
        console.error("Error verifying email:", error);
        return res.status(500).json({ error: "An internal error occurred" });
    }
};

export const resendOTP = async (req: Request, res: Response) => {
    const session = res.locals.session?.id;
    const user = res.locals.user;

    if (!session || !user) {
        return res.status(401).json({ error: "Unauthorized" });
    }

    try {
        const userData = await db.query.users.findFirst({
            where: (table) => eq(table.id, user.id)
        });

        if (!userData || userData.isVerified) {
            return res.status(400).json({ error: "User is already verified or doesn't exist" });
        }

        await sendVerificationEmail(user.id, userData.email, 'verification');

        return res.status(200).json({ status: true, message: 'Verification code resent successfully' });
    } catch (error) {
        if (error instanceof RateLimitError) {
            return res.status(429).json({ error: error.message });
        }
        console.error("Error resending OTP:", error);
        return res.status(500).json({ error: "An internal error occurred" });
    }
};

export const loginGoogle = async (req: Request, res: Response) => {
    const state = generateState();
    const codeVerifier = generateCodeVerifier();
    const url = await google.createAuthorizationURL(state, codeVerifier, {
        scopes: ["profile", "email"]
    });

    // console.log('google url', url)
    // console.log('state', state)
    // console.log('code verifier', codeVerifier)

    const cookieOptions = {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        maxAge: 60 * 10 * 1000,
        sameSite: "lax" as const,
        domain: "localhost",
        path: "/"
    };

    res.cookie("google_oauth_state", state, cookieOptions);
    res.cookie("google_oauth_code_verifier", codeVerifier, cookieOptions);

    // return res.redirect(new URL(url).toString());
    return res.json({ url: new URL(url).toString() });
};

export const handleCallbackGoogle = async (req: Request, res: Response) => {
    const code = Array.isArray(req.query.code) ? req.query.code[0] : req.query.code;
    const state = Array.isArray(req.query.state) ? req.query.state[0] : req.query.state;
    const cookieState = req.query.cookieState?.toString() ?? null;
    const cookieVerifier = req.query.cookieVerifier?.toString() ?? null;
    const storedState = cookieState ?? null;
    const storedCodeVerifier = cookieVerifier ?? null;

    // const code = req.query.code?.toString() ?? null;
    // const state = req.query.state?.toString() ?? null;
    // const storedState = req.cookies.google_oauth_state ?? null;
    // const storedCodeVerifier = req.cookies.google_oauth_code_verifier ?? null;

    // console.log('fetched code', code)
    // console.log('fetched state', state)
    // console.log('fetched cookie state', storedState)
    // console.log('fetched cookie code verifier', storedCodeVerifier)

    if (!code || !state || !storedState || !storedCodeVerifier || state !== storedState) {
        return res.status(400).json({ error: "Invalid OAuth callback" });
    }

    try {
        const tokens = await google.validateAuthorizationCode(code as string, storedCodeVerifier);

        // console.log('google tokens', tokens)

        const response = await axios.get("https://www.googleapis.com/oauth2/v3/userinfo", {
            headers: {
                Authorization: `Bearer ${tokens.accessToken}`
            }
        })

        if (response.status !== 200) {
            return res.status(400).json({ error: "Invalid OAuth response" });
        }
        const googleUser = await response.data

        // console.log('google user', googleUser)

        const existingUser = await db.query.users.findFirst({
            where: (table) => eq(table.email, googleUser.email)
        });

        if (existingUser) {
            if (existingUser.oauthProvider !== 'google') {
                return res.status(400).json({ error: "Email already in use with a different login method" });
            }

            const session = await lucia.createSession(existingUser.id, {});
            const sessionCookie = lucia.createSessionCookie(session.id);
            res.cookie(sessionCookie.name, sessionCookie.value, sessionCookie.attributes);

            res.clearCookie("google_oauth_state", {
                domain: "localhost",
                path: "/"
            });
            res.clearCookie("google_oauth_code_verifier", {
                domain: "localhost",
                path: "/"
            });
            // return res.redirect(`${FRONTEND_URL}/`);

            return res.json({ sessionToken: sessionCookie.value });
        }

        const userId = generateId(15);
        await db.insert(users).values({
            id: userId,
            email: googleUser.email,
            username: googleUser.name ?? googleUser.email.split("@")[0],
            profileUrl: googleUser.picture ?? null,
            isVerified: true,
            oauthProvider: 'google',
            password: null
        });

        const session = await lucia.createSession(userId, {});
        const sessionCookie = lucia.createSessionCookie(session.id);

        res.cookie(sessionCookie.name, sessionCookie.value, sessionCookie.attributes);

        res.clearCookie("google_oauth_state", {
            domain: "localhost",
            path: "/"
        });
        res.clearCookie("google_oauth_code_verifier", {
            domain: "localhost",
            path: "/"
        });
        return res.json({ sessionToken: sessionCookie.value });
        // return res.redirect(`${FRONTEND_URL}/`);
    } catch (e) {
        console.error(e);
        return res.status(500).json({ error: "An error occurred during OAuth" });
    }
}
// export const validateEmail = async (req: Request, res: Response) => {
//     const { email } = req.body;
//     if (!email) {
//         return res.status(400).json({ error: 'Email is required' });
//     }
//     const isUnique = await db.select().from(users).where(eq(users.email, email)).execute();
//     res.json({ isExists: isUnique.length === 0 });
// }


// export const checkUsernameUniqueness = async (req: Request, res: Response) => {
//     const { username } = req.body;
//     const existingUser = await db.select().from(users).where(eq(users.username, username)).execute();
//     if (existingUser.length === 0) {
//         res.json({ isUnique: true });
//     } else {
//         const suggestions = await generateUsername(req.body.firstName, req.body.lastName);
//         res.json({ isUnique: false, suggestions });
//     }
// };

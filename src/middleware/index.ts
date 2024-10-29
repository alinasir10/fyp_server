import { lucia } from "../lib/auth/lucia";
import { verifyRequestOrigin } from "lucia";
import type { User, Session } from "lucia";
import type { Request, Response, NextFunction } from "express";

// Middleware to verify request origin (protection against CSRF)
export const checkOriginMiddleware = (req: Request, res: Response, next: NextFunction) => {
    if (req.method === "GET") {
        return next();
    }

    const originHeader = req.headers.origin ?? null;
    const hostHeader = req.headers.host ?? null;

    if (!originHeader || !hostHeader || !verifyRequestOrigin(originHeader, [hostHeader])) {
        return res.status(403).end();
    }

    return next();
};

// Middleware to validate session and attach user and session to res.locals
export const validateSessionMiddleware = async (req: Request, res: Response, next: NextFunction) => {
    const sessionId = lucia.readSessionCookie(req.headers.cookie ?? "");
    if (!sessionId) {
        res.locals.user = null;
        res.locals.session = null;
        return next();
    }

    try {
        const { session, user } = await lucia.validateSession(sessionId);

        // If session is fresh, update session cookie
        if (session && session.fresh) {
            res.append('Set-Cookie', lucia.createSessionCookie(session.id).serialize());
        }

        // If session is not valid, create a blank session cookie
        if (!session) {
            res.append('Set-Cookie', lucia.createBlankSessionCookie().serialize());
        }

        res.locals.user = user;
        res.locals.session = session;
        next();
    } catch (error) {
        console.error("Session validation error:", error);
        res.locals.user = null;
        res.locals.session = null;
        return res.status(401).json({ error: 'Invalid session' });
    }
};

// Declare the types for res.locals (for TypeScript)
declare global {
    namespace Express {
        interface Locals {
            user: User | null;
            session: Session | null;
        }
    }
}

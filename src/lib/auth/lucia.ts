import { Lucia } from 'lucia';
import { adapter } from './adapter';

export const lucia = new Lucia(adapter, {
    sessionCookie: {
        attributes: {
            secure: process.env.NODE_ENV === "production",
            domain: 'localhost',
            path: '/',
            sameSite: "lax"
        }
    },
    getUserAttributes: (attributes) => {
        return {
            username: attributes.username,
            email: attributes.email,
            profileUrl: attributes.profileUrl,
            isVerified: attributes.isVerified,
            oauthProvider: attributes.oauthProvider
        };
    }
});

declare module "lucia" {
    interface Register {
        Lucia: typeof lucia;
        DatabaseUserAttributes: {
            username: string;
            email: string;
            profileUrl: string | null;
            isVerified: boolean;
            oauthProvider: string | null;
        };
    }
}

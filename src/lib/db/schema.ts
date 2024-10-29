import { pgTable, text, timestamp, boolean, integer } from "drizzle-orm/pg-core";
import {InferSelectModel, InferInsertModel, relations} from 'drizzle-orm';

export const users = pgTable('users', {
	id: text('id').primaryKey(),
	email: text('email').notNull().unique(),
	username: text('username').notNull().unique(),
	password: text('password'),
	profileUrl: text('profile_url'),
	isVerified: boolean('is_verified').default(false),
	oauthProvider: text('oauth_provider'),
	createdAt: timestamp('created_at').defaultNow(),
	updatedAt: timestamp('updated_at').defaultNow(),
});

export const emailVerificationTable = pgTable('email_verification', {
	id: text('id').primaryKey(),
	userId: text('user_id').notNull().references(() => users.id),
	email: text('email').notNull(),
	code: text('code').notNull(),
	expiresAt: timestamp('expires_at', {
		withTimezone: true,
		mode: 'date'
	}).notNull(),
});

export const userRelations = relations(users, ({one}) => ({
	otp: one(emailVerificationTable, {
		fields: [users.id],
		references: [emailVerificationTable.userId]
	})
}))

export const sessions = pgTable('sessions', {
	id: text('id').primaryKey(),
	userId: text('user_id').notNull().references(() => users.id),
	expiresAt: timestamp('expires_at', { withTimezone: true }).notNull()
});

export const conversations = pgTable('conversations', {
	id: integer('id').primaryKey(),
	type: text('type').notNull(), // 'private' or 'group'
	createdAt: timestamp('created_at').defaultNow(),
	updatedAt: timestamp('updated_at').defaultNow(),
});

export const participants = pgTable('participants', {
	id: integer('id').primaryKey(),
	conversationId: integer('conversation_id').references(() => conversations.id),
	userId: text('user_id').references(() => users.id),
	joinedAt: timestamp('joined_at').defaultNow(),
});

export const messages = pgTable('messages', {
	id: integer('id').primaryKey(),
	conversationId: integer('conversation_id').references(() => conversations.id),
	senderId: text('sender_id').references(() => users.id),
	content: text('content').notNull(),
	sentAt: timestamp('sent_at').defaultNow(),
});

export const deletedConversations = pgTable('deleted_conversations', {
	id: integer('id').primaryKey(),
	conversationId: integer('conversation_id').references(() => conversations.id),
	userId: text('user_id').references(() => users.id),
	deletedAt: timestamp('deleted_at').defaultNow(),
});

export const readReceipts = pgTable('read_receipts', {
	id: integer('id').primaryKey(),
	messageId: integer('message_id').references(() => messages.id),
	userId: text('user_id').references(() => users.id),
	readAt: timestamp('read_at').defaultNow(),
});

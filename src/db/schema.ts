import { pgTable, pgEnum, timestamp, varchar, uuid, date, text } from "drizzle-orm/pg-core";

export const users = pgTable("users", {
  id: uuid("id").primaryKey().defaultRandom(),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at")
    .notNull()
    .defaultNow()
    .$onUpdate(() => new Date()),
  email: varchar("email", { length: 256 }).unique().notNull(),
  profileImg: text("profile_image"),
  username: varchar("username", { length: 30 }).unique().notNull(),
  hashedPassword: varchar("hashed_password").default("unset").notNull()
});

export type NewUser = typeof users.$inferInsert;
export type ExistingUser = typeof users.$inferSelect;

export const trips = pgTable("trips", {
    id: uuid("id").primaryKey().defaultRandom(),
    createdAt: timestamp("created_at").notNull().defaultNow(),
    name: varchar("name", { length: 256 }).notNull(),
    location: varchar("location", { length: 256 }).notNull(),
    description: varchar("description", { length: 256 }),
    bannerImg: text("banner_image"),
    startDate: date("start_date"),
    endDate: date("end_date"),
    createdBy: uuid("created_by").references(() => users.id, { onDelete: "cascade" }).notNull()
})

export type NewTrip = typeof trips.$inferInsert

export const roleEnum = pgEnum('role', [
  'OWNER',
  'EDITOR',
  'VIEWER',
]);

export const tripMembers = pgTable("trip_members", {
    id: uuid("id").primaryKey().defaultRandom(),
    createdAt: timestamp("created_at").notNull().defaultNow(),
    tripId: uuid("trip_id").references(() => trips.id, { onDelete: "cascade" }).notNull(),
    userId: uuid("user_id").references(() => users.id, { onDelete: "cascade" }).notNull(),
    role: roleEnum("role").notNull(),
})

export type NewMemeber = typeof trips.$inferInsert

export const photos = pgTable("photos", {
    id: uuid("id").primaryKey().defaultRandom(),
    createdAt: timestamp("created_at").notNull().defaultNow(),
    tripId: uuid("trip_id").references(() => trips.id, { onDelete: "cascade" }).notNull(),
    uploadedBy: uuid("uploaded_by").references(() => users.id, { onDelete: "cascade" }).notNull(),
    imageUrl: text("image_url").notNull()
})

export type NewPhoto = typeof photos.$inferInsert

export const tripNotes = pgTable("trip_notes", {
    id: uuid("id").primaryKey().defaultRandom(),
    createdAt: timestamp("created_at").notNull().defaultNow(),
    tripId: uuid("trip_id").references(() => trips.id, { onDelete: "cascade" }).notNull(),
    createdBy: uuid("created_by").references(() => users.id, { onDelete: "cascade" }).notNull(),
    content: text("content").notNull(),
})

export type NewNote = typeof tripNotes.$inferInsert
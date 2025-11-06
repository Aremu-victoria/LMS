import { Schema, model, models, Document } from 'mongoose';

export type UserRole = 'teacher' | 'student';

export interface IUser extends Document {
	name: string;
	email: string;
	role: UserRole;
	passwordHash: string;
	image?: string;
	// Student-specific
	matricNumber?: string;
	department?: string;
	level?: string;
	// Teacher-specific
	faculty?: string;
	specialization?: string;
	phone?: string;
	createdAt: Date;
	updatedAt: Date;
}

const UserSchema = new Schema<IUser>(
	{
		name: { type: String, required: true },
		email: { type: String, required: true, unique: true, index: true },
		role: { type: String, enum: ['teacher', 'student'], required: true },
		passwordHash: { type: String, required: true },
		image: { type: String },
		// Student fields
		matricNumber: { type: String },
		department: { type: String },
		level: { type: String },
		// Teacher fields
		faculty: { type: String },
		specialization: { type: String },
		phone: { type: String },
	},
	{ timestamps: true }
);

export const User = models.User || model<IUser>('User', UserSchema);









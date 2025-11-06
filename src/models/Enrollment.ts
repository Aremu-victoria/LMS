import { Schema, model, models, Document, Types } from 'mongoose';

export interface IEnrollment extends Document {
	student: Types.ObjectId;
	course: Types.ObjectId;
	enrolledAt: Date;
	progressPercent: number;
	completedMaterialFilepaths: string[];
}

const EnrollmentSchema = new Schema<IEnrollment>(
	{
		student: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
		course: { type: Schema.Types.ObjectId, ref: 'Course', required: true, index: true },
		enrolledAt: { type: Date, default: Date.now },
		progressPercent: { type: Number, default: 0 },
		completedMaterialFilepaths: { type: [String], default: [] },
	},
	{ timestamps: true }
);

EnrollmentSchema.index({ student: 1, course: 1 }, { unique: true });

export const Enrollment = models.Enrollment || model<IEnrollment>('Enrollment', EnrollmentSchema);









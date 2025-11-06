import { Schema, model, models, Document, Types } from 'mongoose';

export interface ICourseMaterial {
	_id?: Types.ObjectId;
	filename: string;
	mimetype: string;
	filepath: string;
	size: number;
}

export interface ICourse extends Document {
	title: string;
	code?: string;
	description: string;
	category: string;
	teacher: Types.ObjectId;
	thumbnail?: string;
	materials: ICourseMaterial[];
	createdAt: Date;
	updatedAt: Date;
}

const CourseMaterialSchema = new Schema<ICourseMaterial>({
	filename: { type: String, required: true },
	mimetype: { type: String, required: true },
	filepath: { type: String, required: true },
	size: { type: Number, required: true },
});

const CourseSchema = new Schema<ICourse>(
	{
		title: { type: String, required: true },
		code: { type: String, index: true },
		description: { type: String, required: true },
		category: { type: String, required: true, index: true },
		teacher: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
		thumbnail: { type: String },
		materials: { type: [CourseMaterialSchema], default: [] },
	},
	{ timestamps: true }
);

export const Course = models.Course || model<ICourse>('Course', CourseSchema);








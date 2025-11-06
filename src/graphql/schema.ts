import { createSchema } from 'graphql-yoga';
import { GraphQLResolveInfo } from 'graphql';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { connectToDatabase } from '../lib/db';
import { User, IUser } from '../models/User';
import { Course, ICourse } from '../models/Course';
import { Enrollment } from '../models/Enrollment';

type Context = {
	session: any;
 	user?: IUser | null;
};

const typeDefs = /* GraphQL */ `
	scalar Date

	enum Role {
		teacher
		student
	}

	type User {
		id: ID!
		name: String!
		email: String!
		role: Role!
		image: String
		# Student fields
		matricNumber: String
		department: String
		level: String
		# Teacher fields
		faculty: String
		specialization: String
		phone: String
		createdAt: Date!
		updatedAt: Date!
	}

	type CourseMaterial {
		filename: String!
		mimetype: String!
		filepath: String!
		size: Int!
	}

	type Course {
		id: ID!
		title: String!
		code: String
		description: String!
		category: String!
		teacher: User!
		thumbnail: String
		materials: [CourseMaterial!]!
		enrolledCount: Int!
		createdAt: Date!
		updatedAt: Date!
	}

	type Enrollment {
		id: ID!
		student: User!
		course: Course!
		progressPercent: Int!
		completedMaterialFilepaths: [String!]!
		createdAt: Date!
		updatedAt: Date!
	}

	input CourseInput {
		title: String!
		code: String
		description: String!
		category: String!
		thumbnail: String
		materials: [CourseMaterialInput!]
	}

	input CourseMaterialInput {
		filename: String!
		mimetype: String!
		filepath: String!
		size: Int!
	}

	type Query {
		me: User
		courses(search: String, category: String, teacherName: String): [Course!]!
		course(id: ID!): Course
		myCourses: [Course!]!
		myEnrollments: [Enrollment!]!
	}

	type Mutation {
		signup(
			name: String!
			email: String!
			password: String!
			role: Role!
			matricNumber: String
			department: String
			level: String
			faculty: String
			specialization: String
			phone: String
		): User!
		createCourse(input: CourseInput!): Course!
		updateCourse(id: ID!, input: CourseInput!): Course!
		deleteCourse(id: ID!): Boolean!
		enroll(courseId: ID!): Enrollment!
		updateProgress(courseId: ID!, completedFilepaths: [String!]!): Enrollment!
	}
`;

const resolvers = {
	Date: {
		__parseValue(value: any) {
			return new Date(value);
		},
		__serialize(value: any) {
			return new Date(value).toISOString();
		},
	},
	Course: {
		teacher: async (parent: ICourse) => {
			await connectToDatabase();
			return User.findById(parent.teacher);
		},
		enrolledCount: async (parent: ICourse) => {
			await connectToDatabase();
			const count = await Enrollment.countDocuments({ course: parent._id as any });
			return count;
		},
	},
	Enrollment: {
		student: async (parent: any) => User.findById(parent.student),
		course: async (parent: any) => Course.findById(parent.course),
	},
	Query: {
		me: async (_: unknown, _a: unknown, ctx: Context) => {
			if (!ctx.session?.user?.email) return null;
			await connectToDatabase();
			return User.findOne({ email: ctx.session.user.email });
		},
		courses: async (
			_: unknown,
			args: { search?: string; category?: string; teacherName?: string }
		) => {
			await connectToDatabase();
			const filter: any = {};
			if (args.category) filter.category = new RegExp(args.category, 'i');
			if (args.search) {
				filter.$or = [
					{ title: new RegExp(args.search, 'i') },
					{ description: new RegExp(args.search, 'i') },
					{ category: new RegExp(args.search, 'i') },
				];
			}
			let courses = await Course.find(filter).sort({ createdAt: -1 });
			if (args.teacherName) {
				const teacherUsers = await User.find({ name: new RegExp(args.teacherName, 'i') }).select('_id');
				const teacherIds = teacherUsers.map((u: any) => u._id as any);
				courses = courses.filter((c: any) => (teacherIds as any[]).some((id: any) => id.equals(c.teacher)));
			}
			return courses;
		},
		course: async (_: unknown, { id }: { id: string }) => {
			await connectToDatabase();
			return Course.findById(id);
		},
			myEnrollments: async (_: unknown, _a: unknown, ctx: Context) => {
			if (!ctx.session?.user?.email) return [];
			await connectToDatabase();
			const user = await User.findOne({ email: ctx.session.user.email });
			if (!user) return [];
			// call sort() on the Mongoose Query before awaiting the results
			const { Enrollment } = await import('../models/Enrollment');
			return Enrollment.find({ student: user._id }).sort({ createdAt: -1 });
		},
		myCourses: async (_: unknown, _a: unknown, ctx: Context) => {
			if (!ctx.session?.user?.email) return [];
			await connectToDatabase();
			const user = await User.findOne({ email: ctx.session.user.email });
			if (!user || user.role !== 'teacher') return [];
			return Course.find({ teacher: user._id }).sort({ createdAt: -1 });
		},
	},
	Mutation: {
		signup: async (
			_: unknown,
			{ name, email, password, role, matricNumber, department, level, faculty, specialization, phone }: { name: string; email: string; password: string; role: 'teacher' | 'student'; matricNumber?: string; department?: string; level?: string; faculty?: string; specialization?: string; phone?: string }
		) => {
			console.log('[graphql] signup called', { email, role });
			await connectToDatabase();
			const existing = await User.findOne({ email });
			if (existing) {
				console.log('[graphql] signup failed - email exists', email);
				throw new Error('Email already in use');
			}
			const passwordHash = await bcrypt.hash(password, 10);
			const userData: Partial<IUser> & { passwordHash: string } = { name, email, role, passwordHash };
			if (role === 'student') {
				if (matricNumber) userData.matricNumber = matricNumber;
				if (department) userData.department = department;
				if (level) userData.level = level;
			}
			if (role === 'teacher') {
				if (faculty) userData.faculty = faculty;
				if (specialization) userData.specialization = specialization;
				if (phone) userData.phone = phone;
			}
			const user = await User.create(userData);
			console.log('[graphql] signup success', { id: user._id?.toString?.() });
			return user;
		},
		createCourse: async (_: unknown, { input }: { input: any }, ctx: Context) => {
			if (!ctx.session?.user?.email) throw new Error('Unauthorized');
			await connectToDatabase();
			const user = await User.findOne({ email: ctx.session.user.email });
			if (!user || user.role !== 'teacher') throw new Error('Only teachers can create courses');
			const course = await Course.create({ ...input, teacher: user._id, materials: input.materials || [] });
			return course;
		},
		updateCourse: async (_: unknown, { id, input }: { id: string; input: any }, ctx: Context) => {
			if (!ctx.session?.user?.email) throw new Error('Unauthorized');
			await connectToDatabase();
			const user = await User.findOne({ email: ctx.session.user.email });
			if (!user || user.role !== 'teacher') throw new Error('Only teachers can edit courses');
			const course = await Course.findById(id);
			if (!course) throw new Error('Course not found');
			if (!course.teacher.equals(user._id)) throw new Error('Forbidden');
			course.title = input.title;
			course.code = input.code;
			course.description = input.description;
			course.category = input.category;
			course.thumbnail = input.thumbnail;
			course.materials = input.materials || [];
			await course.save();
			return course;
		},
		deleteCourse: async (_: unknown, { id }: { id: string }, ctx: Context) => {
			if (!ctx.session?.user?.email) throw new Error('Unauthorized');
			await connectToDatabase();
			const user = await User.findOne({ email: ctx.session.user.email });
			if (!user || user.role !== 'teacher') throw new Error('Only teachers can delete courses');
			const course = await Course.findById(id);
			if (!course) return false;
			if (!course.teacher.equals(user._id)) throw new Error('Forbidden');
			await course.deleteOne();
			return true;
		},
		enroll: async (_: unknown, { courseId }: { courseId: string }, ctx: Context) => {
			if (!ctx.session?.user?.email) throw new Error('Unauthorized');
			await connectToDatabase();
			const user = await User.findOne({ email: ctx.session.user.email });
			if (!user || user.role !== 'student') throw new Error('Only students can enroll');
			const course = await Course.findById(courseId);
			if (!course) throw new Error('Course not found');
			const enrollment = await Enrollment.findOneAndUpdate(
				{ student: user._id, course: course._id },
				{ $setOnInsert: { progressPercent: 0, completedMaterialFilepaths: [] } },
				{ upsert: true, new: true }
			);
			return enrollment;
		},
		updateProgress: async (
			_: unknown,
			{ courseId, completedFilepaths }: { courseId: string; completedFilepaths: string[] },
			ctx: Context
		) => {
			if (!ctx.session?.user?.email) throw new Error('Unauthorized');
			await connectToDatabase();
			const user = await User.findOne({ email: ctx.session.user.email });
			if (!user) throw new Error('Unauthorized');
			const course = await Course.findById(courseId);
			if (!course) throw new Error('Course not found');
			const total = Math.max(course.materials.length, 1);
			const unique = Array.from(new Set(completedFilepaths));
			const progressPercent = Math.min(100, Math.round((unique.length / total) * 100));
			const enrollment = await Enrollment.findOneAndUpdate(
				{ student: user._id, course: course._id },
				{ completedMaterialFilepaths: unique, progressPercent },
				{ new: true }
			);
			if (!enrollment) throw new Error('Not enrolled');
			return enrollment;
		},
	},
};

export const schema = createSchema({ typeDefs, resolvers });



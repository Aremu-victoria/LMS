import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import { MongoDBAdapter } from '@auth/mongodb-adapter';
import clientPromise from '../../../../lib/mongodb';
import { connectToDatabase } from '../../../../lib/db';
import { User } from '../../../../models/User';
import bcrypt from 'bcryptjs';

export const authOptions = {
	adapter: MongoDBAdapter(clientPromise) as any,
	session: { strategy: 'jwt' as const },
	providers: [
		Credentials({
			name: 'Credentials',
			credentials: {
				email: { label: 'Email', type: 'email' },
				password: { label: 'Password', type: 'password' },
			},
			authorize: async (credentials) => {
				if (!credentials?.email || !credentials?.password) return null;
				await connectToDatabase();
				const user = await User.findOne({ email: credentials.email });
				if (!user) return null;
				const ok = await bcrypt.compare(credentials.password, user.passwordHash);
				if (!ok) return null;
				return { id: String(user._id), name: user.name, email: user.email, role: user.role } as any;
			},
		}),
	],
	callbacks: {
		async jwt({ token, user }: any) {
			if (user) {
				token.role = (user as any).role;
			}
			return token;
		},
		async session({ session, token }: any) {
			(session.user as any).role = token.role;
			return session;
		},
	},
};

const handler = NextAuth(authOptions as any);
export { handler as GET, handler as POST };









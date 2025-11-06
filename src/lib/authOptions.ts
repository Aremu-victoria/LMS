import NextAuth, { NextAuthOptions, DefaultSession } from 'next-auth';
import CredentialsProvider from 'next-auth/providers/credentials';
import { MongoDBAdapter } from '@auth/mongodb-adapter';
import clientPromise from './mongodb';
import { connectToDatabase } from './db';
import { User } from '../models/User';
import bcrypt from 'bcryptjs';

declare module 'next-auth' {
  interface Session extends DefaultSession {
    user: {
      id: string;
      role: string;
    } & DefaultSession['user'];
  }

  interface User {
    role: string;
  }
}

export const authOptions: NextAuthOptions = {
  adapter: MongoDBAdapter(clientPromise) as any,
  secret: process.env.NEXTAUTH_SECRET,
  session: {
    strategy: 'jwt',
  },
  providers: [
    CredentialsProvider({
      name: 'Credentials',
      credentials: {
        email: { label: 'Email', type: 'email' },
        password: { label: 'Password', type: 'password' },
      },
      async authorize(credentials) {
        console.log('[auth] authorize called for', credentials?.email);
        if (!credentials?.email || !credentials?.password) {
          console.log('[auth] authorize missing credentials');
          return null;
        }
        try {
          await connectToDatabase();
          const user = await User.findOne({ email: credentials.email });
          if (!user) {
            console.log('[auth] authorize user not found', credentials.email);
            return null;
          }
          const isValid = await bcrypt.compare(credentials.password, user.passwordHash);
          if (!isValid) {
            console.log('[auth] authorize invalid password for', credentials.email);
            return null;
          }
          console.log('[auth] authorize success for', credentials.email);
          return {
            id: String(user._id),
            name: user.name,
            email: user.email,
            role: user.role,
          };
        } catch (err) {
          console.error('[auth] authorize error', err);
          throw err;
        }
      },
    }),
  ],
  callbacks: {
    async jwt({ token, user }) {
      try {
        if (user) {
          console.log('[auth] jwt callback adding role from user', (user as any).role);
          token.role = (user as any).role;
        }
        return token;
      } catch (err) {
        console.error('[auth] jwt callback error', err);
        throw err;
      }
    },
    async session({ session, token }) {
      try {
        if (session?.user) {
          (session.user as any).role = token.role as any;
        }
        console.log('[auth] session callback produced session for', (session?.user as any)?.email || null);
        return session;
      } catch (err) {
        console.error('[auth] session callback error', err);
        throw err;
      }
    },
  },
};

export default authOptions;

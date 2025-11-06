"use client";
import { SessionProvider } from 'next-auth/react';
import { ApolloClientProvider } from '../lib/apollo';
import { ReactNode } from 'react';
import ToastProvider from './ToastProvider';

export default function Providers({ children }: { children: ReactNode }) {
	return (
		<SessionProvider>
			<ApolloClientProvider>
				<ToastProvider>{children}</ToastProvider>
			</ApolloClientProvider>
		</SessionProvider>
	);
}








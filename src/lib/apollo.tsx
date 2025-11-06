"use client";
import { ApolloClient, InMemoryCache, HttpLink } from '@apollo/client';
import { ApolloProvider } from '@apollo/client/react';
import { ReactNode, useMemo } from 'react';

function makeClient() {
	return new ApolloClient({
		link: new HttpLink({ uri: '/api/graphql', credentials: 'include' }),
		cache: new InMemoryCache(),
	});
}

export function ApolloClientProvider({ children }: { children: ReactNode }) {
	const client = useMemo(() => makeClient(), []);
	return <ApolloProvider client={client}>{children}</ApolloProvider>;
}









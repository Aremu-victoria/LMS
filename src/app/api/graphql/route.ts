import { createYoga } from 'graphql-yoga';
import { schema } from '../../../graphql/schema';
import { NextRequest } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '../../auth/[...nextauth]/authOptions';

const yoga = createYoga({
	schema,
	graphqlEndpoint: '/api/graphql',
	context: async () => {
		const session = await getServerSession(authOptions);
		return { session };
	},
});

// Wrap the Yoga instance so it satisfies Next's route handler types.
// graphql-yoga's handler shape isn't assignable to Next's expected type, so use a thin wrapper.
export const GET = async (request: NextRequest, context: unknown): Promise<Response> => {
	// graphql-yoga's handler type doesn't match Next's RouteHandler types at the type level,
	// but at runtime the yoga handler can be forwarded the Request. Use a typed cast via unknown
	return (yoga as unknown as (request: Request, context?: unknown) => Response | Promise<Response>)(
		request as unknown as Request,
		context
	);
};

export const POST = async (request: NextRequest, context: unknown): Promise<Response> => {
	return (yoga as unknown as (request: Request, context?: unknown) => Response | Promise<Response>)(
		request as unknown as Request,
		context
	);
};









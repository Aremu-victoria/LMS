// Re-export `authOptions` from the API route so server code importing
// from `../../auth/[...nextauth]/authOptions` can resolve it.
export { authOptions } from '../../api/auth/[...nextauth]/route';

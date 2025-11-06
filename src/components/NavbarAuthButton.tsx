"use client";
import { useSession } from "next-auth/react";

export default function NavbarAuthButton() {
  const { data: session, status } = useSession();
  if (status === "loading") return null;
  if (session?.user) {
    return (
      <span className="ml-2 px-3 py-1 rounded-md bg-blue-50 text-blue-700 font-semibold">Welcome, {session.user.name || session.user.email}</span>
    );
  }
  return (
    <a className="ml-2 rounded-md border px-3 py-1 hover:bg-gray-50 dark:hover:bg-gray-900 transition-colors font-semibold bg-slate-800 text-white" href="/auth">Get Started</a>
  );
}

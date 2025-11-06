"use client";
import { useSession, signOut } from 'next-auth/react';
import { Home, Info, BookOpen, LayoutDashboard, LogOut, User as UserIcon, Mail } from 'lucide-react';

export default function Navbar() {
  const { data: session, status } = useSession();
  const role = (session?.user as any)?.role as 'teacher' | 'student' | undefined;

  return (
    <header className="border-b border-gray-200 dark:border-gray-800">
      <nav className="mx-auto max-w-6xl px-4 py-3 flex items-center justify-between">
        <a href="/" className="font-extrabold text-xl tracking-tight text-slate-800 dark:text-slate-100">LMS</a>
        <div className="flex items-center gap-4 text-sm">
          <a className="hover:text-blue-600 transition-colors flex items-center gap-1" href="/"><Home className="w-4 h-4" /> Home</a>
          <a className="hover:text-blue-600 transition-colors flex items-center gap-1" href="/courses"><BookOpen className="w-4 h-4" /> Courses</a>
          <a className="hover:text-blue-600 transition-colors flex items-center gap-1" href="/about"><Info className="w-4 h-4" /> About</a>
          <a className="hover:text-blue-600 transition-colors flex items-center gap-1" href="/#contact"><Mail className="w-4 h-4" /> Contact</a>
          {status !== 'loading' && (
            <>
              {session?.user ? (
                <>
                  {role === 'teacher' && <a className="hover:text-blue-600 transition-colors flex items-center gap-1" href="/dashboard"><LayoutDashboard className="w-4 h-4" /> Dashboard</a>}
                  {role === 'student' && <a className="hover:text-blue-600 transition-colors flex items-center gap-1" href="/my"><LayoutDashboard className="w-4 h-4" /> My Enrollments</a>}
                  <a className="hover:text-blue-600 transition-colors flex items-center gap-1" href="/profile"><UserIcon className="w-4 h-4" /> Profile</a>
                  <span className="hidden sm:inline text-gray-500">|</span>
                  <span className="px-2 py-1 rounded-md bg-blue-50 text-blue-700 font-semibold">{session.user.name || session.user.email}</span>
                  <button onClick={() => signOut({ callbackUrl: '/' })} className="rounded-md border px-3 py-1 hover:bg-gray-50 dark:hover:bg-gray-900 transition-colors flex items-center gap-1"><LogOut className="w-4 h-4" /> Logout</button>
                </>
              ) : (
                <a className="rounded-md bg-slate-800 text-white px-3 py-1 hover:bg-slate-900 transition-colors font-semibold" href="/auth">Sign in</a>
              )}
            </>
          )}
        </div>
      </nav>
    </header>
  );
}



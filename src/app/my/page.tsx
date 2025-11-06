"use client";
import { gql } from 'graphql-tag';
import { useQuery } from '@apollo/client/react';
import { useSession } from 'next-auth/react';

type MyEnrollment = { id: string; progressPercent: number; course: { id: string; title: string } };

const MY_ENROLLMENTS = gql`
  query MyEnrollments { myEnrollments { id progressPercent course { id title } } }
`;

export default function MyCoursesPage() {
  const { data: session } = useSession();
  const { data, loading } = useQuery<{ myEnrollments: MyEnrollment[] }>(MY_ENROLLMENTS);
  const list = data?.myEnrollments || [];
  return (
    <div className="mx-auto max-w-3xl px-4 py-8">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold tracking-tight">My Enrollments</h1>
        {session?.user && <div className="text-sm text-slate-600">Welcome, {session.user.name || session.user.email}</div>}
      </div>
      {loading && <div className="mt-4">Loading...</div>}
      <ul className="mt-4 space-y-3">
        {list.map((e) => (
          <li key={e.id} className="border rounded-md p-3 flex items-center justify-between">
            <a href={`/course/${e.course.id}`}>{e.course.title}</a>
            <div className="w-40 h-2 bg-gray-200 rounded-full overflow-hidden">
              <div className="h-2 bg-blue-600" style={{ width: `${e.progressPercent}%` }} />
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}








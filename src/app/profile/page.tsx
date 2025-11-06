"use client";
import { gql } from 'graphql-tag';
import { useQuery } from '@apollo/client/react';

const ME = gql`
  query Me { me { id name email role matricNumber department level faculty specialization phone } }
`;

export default function ProfilePage() {
  const { data } = useQuery(ME);
  const u = data?.me;
  return (
    <div className="mx-auto max-w-3xl px-4 py-10">
      <h1 className="text-2xl font-semibold tracking-tight">Profile</h1>
      {u && (
        <div className="mt-6 rounded-lg border border-slate-200 bg-white p-6">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
            <div><div className="text-slate-500">Name</div><div className="font-medium">{u.name}</div></div>
            <div><div className="text-slate-500">Email</div><div className="font-medium">{u.email}</div></div>
            <div><div className="text-slate-500">Role</div><div className="font-medium capitalize">{u.role}</div></div>
            {u.role === 'student' && (
              <>
                <div><div className="text-slate-500">Matric Number</div><div className="font-medium">{u.matricNumber || '-'}</div></div>
                <div><div className="text-slate-500">Department</div><div className="font-medium">{u.department || '-'}</div></div>
                <div><div className="text-slate-500">Level</div><div className="font-medium">{u.level || '-'}</div></div>
              </>
            )}
            {u.role === 'teacher' && (
              <>
                <div><div className="text-slate-500">Faculty</div><div className="font-medium">{u.faculty || '-'}</div></div>
                <div><div className="text-slate-500">Specialization</div><div className="font-medium">{u.specialization || '-'}</div></div>
                <div><div className="text-slate-500">Phone</div><div className="font-medium">{u.phone || '-'}</div></div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}




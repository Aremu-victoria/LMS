"use client";
import { gql } from 'graphql-tag';
import { useQuery } from '@apollo/client/react';
import { useState } from 'react';
import { Search, Filter } from 'lucide-react';
import { COURSE_CATEGORIES } from '../../lib/constants';

type CourseSummary = {
  id: string;
  title: string;
  description: string;
  category: string;
};

const COURSES = gql`
  query Courses($search: String, $category: String, $teacherName: String) {
    courses(search: $search, category: $category, teacherName: $teacherName) {
      id
      title
      description
      category
    }
  }
`;

export default function CoursesPage() {
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState('');
  const [teacherName, setTeacherName] = useState('');
  const { data, loading } = useQuery<{ courses: CourseSummary[] }>(COURSES, { variables: { search, category, teacherName } });

  return (
    <div className="mx-auto max-w-6xl px-4 py-8">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <h1 className="text-2xl font-semibold tracking-tight">Courses</h1>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 w-full sm:w-auto">
          <div className="border rounded-md px-3 py-2 bg-white flex items-center gap-2"><Search className="w-4 h-4 text-slate-500" /><input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search" className="bg-transparent outline-none w-full text-slate-900 placeholder:text-slate-500"/></div>
          <div className="border rounded-md px-3 py-2 bg-white flex items-center gap-2">
            <Filter className="w-4 h-4 text-slate-500" />
            <select value={category} onChange={(e) => setCategory(e.target.value)} className="bg-transparent outline-none w-full text-slate-900">
              <option value="">All Categories</option>
              {COURSE_CATEGORIES.map((cat) => (
                <option key={cat} value={cat}>{cat}</option>
              ))}
            </select>
          </div>
          <div className="border rounded-md px-3 py-2 bg-white flex items-center gap-2"><Filter className="w-4 h-4 text-slate-500" /><input value={teacherName} onChange={(e) => setTeacherName(e.target.value)} placeholder="Teacher" className="bg-transparent outline-none w-full text-slate-900 placeholder:text-slate-500"/></div>
        </div>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 mt-6">
        {loading && <div>Loading...</div>}
        {data?.courses?.map((c) => (
          <a key={c.id} href={`/course/${c.id}`} className="border rounded-lg p-4 hover:shadow transition-colors bg-white">
            <div className="text-xs text-gray-500">{c.category}</div>
            <div className="mt-1 font-medium text-slate-900">{c.title}</div>
            <div className="text-sm text-gray-600 line-clamp-2 mt-1">{c.description}</div>
          </a>
        ))}
      </div>
    </div>
  );
}








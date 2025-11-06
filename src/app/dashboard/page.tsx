"use client";
import { gql } from 'graphql-tag';
import { useMutation, useQuery } from '@apollo/client/react';
import { useState } from 'react';
import { useSession } from 'next-auth/react';
import { FileUp, Trash2, Edit3 } from 'lucide-react';
import { COURSE_CATEGORIES } from '../../lib/constants';

type UploadedFile = { filename: string; filepath: string; mimetype?: string; size?: number };

const CREATE_COURSE = gql`
  mutation CreateCourse($input: CourseInput!) {
    createCourse(input: $input) { id title }
  }
`;

const MY_COURSES = gql`
  query MyCourses { myCourses { id title code category description enrolledCount } }
`;

const DELETE_COURSE = gql`
  mutation DeleteCourse($id: ID!) { deleteCourse(id: $id) }
`;

export default function DashboardPage() {
  const { data: session } = useSession();
  const [title, setTitle] = useState('');
  const [code, setCode] = useState('');
  const [description, setDescription] = useState('');
  const [category, setCategory] = useState('');
  const [materials, setMaterials] = useState<UploadedFile[]>([]);
  const [thumbnail, setThumbnail] = useState<string>('');
  const [createCourse, { loading }] = useMutation(CREATE_COURSE);
  const { data: listData, refetch } = useQuery<{ myCourses: { id: string; title: string; code?: string; category: string; description: string; enrolledCount: number }[] }>(MY_COURSES);
  const [deleteCourse] = useMutation(DELETE_COURSE, { onCompleted: () => refetch() });

  async function handleUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const files = e.target.files;
    if (!files || !files.length) return;
    const form = new FormData();
    Array.from(files).forEach((f) => form.append('files', f));
    const res = await fetch('/api/upload', { method: 'POST', body: form });
  const json = await res.json();
  // assume upload endpoint returns { files: UploadedFile[] }
  setMaterials((prev) => [...prev, ...(json.files as UploadedFile[])]);
  }

  async function handleThumbnailUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const files = e.target.files;
    if (!files || !files.length) return;
    const form = new FormData();
    form.append('files', files[0]);
    const res = await fetch('/api/upload', { method: 'POST', body: form });
    const json = await res.json();
    const first = (json.files as UploadedFile[])[0];
    if (first?.filepath) setThumbnail(first.filepath);
  }

  async function submit() {
    await createCourse({ variables: { input: { title, code, description, category, thumbnail: thumbnail || undefined, materials } } });
    setTitle(''); setDescription(''); setCategory(''); setMaterials([]);
    setCode(''); setThumbnail('');
    alert('Course created');
    refetch();
  }

  return (
    <div className="min-h-screen bg-gray-50 py-12">
      <div className="mx-auto max-w-4xl px-4">
        {session?.user && (
          <div className="mb-6">
            <h2 className="text-xl font-semibold text-slate-900">Welcome, {session.user.name || session.user.email}</h2>
          </div>
        )}

        <div className="rounded-lg bg-white shadow-sm p-6">
          <h1 className="text-2xl font-semibold tracking-tight text-slate-800">Teacher Dashboard</h1>
          <p className="mt-1 text-sm text-slate-500">Create and manage your courses from here.</p>
          <div className="mt-6 space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <input className="w-full border border-slate-200 rounded-md px-4 py-3 bg-white text-slate-900 placeholder:text-slate-500" placeholder="Title" value={title} onChange={(e)=>setTitle(e.target.value)} />
              <input className="w-full border border-slate-200 rounded-md px-4 py-3 bg-white text-slate-900 placeholder:text-slate-500" placeholder="Code (e.g., CSC101)" value={code} onChange={(e)=>setCode(e.target.value)} />
            </div>
            <textarea className="w-full border border-slate-200 rounded-md px-4 py-3 bg-white text-slate-900 placeholder:text-slate-500" rows={4} placeholder="Description" value={description} onChange={(e)=>setDescription(e.target.value)} />
            <select className="w-full border border-slate-200 rounded-md px-4 py-3 bg-white text-slate-900" value={category} onChange={(e)=>setCategory(e.target.value)}>
              <option value="">Select Category</option>
              {COURSE_CATEGORIES.map((cat) => (
                <option key={cat} value={cat}>{cat}</option>
              ))}
            </select>
            <label className="block text-sm text-slate-600">Course thumbnail (optional)</label>
            <div className="flex items-center gap-2">
              <FileUp className="w-5 h-5 text-slate-600" />
              <input type="file" accept="image/*" onChange={handleThumbnailUpload} className="block" />
            </div>
            {thumbnail && (
              <div className="mt-2 text-sm text-slate-600">Selected thumbnail: <a className="text-blue-700 hover:underline" href={thumbnail} target="_blank">{thumbnail}</a></div>
            )}
            <label className="block mt-4 text-sm text-slate-600">Upload materials</label>
            <div className="flex items-center gap-2">
              <FileUp className="w-5 h-5 text-slate-600" />
              <input type="file" multiple onChange={handleUpload} accept=".pdf,.doc,.docx,.ppt,.pptx,.mp4,.mov,.avi,.mkv,.png,.jpg,.jpeg" className="block" />
            </div>
            <ul className="text-sm text-slate-700">
              {materials.map((m) => (
                <li key={m.filepath} className="flex items-center justify-between">
                  <span>{m.filename} <span className="text-slate-400">({Math.round((m.size||0)/1024)} KB)</span></span>
                </li>
              ))}
            </ul>
            <div className="pt-2">
              <button onClick={submit} disabled={loading} className="rounded-md bg-slate-800 text-white px-6 py-2 hover:bg-slate-900 transition-colors disabled:opacity-50">
                {loading ? 'Creating...' : 'Create Course'}
              </button>
            </div>
          </div>
        </div>
        <div className="mt-8 rounded-lg bg-white shadow-sm p-6">
          <h2 className="text-lg font-semibold text-slate-800">Your Courses</h2>
          <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-4">
            {listData?.myCourses?.map((c) => (
              <div key={c.id} className="border rounded-lg p-4">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="text-xs text-slate-500">{c.category} {c.code ? `· ${c.code}` : ''}</div>
                    <div className="font-medium">{c.title}</div>
                    <div className="text-xs text-slate-500 mt-1">Enrolled: {c.enrolledCount}</div>
                  </div>
                  <div className="flex items-center gap-2">
                    <button className="p-2 rounded hover:bg-slate-100" title="Edit"><Edit3 className="w-4 h-4" /></button>
                    <button onClick={() => deleteCourse({ variables: { id: c.id } })} className="p-2 rounded hover:bg-slate-100" title="Delete"><Trash2 className="w-4 h-4" /></button>
                  </div>
                </div>
              </div>
            ))}
            {!listData?.myCourses?.length && (
              <div className="text-sm text-slate-500">No courses yet.</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}








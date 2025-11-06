"use client";
import { gql } from 'graphql-tag';
import { useQuery, useMutation } from '@apollo/client/react';
import { useParams } from 'next/navigation';
import { useMemo } from 'react';
import { useToast } from '../../../components/ToastProvider';
import { Download, ExternalLink } from 'lucide-react';

type CourseMaterial = { filename: string; filepath: string; mimetype?: string; size?: number };
type CourseDetail = { id: string; title: string; description: string; category: string; materials?: CourseMaterial[] };

const COURSE = gql`
  query Course($id: ID!) {
    course(id: $id) {
      id
      title
      description
      category
      materials { filename filepath mimetype size }
    }
  }
`;

const ENROLL = gql`
  mutation Enroll($courseId: ID!) { enroll(courseId: $courseId) { id progressPercent } }
`;

const UPDATE_PROGRESS = gql`
  mutation UpdateProgress($courseId: ID!, $completedFilepaths: [String!]!) {
    updateProgress(courseId: $courseId, completedFilepaths: $completedFilepaths) { id progressPercent }
  }
`;

export default function CourseDetailPage() {
  const params = useParams();
  const id = params?.id as string;
  const { data } = useQuery<{ course: CourseDetail }>(COURSE, { variables: { id }, skip: !id });
  const [enroll, { loading: enrolling }] = useMutation(ENROLL, { variables: { courseId: id } });
  const [updateProgress, { loading: updating }] = useMutation(UPDATE_PROGRESS);
  const { showToast } = useToast();

  const course = data?.course;
  const allFilepaths = useMemo(() => (course?.materials || []).map((m) => m.filepath), [course]);

  async function markCompleted() {
    if (!id) return;
    await updateProgress({ variables: { courseId: id, completedFilepaths: allFilepaths } });
    showToast('Course marked as completed', 'success');
  }

  return (
    <div className="mx-auto max-w-3xl px-4 py-8">
      {course && (
        <>
          <h1 className="text-2xl font-semibold tracking-tight">{course.title}</h1>
          <div className="text-gray-500">{course.category}</div>
          <p className="mt-3 text-gray-700 dark:text-gray-300">{course.description}</p>
          <div className="mt-4 flex items-center gap-3">
            <button onClick={() => enroll()} disabled={enrolling} className="rounded-md bg-blue-600 text-white px-4 py-2 hover:bg-blue-700 transition-colors disabled:opacity-50">{enrolling ? 'Enrolling...' : 'Enroll'}</button>
            <button onClick={markCompleted} disabled={updating || !course?.materials?.length} className="rounded-md bg-slate-800 text-white px-4 py-2 hover:bg-slate-900 transition-colors disabled:opacity-50">{updating ? 'Marking...' : "I'm done (Completed)"}</button>
          </div>
          <h2 className="mt-8 font-medium">Materials</h2>
          <ul className="mt-2 space-y-2">
            {course.materials?.map((m) => (
              <li key={m.filepath} className="flex items-center justify-between border rounded-md px-3 py-2 bg-white">
                <span className="text-sm text-slate-800">{m.filename}</span>
                <div className="flex items-center gap-2">
                  <a href={m.filepath} target="_blank" className="text-sm text-slate-700 hover:text-slate-900 flex items-center gap-1"><ExternalLink className="w-4 h-4"/> View</a>
                  <a href={m.filepath} download className="text-sm text-blue-600 hover:text-blue-800 flex items-center gap-1"><Download className="w-4 h-4"/> Download</a>
                </div>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}








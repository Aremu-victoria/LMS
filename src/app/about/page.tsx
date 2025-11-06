import { Mail, Phone, Github, Linkedin } from 'lucide-react';

export default function AboutPage() {
  return (
    <div className="bg-white">
      <div className="mx-auto max-w-6xl px-4 py-14">
      <div className="max-w-4xl">
          <h1 className="text-4xl font-extrabold tracking-tight text-slate-900">About This LMS</h1>
          <p className="mt-4 text-lg leading-relaxed text-slate-800">This platform was built by <span className="font-semibold text-slate-900">Aremu Victoria</span>, an <span className="font-semibold text-slate-900">SQI College of ICT</span> final student, with the aim of improving the education sector through technology and digital learning. It provides a clean, modern experience for teachers to share knowledge and for students to learn effectively.</p>
      </div>

        <section className="grid grid-cols-1 md:grid-cols-2 gap-8 mt-10">
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
          <h2 className="text-2xl font-semibold text-slate-900">Our Mission</h2>
            <p className="mt-2 text-slate-800">To empower institutions with simple yet powerful tools that make learning accessible, engaging, and measurable for every student.</p>
        </div>
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
          <h2 className="text-2xl font-semibold text-slate-900">Our Vision</h2>
            <p className="mt-2 text-slate-800">A future where teachers and students collaborate seamlessly using technology to achieve outstanding academic outcomes.</p>
        </div>
        </section>

        <section className="mt-10">
        <h2 className="text-2xl font-semibold text-slate-900">How It Helps</h2>
        <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
            <div className="font-semibold text-slate-900">For Teachers</div>
              <p className="mt-1 text-slate-800">Upload courses, manage learning materials, and monitor student progress in real time.</p>
          </div>
          <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
            <div className="font-semibold text-slate-900">For Students</div>
              <p className="mt-1 text-slate-800">Enroll in courses, download resources, and track your learning milestones.</p>
          </div>
        </div>
        </section>

        <section className="mt-10">
        <h2 className="text-2xl font-semibold text-slate-900">Core Features</h2>
          <ul className="mt-2 list-disc pl-6 text-slate-900 space-y-1">
          <li>Secure authentication and role-based access</li>
          <li>Course uploads with files (PDF, video, documents)</li>
          <li>Student enrollment and download access</li>
          <li>Real-time progress tracking</li>
          <li>Responsive, professional UI built with Next.js and Tailwind CSS</li>
          </ul>
        </section>

        <section className="mt-12">
        <h2 className="text-2xl font-semibold text-slate-900">Contact Me</h2>
        <div className="mt-3 rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
            <a href="mailto:contact@edu-lms.com" className="flex items-center gap-2 text-slate-800 hover:text-blue-700 transition-colors"><Mail className="w-4 h-4"/> victoria@edu-lms.com</a>
            <a href="tel:+234000000000" className="flex items-center gap-2 text-slate-800 hover:text-blue-700 transition-colors"><Phone className="w-4 h-4"/> +234 000 000 000</a>
            <a href="#" className="flex items-center gap-2 text-slate-800 hover:text-blue-700 transition-colors"><Github className="w-4 h-4"/> github.com/aremuvictoria</a>
            <a href="#" className="flex items-center gap-2 text-slate-800 hover:text-blue-700 transition-colors"><Linkedin className="w-4 h-4"/> linkedin.com/in/aremuvictoria</a>
          </div>
        </div>
        </section>
      </div>
    </div>
  );
}

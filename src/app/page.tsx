export default function LandingPage() {
  return (
    <div className="min-h-screen bg-white">
      <section className="relative">
        <div className="absolute inset-0">
          <img src="/coverpage.jpg" alt="Cover" className="h-full w-full object-cover" />
          <div className="absolute inset-0 bg-white/25" />
        </div>
        <div className="relative mx-auto max-w-6xl px-4 py-24 lg:py-36">
          <div className="max-w-2xl">
            <h1 className="text-4xl sm:text-5xl font-extrabold tracking-tight text-slate-900">Empowering Teachers and Students Through Learning</h1>
            <p className="mt-4 text-lg text-slate-900">A clean, modern LMS for colleges. Teachers upload resources; students enroll, study, and track progress seamlessly.</p>
            <div className="mt-8 flex flex-col sm:flex-row gap-3">
              <a href="/auth" className="inline-flex items-center justify-center rounded-md bg-slate-900 text-white px-6 py-3 font-semibold hover:bg-slate-800 transition-colors">Get Started</a>
              <a href="/courses" className="inline-flex items-center justify-center rounded-md border border-slate-300 text-slate-800 px-6 py-3 font-semibold bg-white hover:bg-slate-50 transition-colors">Browse Courses</a>
            </div>
          </div>
        </div>
      </section>
      <section className="mx-auto max-w-6xl px-4 py-16 lg:py-20">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-10 items-start">
          <div>
            <h2 className="text-2xl font-bold text-slate-900">What you can do</h2>
            <p className="mt-2 text-slate-600">A focused platform with the essentials for academic learning and teaching.</p>
          </div>
          <div className="rounded-xl border border-slate-200 p-6 bg-slate-50">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="rounded-lg bg-white border border-slate-200 p-4">
                <h3 className="font-semibold text-slate-900">Teacher Uploads</h3>
                <p className="text-sm text-slate-600 mt-1">Upload PDFs, videos, and documents with categories and thumbnails.</p>
              </div>
              <div className="rounded-lg bg-white border border-slate-200 p-4">
                <h3 className="font-semibold text-slate-900">Student Enrollment</h3>
                <p className="text-sm text-slate-600 mt-1">Enroll in courses, download materials, and learn at your pace.</p>
              </div>
              <div className="rounded-lg bg-white border border-slate-200 p-4">
                <h3 className="font-semibold text-slate-900">Progress Tracking</h3>
                <p className="text-sm text-slate-600 mt-1">Track completion with clear progress indicators per course.</p>
              </div>
              <div className="rounded-lg bg-white border border-slate-200 p-4">
                <h3 className="font-semibold text-slate-900">Clean, Responsive UI</h3>
                <p className="text-sm text-slate-600 mt-1">Neutral tones, clear typography, and thoughtful spacing.</p>
              </div>
            </div>
          </div>
        </div>
      </section>
      <section className="mx-auto max-w-6xl px-4 py-16">
        <h2 className="text-2xl font-bold text-slate-900">Available Categories</h2>
        <p className="mt-2 text-slate-600">Explore a wide range of academic fields.</p>
        <div className="mt-6 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
          {['Computer Science & IT','Data Science & AI','Software Engineering','Web Development','Mobile App Development','Cybersecurity','Electrical & Electronics Engineering','Mechanical Engineering'].map((c) => (
            <div key={c} className=" border-slate-200 bg-white px-3 py-2 text-sm text-slate-800">{c}</div>
          ))}
        </div>
      </section>
      <section className="mx-auto max-w-6xl px-4 py-16">
        <h2 className="text-2xl font-bold text-slate-900">Meet Our Teachers</h2>
        <p className="mt-2 text-slate-600">Experienced educators across diverse disciplines.</p>
        <div className="mt-6 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {[1,2,3].map((i) => (
            <div key={i} className="rounded-lg border border-slate-200 bg-white p-4">
              <div className="h-16 w-16 rounded-full bg-slate-300 ring-1 ring-slate-300" />
              <div className="mt-3 font-medium text-slate-900">Dr. Placeholder {i}</div>
              <div className="text-sm text-slate-600">Department of Computer Science</div>
            </div>
          ))}
        </div>
      </section>
      <section id="contact" className="mx-auto max-w-6xl px-4 py-16">
        <h2 className="text-2xl font-bold text-slate-900">Contact Us</h2>
        <p className="mt-2 text-slate-600">Have questions? Send us a message.</p>
        <form className="mt-6 grid grid-cols-1 sm:grid-cols-2 gap-3 max-w-3xl">
          <input className="border border-slate-200 rounded-md px-3 py-2 bg-white text-slate-900 placeholder:text-slate-500" placeholder="Your name" />
          <input className="border border-slate-200 rounded-md px-3 py-2 bg-white text-slate-900 placeholder:text-slate-500" placeholder="Your email" />
          <textarea className="sm:col-span-2 border border-slate-200 rounded-md px-3 py-2 bg-white text-slate-900 placeholder:text-slate-500" rows={4} placeholder="Your message" />
          <div className="sm:col-span-2">
            <button type="button" className="rounded-md bg-slate-900 text-white px-5 py-2 hover:bg-slate-800 transition-colors">Send Message</button>
          </div>
        </form>
      </section>
    </div>
  );
}

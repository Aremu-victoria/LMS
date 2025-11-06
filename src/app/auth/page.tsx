"use client";
import { useMemo, useState } from 'react';
import { signIn } from 'next-auth/react';
import { gql } from 'graphql-tag';
import { useMutation } from '@apollo/client/react';
import { useToast } from '../../components/ToastProvider';
import { Mail, Lock, User as UserIcon, Phone } from 'lucide-react';

const SIGNUP = gql`
  mutation Signup(
    $name: String!
    $email: String!
    $password: String!
    $role: Role!
    $matricNumber: String
    $department: String
    $level: String
    $faculty: String
    $specialization: String
    $phone: String
  ) {
    signup(
      name: $name
      email: $email
      password: $password
      role: $role
      matricNumber: $matricNumber
      department: $department
      level: $level
      faculty: $faculty
      specialization: $specialization
      phone: $phone
    ) { id }
  }
`;

export default function AuthPage() {
  const [isLogin, setIsLogin] = useState(true);
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [role, setRole] = useState<'teacher' | 'student'>('student');
  const [matricNumber, setMatricNumber] = useState('');
  const [department, setDepartment] = useState('');
  const [level, setLevel] = useState('');
  const [faculty, setFaculty] = useState('');
  const [specialization, setSpecialization] = useState('');
  const [phone, setPhone] = useState('');
  const [signup, { loading }] = useMutation(SIGNUP);
  const { showToast } = useToast();

  const isEmailValid = useMemo(() => /.+@.+\..+/.test(email), [email]);
  const isPasswordValid = useMemo(() => password.length >= 6, [password]);
  const canSubmit = useMemo(() => {
    if (isLogin) return isEmailValid && isPasswordValid;
    if (!name.trim()) return false;
    if (!isEmailValid || !isPasswordValid) return false;
    if (password !== confirmPassword) return false;
    if (role === 'student') return !!(matricNumber && department && level);
    if (role === 'teacher') return !!(faculty && specialization && phone);
    return true;
  }, [isLogin, name, isEmailValid, isPasswordValid, role, matricNumber, department, level, faculty, specialization, phone]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    try {
      if (isLogin) {
        const res = await signIn('credentials', { email, password, redirect: false });
        if (res?.error) throw new Error('Invalid credentials');
        showToast('Welcome back!', 'success');
        window.location.href = '/';
        return;
      }
      await signup({ variables: { name, email, password, role, matricNumber: matricNumber || null, department: department || null, level: level || null, faculty: faculty || null, specialization: specialization || null, phone: phone || null } });
      showToast(`Welcome, ${name}!`, 'success');
      const res = await signIn('credentials', { email, password, redirect: false });
      if (res?.error) {
        showToast('Account created. Please log in.', 'info');
        window.location.href = '/auth';
        return;
      }
      window.location.href = role === 'teacher' ? '/dashboard' : '/my';
    } catch (err: any) {
      showToast(err?.message || 'Something went wrong', 'error');
    }
  }

  return (
    <div className="min-h-screen bg-white flex items-center justify-center py-12 px-4">
      <div className="w-full max-w-5xl">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          <div className="hidden md:block border border-slate-200 rounded-lg p-8 bg-slate-50">
            <h2 className="text-3xl font-extrabold text-slate-900">{isLogin ? 'Welcome back' : 'Join the LMS'}</h2>
            <p className="mt-3 text-slate-600 text-lg">A professional platform for teachers to share knowledge and for students to learn, enroll, and track their progress.</p>
            <ul className="mt-6 space-y-2 text-slate-700">
              <li>• Upload PDFs, videos, and documents</li>
              <li>• Enroll in courses and download materials</li>
              <li>• Track progress with clear indicators</li>
            </ul>
          </div>
          <div className="bg-white border border-slate-200 shadow-sm rounded-lg p-6">
            <div className="mb-4">
              <h1 className="text-2xl font-semibold text-slate-800">{isLogin ? 'Sign in to your account' : 'Create your account'}</h1>
              <p className="mt-1 text-sm text-slate-500">{isLogin ? 'Access your dashboard and courses' : 'Sign up as a student or teacher'}</p>
            </div>
            <form onSubmit={handleSubmit} className="mt-3 space-y-3">
            {!isLogin && (
                <div className="w-full border border-slate-200 rounded-md px-3 py-2 bg-white flex items-center gap-2">
                  <UserIcon className="w-4 h-4 text-slate-500" />
                  <input className="flex-1 outline-none bg-transparent text-slate-900 placeholder:text-slate-500" placeholder="Full name" value={name} onChange={(e)=>setName(e.target.value)} />
                </div>
            )}
              <div className="w-full border border-slate-200 rounded-md px-3 py-2 bg-white flex items-center gap-2">
                <Mail className="w-4 h-4 text-slate-500" />
                <input className="flex-1 outline-none bg-transparent text-slate-900 placeholder:text-slate-500" type="email" placeholder="Email" value={email} onChange={(e)=>setEmail(e.target.value)} />
              </div>
              <div className="w-full border border-slate-200 rounded-md px-3 py-2 bg-white flex items-center gap-2">
                <Lock className="w-4 h-4 text-slate-500" />
                <input className="flex-1 outline-none bg-transparent text-slate-900 placeholder:text-slate-500" type="password" placeholder="Password (min 6 chars)" value={password} onChange={(e)=>setPassword(e.target.value)} />
              </div>
              {!isLogin && (
                <div className="w-full border border-slate-200 rounded-md px-3 py-2 bg-white flex items-center gap-2">
                  <Lock className="w-4 h-4 text-slate-500" />
                  <input className="flex-1 outline-none bg-transparent text-slate-900 placeholder:text-slate-500" type="password" placeholder="Confirm password" value={confirmPassword} onChange={(e)=>setConfirmPassword(e.target.value)} />
                </div>
              )}
            {!isLogin && (
              <>
                <div>
                  <label className="block text-sm text-slate-600 mb-2">Role</label>
                    <select className="w-full border border-slate-200 rounded-md px-3 py-2 bg-white text-slate-900" value={role} onChange={(e)=>setRole(e.target.value as 'student' | 'teacher')}>
                    <option value="student">Student</option>
                    <option value="teacher">Teacher</option>
                  </select>
                </div>
                {role === 'student' && (
                  <div className="space-y-2">
                      <div className="w-full border border-slate-200 rounded-md px-3 py-2 bg-white flex items-center gap-2">
                        <UserIcon className="w-4 h-4 text-slate-500" />
                        <input className="flex-1 outline-none bg-transparent text-slate-900 placeholder:text-slate-500" placeholder="Matric Number" value={matricNumber} onChange={(e)=>setMatricNumber(e.target.value)} />
                      </div>
                      <div className="w-full border border-slate-200 rounded-md px-3 py-2 bg-white flex items-center gap-2">
                        <UserIcon className="w-4 h-4 text-slate-500" />
                        <input className="flex-1 outline-none bg-transparent text-slate-900 placeholder:text-slate-500" placeholder="Department" value={department} onChange={(e)=>setDepartment(e.target.value)} />
                      </div>
                      <div className="w-full border border-slate-200 rounded-md px-3 py-2 bg-white flex items-center gap-2">
                        <UserIcon className="w-4 h-4 text-slate-500" />
                        <input className="flex-1 outline-none bg-transparent text-slate-900 placeholder:text-slate-500" placeholder="Level" value={level} onChange={(e)=>setLevel(e.target.value)} />
                      </div>
                  </div>
                )}
                {role === 'teacher' && (
                  <div className="space-y-2">
                      <div className="w-full border border-slate-200 rounded-md px-3 py-2 bg-white flex items-center gap-2">
                        <UserIcon className="w-4 h-4 text-slate-500" />
                        <input className="flex-1 outline-none bg-transparent text-slate-900 placeholder:text-slate-500" placeholder="Department/Faculty" value={faculty} onChange={(e)=>setFaculty(e.target.value)} />
                      </div>
                      <div className="w-full border border-slate-200 rounded-md px-3 py-2 bg-white flex items-center gap-2">
                        <UserIcon className="w-4 h-4 text-slate-500" />
                        <input className="flex-1 outline-none bg-transparent text-slate-900 placeholder:text-slate-500" placeholder="Area of Specialization" value={specialization} onChange={(e)=>setSpecialization(e.target.value)} />
                      </div>
                      <div className="w-full border border-slate-200 rounded-md px-3 py-2 bg-white flex items-center gap-2">
                        <Phone className="w-4 h-4 text-slate-500" />
                        <input className="flex-1 outline-none bg-transparent text-slate-900 placeholder:text-slate-500" placeholder="Phone Number" value={phone} onChange={(e)=>setPhone(e.target.value)} />
                      </div>
                  </div>
                )}
              </>
            )}
            {!isLogin && password !== confirmPassword && (
              <div className="text-sm text-rose-600">Passwords do not match.</div>
            )}
            <button className="w-full rounded-md bg-slate-800 text-white px-4 py-2 hover:bg-slate-900 transition-colors disabled:opacity-50" disabled={loading || !canSubmit} type="submit">
                {isLogin ? 'Login' : 'Create account'}
              </button>
            </form>
            <div className="mt-4 text-center">
              <button className="text-sm text-slate-600 hover:underline" onClick={()=>setIsLogin(!isLogin)}>
                {isLogin ? 'No account? Create one' : 'Have an account? Log in'}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}








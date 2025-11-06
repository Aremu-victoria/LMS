import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import Providers from "../components/Providers";
import Navbar from "../components/Navbar";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "LMS",
  description: "Minimal, modern learning management system",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased bg-white text-gray-900 dark:bg-gray-950 dark:text-gray-100 transition-colors`}
      >
        <div className="min-h-screen flex flex-col">
          <Providers>
            <Navbar />
            <main className="flex-1">{children}</main>
            <footer className="border-t border-gray-200 dark:border-gray-800">
              <div className="mx-auto max-w-6xl px-4 py-6 text-sm text-gray-500 flex flex-col sm:flex-row justify-between items-center">
                <span>© 2025 Built by Aremu Victoria — SQI College of ICT Final Student. All Rights Reserved.</span>
                <span>
                  <a href="/about" className="hover:text-blue-600 transition-colors">About Us</a> &middot; 
                  <a href="mailto:support@lms.com" className="hover:text-blue-600 transition-colors">Contact</a>
                </span>
              </div>
            </footer>
          </Providers>
        </div>
      </body>
    </html>
  );
}

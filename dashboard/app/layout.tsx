import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "MiniStack Dashboard",
  description: "Visual dashboard for MiniStack AWS emulator",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="min-h-screen">
        <nav className="border-b border-[var(--border)] px-6 py-4 flex items-center gap-4">
          <a href="/" className="text-lg font-bold tracking-tight">
            MiniStack
          </a>
          <span className="text-[var(--text-muted)] text-sm">Dashboard</span>
          <div className="ml-auto flex gap-4 text-sm">
            <a
              href="/"
              className="hover:text-white text-[var(--text-muted)] transition-colors"
            >
              Overview
            </a>
            <a
              href="/tests"
              className="hover:text-white text-[var(--text-muted)] transition-colors"
            >
              Tests
            </a>
          </div>
        </nav>
        <main className="p-6">{children}</main>
      </body>
    </html>
  );
}

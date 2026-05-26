"use client";

import { useState, FormEvent, useEffect } from "react";
import { useRouter } from "next/navigation";
import { Shield, Eye, EyeOff, AlertCircle, Lock, Mail } from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";
import { toast } from "sonner";

export default function LoginPage() {
  const router = useRouter();
  const { login, register, isAuthenticated, isLoading } = useAuth();

  useEffect(() => {
    if (!isLoading && isAuthenticated) router.replace("/dashboard");
  }, [isAuthenticated, isLoading, router]);

  const [mode, setMode]                   = useState<"login" | "register">("login");
  const [email, setEmail]                 = useState("");
  const [password, setPassword]           = useState("");
  const [confirmPassword, setConfirm]     = useState("");
  const [showPass, setShowPass]           = useState(false);
  const [showConfirmPass, setShowConfirm] = useState(false);
  const [rememberMe, setRememberMe]       = useState(false);
  const [loading, setLoading]             = useState(false);
  const [error, setError]                 = useState("");

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    if (mode === "register" && password !== confirmPassword) { setError("Passwords do not match"); return; }
    if (mode === "register" && password.length < 8)          { setError("Password must be at least 8 characters"); return; }
    setLoading(true);
    try {
      if (mode === "login") {
        await login(email, password, rememberMe);
        toast.success("Welcome back!");
        router.push("/dashboard");
      } else {
        await register(email, password);
        toast.success("Account created — please sign in.");
        setMode("login"); setPassword(""); setConfirm("");
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Authentication failed");
    } finally {
      setLoading(false);
    }
  };

  const switchMode = () => {
    setMode(mode === "login" ? "register" : "login");
    setEmail(""); setPassword(""); setConfirm("");
    setRememberMe(false); setError("");
  };

  if (isLoading || isAuthenticated) {
    return (
      <div className="min-h-screen bg-[#050c18] flex items-center justify-center">
        <Shield className="w-6 h-6 text-blue-500 animate-pulse" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#050c18] flex items-center justify-center p-4 relative overflow-hidden">

      {/* Background grid */}
      <div
        className="absolute inset-0 opacity-[0.04]"
        style={{
          backgroundImage:
            "linear-gradient(#1a7fff 1px, transparent 1px), linear-gradient(90deg, #1a7fff 1px, transparent 1px)",
          backgroundSize: "48px 48px",
        }}
      />
      {/* Glow */}
      <div className="absolute top-[-20%] left-1/2 -translate-x-1/2 w-[600px] h-[400px] bg-blue-600/8 rounded-full blur-[120px] pointer-events-none" />

      <div className="relative w-full max-w-[400px]">

        {/* ── Logo ── */}
        <div className="flex items-center justify-center gap-3 mb-8">
          <div className="w-10 h-10 bg-blue-600 rounded-[8px] flex items-center justify-center shadow-lg shadow-blue-900/40">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <p className="text-[18px] font-bold text-white tracking-wide leading-none">AuditScan</p>
            <p className="text-[10px] text-[#2a5070] uppercase tracking-widest mt-0.5">Security Platform</p>
          </div>
        </div>

        {/* ── Card ── */}
        <div className="bg-[#080f1e] border border-[#0f1e30] rounded-[10px] p-8 shadow-2xl">

          <h1 className="text-[16px] font-semibold text-[#c0d8f0] mb-1">
            {mode === "login" ? "Sign in to your account" : "Create an account"}
          </h1>
          <p className="text-[12px] text-[#2a5070] mb-6">
            {mode === "login"
              ? "Enter your credentials to access the security dashboard"
              : "Start scanning targets in minutes"}
          </p>

          <form onSubmit={handleSubmit} autoComplete="off" className="space-y-4">

            {/* Email */}
            <div>
              <label className="block text-[11px] font-medium text-[#3d6080] mb-1.5 uppercase tracking-wide">
                Email address
              </label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#1e3a55]" />
                <input
                  type="email" required autoComplete="off"
                  value={email} onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@company.com"
                  className="w-full bg-[#060d1a] border border-[#0f1e30] rounded-[5px] pl-9 pr-3.5 py-2.5 text-[13px] text-[#b0cce8] placeholder-[#1e3a55] focus:outline-none focus:border-blue-700/60 focus:ring-1 focus:ring-blue-700/30 transition"
                />
              </div>
            </div>

            {/* Password */}
            <div>
              <label className="block text-[11px] font-medium text-[#3d6080] mb-1.5 uppercase tracking-wide">
                Password
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#1e3a55]" />
                <input
                  type={showPass ? "text" : "password"} required autoComplete="new-password"
                  value={password} onChange={(e) => setPassword(e.target.value)}
                  placeholder={mode === "register" ? "Min. 8 characters" : "••••••••"}
                  className="w-full bg-[#060d1a] border border-[#0f1e30] rounded-[5px] pl-9 pr-10 py-2.5 text-[13px] text-[#b0cce8] placeholder-[#1e3a55] focus:outline-none focus:border-blue-700/60 focus:ring-1 focus:ring-blue-700/30 transition"
                />
                <button type="button" onClick={() => setShowPass(!showPass)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-[#1e3a55] hover:text-[#4a8ab5] transition-colors">
                  {showPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Confirm password (register) */}
            {mode === "register" && (
              <div>
                <label className="block text-[11px] font-medium text-[#3d6080] mb-1.5 uppercase tracking-wide">
                  Confirm Password
                </label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#1e3a55]" />
                  <input
                    type={showConfirmPass ? "text" : "password"} required autoComplete="new-password"
                    value={confirmPassword} onChange={(e) => setConfirm(e.target.value)}
                    placeholder="Repeat your password"
                    className={`w-full bg-[#060d1a] border rounded-[5px] pl-9 pr-10 py-2.5 text-[13px] text-[#b0cce8] placeholder-[#1e3a55] focus:outline-none focus:ring-1 transition ${
                      confirmPassword && confirmPassword !== password
                        ? "border-red-800/80 focus:border-red-700 focus:ring-red-700/30"
                        : "border-[#0f1e30] focus:border-blue-700/60 focus:ring-blue-700/30"
                    }`}
                  />
                  <button type="button" onClick={() => setShowConfirm(!showConfirmPass)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-[#1e3a55] hover:text-[#4a8ab5] transition-colors">
                    {showConfirmPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
                {confirmPassword && confirmPassword !== password && (
                  <p className="text-[11px] text-red-400 mt-1">Passwords do not match</p>
                )}
              </div>
            )}

            {/* Remember me */}
            {mode === "login" && (
              <label className="flex items-center gap-2 cursor-pointer select-none">
                <input
                  type="checkbox" checked={rememberMe}
                  onChange={(e) => setRememberMe(e.target.checked)}
                  className="w-3.5 h-3.5 rounded border-[#0f1e30] bg-[#060d1a] accent-blue-500 cursor-pointer"
                />
                <span className="text-[12px] text-[#2a5070]">Keep me signed in</span>
              </label>
            )}

            {/* Error */}
            {error && (
              <div className="flex items-center gap-2 text-red-400 text-[12px] bg-red-950/40 border border-red-800/60 rounded-[5px] px-3 py-2">
                <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                {error}
              </div>
            )}

            {/* Submit */}
            <button
              type="submit" disabled={loading}
              className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold py-2.5 rounded-[5px] text-[13px] transition-colors mt-2"
            >
              {loading
                ? "Please wait…"
                : mode === "login" ? "Sign In" : "Create Account"}
            </button>
          </form>

          {/* Switch mode */}
          <p className="text-center text-[12px] text-[#2a5070] mt-5">
            {mode === "login" ? "Don't have an account? " : "Already have an account? "}
            <button onClick={switchMode} className="text-blue-400 hover:text-blue-300 font-medium transition-colors">
              {mode === "login" ? "Sign up" : "Sign in"}
            </button>
          </p>
        </div>

        {/* Footer note */}
        <p className="text-center text-[11px] text-[#1a3550] mt-5">
          Authorized security testing only · AuditScan IA
        </p>
      </div>
    </div>
  );
}

"use client";

import { useState, FormEvent, useEffect } from "react";
import { useRouter } from "next/navigation";
import { Shield, Eye, EyeOff, AlertCircle, Lock, Mail, ArrowRight, Zap } from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

export default function LoginPage() {
  const router = useRouter();
  const { login, register, isAuthenticated, isLoading } = useAuth();

  useEffect(() => {
    if (!isLoading && isAuthenticated) router.replace("/dashboard");
  }, [isAuthenticated, isLoading, router]);

  const [mode, setMode]               = useState<"login" | "register">("login");
  const [email, setEmail]             = useState("");
  const [password, setPassword]       = useState("");
  const [confirmPassword, setConfirm] = useState("");
  const [showPass, setShowPass]       = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [rememberMe, setRememberMe]   = useState(false);
  const [loading, setLoading]         = useState(false);
  const [error, setError]             = useState("");
  const [focused, setFocused]         = useState<string | null>(null);

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
      <div className="min-h-screen bg-zinc-950 flex items-center justify-center">
        <Shield className="w-6 h-6 text-indigo-400 animate-pulse" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-zinc-950 flex items-center justify-center p-4 relative overflow-hidden">

      {/* Ambient glow blobs */}
      <div className="absolute top-[-20%] left-[-10%] w-[500px] h-[500px] bg-indigo-600/8 rounded-full blur-[120px] pointer-events-none" />
      <div className="absolute bottom-[-20%] right-[-10%] w-[400px] h-[400px] bg-violet-600/6 rounded-full blur-[100px] pointer-events-none" />

      {/* Subtle grid */}
      <div className="absolute inset-0 pointer-events-none" style={{
        backgroundImage: "linear-gradient(rgba(99,102,241,0.04) 1px,transparent 1px),linear-gradient(90deg,rgba(99,102,241,0.04) 1px,transparent 1px)",
        backgroundSize: "48px 48px",
      }} />

      {/* Dot pattern overlay */}
      <div className="absolute inset-0 pointer-events-none" style={{
        backgroundImage: "radial-gradient(rgba(99,102,241,0.12) 1px, transparent 1px)",
        backgroundSize: "24px 24px",
        maskImage: "radial-gradient(ellipse 60% 60% at 50% 50%, black 20%, transparent 100%)",
        WebkitMaskImage: "radial-gradient(ellipse 60% 60% at 50% 50%, black 20%, transparent 100%)",
      }} />

      <div className="relative w-full max-w-[400px] fade-in-up">

        {/* Logo block */}
        <div className="flex flex-col items-center mb-8 gap-3">
          <div className="relative">
            <div className="absolute inset-0 bg-indigo-600/30 rounded-2xl blur-xl" />
            <div className="relative w-14 h-14 bg-indigo-600 rounded-2xl flex items-center justify-center shadow-lg shadow-indigo-950/60">
              <Shield className="w-7 h-7 text-white" />
            </div>
          </div>
          <div className="text-center">
            <p className="text-[20px] font-bold text-zinc-100 tracking-tight">AuditScan IA</p>
            <p className="text-[11px] text-zinc-600 uppercase tracking-[0.2em] mt-0.5">Security Platform</p>
          </div>
        </div>

        {/* Card */}
        <div className="relative bg-zinc-900/80 backdrop-blur-sm border border-zinc-800 rounded-2xl p-7 shadow-2xl shadow-black/50">

          {/* Card inner glow on focus */}
          <div className={cn(
            "absolute inset-0 rounded-2xl border border-indigo-500/0 transition-all duration-500 pointer-events-none",
            focused && "border-indigo-500/15 shadow-[0_0_40px_rgba(99,102,241,0.06)_inset]"
          )} />

          {/* Mode tabs */}
          <div className="flex gap-1 p-1 bg-zinc-800/60 rounded-lg mb-6">
            {(["login", "register"] as const).map((m) => (
              <button
                key={m}
                onClick={() => { setMode(m); setEmail(""); setPassword(""); setConfirm(""); setError(""); }}
                className={cn(
                  "flex-1 py-1.5 rounded-md text-[12px] font-semibold transition-all duration-200",
                  mode === m
                    ? "bg-zinc-700 text-zinc-100 shadow-sm"
                    : "text-zinc-600 hover:text-zinc-400"
                )}
              >
                {m === "login" ? "Sign In" : "Sign Up"}
              </button>
            ))}
          </div>

          <form onSubmit={handleSubmit} autoComplete="off" className="space-y-4">

            {/* Email */}
            <div className="space-y-1.5">
              <label className="text-[11px] font-medium text-zinc-500 uppercase tracking-wide">Email</label>
              <div className={cn(
                "relative rounded-lg transition-all duration-200",
                focused === "email" ? "ring-1 ring-indigo-500/30" : ""
              )}>
                <Mail className={cn(
                  "absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 transition-colors duration-150",
                  focused === "email" ? "text-indigo-400" : "text-zinc-600"
                )} />
                <input
                  type="email" required autoComplete="off"
                  value={email} onChange={(e) => setEmail(e.target.value)}
                  onFocus={() => setFocused("email")}
                  onBlur={() => setFocused(null)}
                  placeholder="analyst@company.com"
                  className="w-full bg-zinc-800/60 border border-zinc-700/80 rounded-lg pl-9 pr-3.5 py-2.5 text-[13px] text-zinc-100 placeholder-zinc-600 outline-none transition-all duration-150 font-mono focus:border-indigo-500/40"
                />
              </div>
            </div>

            {/* Password */}
            <div className="space-y-1.5">
              <label className="text-[11px] font-medium text-zinc-500 uppercase tracking-wide">Password</label>
              <div className={cn(
                "relative rounded-lg transition-all duration-200",
                focused === "password" ? "ring-1 ring-indigo-500/30" : ""
              )}>
                <Lock className={cn(
                  "absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 transition-colors duration-150",
                  focused === "password" ? "text-indigo-400" : "text-zinc-600"
                )} />
                <input
                  type={showPass ? "text" : "password"} required autoComplete="new-password"
                  value={password} onChange={(e) => setPassword(e.target.value)}
                  onFocus={() => setFocused("password")}
                  onBlur={() => setFocused(null)}
                  placeholder={mode === "register" ? "Min. 8 characters" : "••••••••"}
                  className="w-full bg-zinc-800/60 border border-zinc-700/80 rounded-lg pl-9 pr-10 py-2.5 text-[13px] text-zinc-100 placeholder-zinc-600 outline-none transition-all duration-150 focus:border-indigo-500/40"
                />
                <button type="button" onClick={() => setShowPass(!showPass)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-600 hover:text-zinc-400 transition-colors">
                  {showPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Confirm password */}
            {mode === "register" && (
              <div className="space-y-1.5">
                <label className="text-[11px] font-medium text-zinc-500 uppercase tracking-wide">Confirm Password</label>
                <div className={cn(
                  "relative rounded-lg transition-all duration-200",
                  focused === "confirm" ? "ring-1 ring-indigo-500/30" : ""
                )}>
                  <Lock className={cn(
                    "absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 transition-colors duration-150",
                    focused === "confirm" ? "text-indigo-400" : "text-zinc-600"
                  )} />
                  <input
                    type={showConfirm ? "text" : "password"} required autoComplete="new-password"
                    value={confirmPassword} onChange={(e) => setConfirm(e.target.value)}
                    onFocus={() => setFocused("confirm")}
                    onBlur={() => setFocused(null)}
                    placeholder="Repeat your password"
                    className={cn(
                      "w-full bg-zinc-800/60 border rounded-lg pl-9 pr-10 py-2.5 text-[13px] text-zinc-100 placeholder-zinc-600 outline-none transition-all duration-150",
                      confirmPassword && confirmPassword !== password
                        ? "border-red-700/60 focus:border-red-600/50"
                        : "border-zinc-700/80 focus:border-indigo-500/40"
                    )}
                  />
                  <button type="button" onClick={() => setShowConfirm(!showConfirm)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-600 hover:text-zinc-400 transition-colors">
                    {showConfirm ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
                {confirmPassword && confirmPassword !== password && (
                  <p className="text-[11px] text-red-400">Passwords do not match</p>
                )}
              </div>
            )}

            {/* Remember me */}
            {mode === "login" && (
              <label className="flex items-center gap-2 cursor-pointer group">
                <div className={cn(
                  "w-3.5 h-3.5 rounded border flex items-center justify-center transition-all duration-150",
                  rememberMe ? "bg-indigo-600 border-indigo-500" : "border-zinc-600 group-hover:border-zinc-500"
                )}>
                  {rememberMe && <svg viewBox="0 0 10 10" className="w-2 h-2 text-white"><path d="M1.5 5L4 7.5L8.5 2.5" stroke="currentColor" strokeWidth="1.5" fill="none" strokeLinecap="round" strokeLinejoin="round"/></svg>}
                </div>
                <input type="checkbox" checked={rememberMe} onChange={(e) => setRememberMe(e.target.checked)} className="sr-only" />
                <span className="text-[12px] text-zinc-500 group-hover:text-zinc-400 transition-colors">Keep me signed in</span>
              </label>
            )}

            {/* Error */}
            {error && (
              <div className="flex items-center gap-2 text-red-400 text-[12px] bg-red-950/40 border border-red-900/50 rounded-lg px-3 py-2 fade-in">
                <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                {error}
              </div>
            )}

            {/* Submit */}
            <button
              type="submit"
              disabled={loading}
              className={cn(
                "relative w-full py-2.5 rounded-lg text-[13px] font-semibold transition-all duration-200 mt-1 overflow-hidden group",
                "bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white",
                !loading && "shadow-lg shadow-indigo-950/60 hover:shadow-indigo-950/80 btn-glow"
              )}
            >
              <span className="relative flex items-center justify-center gap-2">
                {loading ? (
                  <>
                    <svg className="w-4 h-4 animate-spin" viewBox="0 0 24 24" fill="none">
                      <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" strokeOpacity="0.25"/>
                      <path d="M12 2a10 10 0 0 1 10 10" stroke="currentColor" strokeWidth="3" strokeLinecap="round"/>
                    </svg>
                    Please wait…
                  </>
                ) : (
                  <>
                    {mode === "login" ? "Sign In" : "Create Account"}
                    <ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform duration-150" />
                  </>
                )}
              </span>
            </button>
          </form>

          <p className="text-center text-[12px] text-zinc-600 mt-5">
            {mode === "login" ? "No account? " : "Already registered? "}
            <button onClick={switchMode} className="text-indigo-400 hover:text-indigo-300 font-medium transition-colors">
              {mode === "login" ? "Sign up free" : "Sign in"}
            </button>
          </p>
        </div>

        {/* Feature tags */}
        <div className="flex items-center justify-center gap-3 mt-5 flex-wrap">
          {["8-Phase Pipeline", "21 Microservices", "SOC Reports"].map((tag) => (
            <span key={tag} className="flex items-center gap-1 text-[10px] text-zinc-700 font-mono">
              <Zap className="w-2.5 h-2.5 text-indigo-700" />
              {tag}
            </span>
          ))}
        </div>

        <p className="text-center text-[10px] text-zinc-800 mt-3">
          Authorized security testing only
        </p>
      </div>
    </div>
  );
}

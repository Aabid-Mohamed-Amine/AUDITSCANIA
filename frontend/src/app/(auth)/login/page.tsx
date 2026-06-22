"use client";

import { useState, FormEvent, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/contexts/AuthContext";
import { toast } from "sonner";

export default function LoginPage() {
  const router = useRouter();
  const { login, register, isAuthenticated, isLoading } = useAuth();

  const canvasRef = useRef<HTMLCanvasElement>(null);

  const [mode, setMode]               = useState<"login" | "register">("login");
  const [email, setEmail]             = useState("");
  const [password, setPassword]       = useState("");
  const [confirmPassword, setConfirm] = useState("");
  const [showPass, setShowPass]       = useState(false);
  const [rememberMe, setRememberMe]   = useState(false);
  const [loading, setLoading]         = useState(false);
  const [error, setError]             = useState("");
  const [submitted, setSubmitted]     = useState(false);

  useEffect(() => {
    if (!isLoading && isAuthenticated) router.replace("/dashboard");
  }, [isAuthenticated, isLoading, router]);

  /* Matrix canvas animation */
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const resize = () => {
      canvas.width  = window.innerWidth;
      canvas.height = window.innerHeight;
    };
    resize();

    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$@%&*";
    const fontSize  = 16;
    let columns     = Math.floor(canvas.width / fontSize);
    let drops: number[] = Array.from({ length: columns }, () => 1);

    window.addEventListener("resize", () => {
      resize();
      columns = Math.floor(canvas.width / fontSize);
      drops   = Array.from({ length: columns }, () => 1);
    });

    const draw = () => {
      ctx.fillStyle = "rgba(249, 249, 255, 0.1)";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.fillStyle = "#0051d5";
      ctx.font = `${fontSize}px monospace`;
      drops.forEach((y, i) => {
        const char = alphabet[Math.floor(Math.random() * alphabet.length)];
        ctx.fillText(char, i * fontSize, y * fontSize);
        if (y * fontSize > canvas.height && Math.random() > 0.975) drops[i] = 0;
        drops[i]++;
      });
    };

    const id = setInterval(draw, 60);
    return () => clearInterval(id);
  }, []);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    if (mode === "register" && password !== confirmPassword) { setError("Passwords do not match"); return; }
    if (mode === "register" && password.length < 8) { setError("Password must be at least 8 characters"); return; }
    setLoading(true);
    setSubmitted(true);
    try {
      if (mode === "login") {
        await login(email, password, rememberMe);
        toast.success("Welcome back!");
        router.push("/dashboard");
      } else {
        await register(email, password);
        toast.success("Account created -- please sign in.");
        setMode("login"); setPassword(""); setConfirm(""); setSubmitted(false);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Authentication failed");
      setSubmitted(false);
    } finally {
      setLoading(false);
    }
  };

  if (isLoading || isAuthenticated) {
    return (
      <div
        className="min-h-screen flex items-center justify-center"
        style={{ background: "var(--sc-bg)", fontFamily: "'Geist', sans-serif" }}
      >
        <span className="material-symbols-outlined animate-pulse" style={{ fontSize: 32, color: "var(--sc-brand)" }}>
          shield_lock
        </span>
      </div>
    );
  }

  return (
    <div
      className="relative min-h-screen overflow-hidden flex items-center justify-center p-4"
      style={{ background: "var(--sc-bg)", fontFamily: "'Geist', sans-serif", color: "var(--sc-on)" }}
    >
      {/* Background layers */}
      <div className="fixed inset-0 z-0 pointer-events-none">
        <div className="absolute inset-0 opacity-10">
          <div
            className="w-full h-full"
            style={{ background: "radial-gradient(ellipse at center, #e7eefe 0%, transparent 70%)" }}
          />
        </div>
        <canvas
          ref={canvasRef}
          className="absolute inset-0 opacity-[0.04]"
          style={{ mixBlendMode: "multiply" }}
        />
      </div>

      {/* Card */}
      <div className="relative z-10 w-full max-w-md fade-in-up">

        {/* Brand header */}
        <div className="text-center mb-10">
          <div
            className="inline-flex items-center justify-center p-3 rounded-xl mb-6 relative overflow-hidden shadow-sm"
            style={{
              background: "var(--sc-surface)",
              border: "1px solid var(--sc-border)",
            }}
          >
            <div className="scan-line-anim" />
            <span
              className="material-symbols-outlined"
              style={{
                fontSize: 36,
                color: "var(--sc-brand)",
                fontVariationSettings: "'FILL' 1, 'wght' 400",
              }}
            >
              shield_lock
            </span>
          </div>
          <h1
            className="font-bold tracking-tight"
            style={{ fontSize: 24, color: "var(--sc-on)" }}
          >
            AEGIS Pentest
          </h1>
          <p
            className="mt-2 uppercase tracking-widest font-mono"
            style={{ fontSize: 11, color: "var(--sc-on-v)" }}
          >
            Secure Command Access
          </p>
        </div>

        {/* Login card */}
        <div
          className="relative rounded-xl p-8 shadow-xl"
          style={{
            background: "#ffffff",
            border: "1px solid var(--sc-border)",
            boxShadow: "0 8px 32px rgba(0,81,213,0.06), 0 2px 8px rgba(0,0,0,0.04)",
          }}
        >
          {/* Corner accents */}
          <div
            className="absolute top-0 left-0 w-4 h-4 rounded-tl-xl -translate-x-[1px] -translate-y-[1px]"
            style={{ borderTop: "2px solid rgba(0,81,213,0.2)", borderLeft: "2px solid rgba(0,81,213,0.2)" }}
          />
          <div
            className="absolute bottom-0 right-0 w-4 h-4 rounded-br-xl translate-x-[1px] translate-y-[1px]"
            style={{ borderBottom: "2px solid rgba(0,81,213,0.2)", borderRight: "2px solid rgba(0,81,213,0.2)" }}
          />

          {/* Mode tabs */}
          <div
            className="flex gap-1 p-1 rounded-lg mb-6"
            style={{ background: "var(--sc-low)" }}
          >
            {(["login", "register"] as const).map((m) => (
              <button
                key={m}
                type="button"
                onClick={() => { setMode(m); setEmail(""); setPassword(""); setConfirm(""); setError(""); }}
                className="flex-1 py-1.5 rounded-md text-xs font-semibold transition-all duration-200 uppercase tracking-widest"
                style={{
                  background:  mode === m ? "var(--sc-surface)" : "transparent",
                  color:       mode === m ? "var(--sc-on)" : "var(--sc-outline)",
                  boxShadow:   mode === m ? "0 1px 4px rgba(0,0,0,0.08)" : "none",
                  fontFamily:  "'JetBrains Mono', monospace",
                }}
              >
                {m === "login" ? "Sign In" : "Register"}
              </button>
            ))}
          </div>

          <form className="space-y-5" onSubmit={handleSubmit} autoComplete="off">
            {/* Email */}
            <div className="space-y-1.5 group">
              <label
                className="block uppercase tracking-widest font-mono"
                style={{ fontSize: 10, color: "var(--sc-on-v)" }}
              >
                {mode === "login" ? "Authentication_Identity" : "Email"}
              </label>
              <div className="relative flex items-center rounded-lg transition-all">
                <span
                  className="material-symbols-outlined absolute left-3"
                  style={{ fontSize: 18, color: "var(--sc-outline)" }}
                >
                  alternate_email
                </span>
                <input
                  type="email"
                  required
                  autoComplete="off"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="operator@aegis.ops"
                  className="w-full rounded-lg pl-10 pr-4 py-3 text-sm outline-none transition-all"
                  style={{
                    background: "var(--sc-low)",
                    border: "1px solid var(--sc-border)",
                    color: "var(--sc-on)",
                    fontFamily: "'Geist', sans-serif",
                  }}
                  onFocus={(e) => {
                    e.currentTarget.style.borderColor = "var(--sc-brand)";
                    e.currentTarget.style.boxShadow = "0 0 0 3px rgba(0,81,213,0.08)";
                  }}
                  onBlur={(e) => {
                    e.currentTarget.style.borderColor = "var(--sc-border)";
                    e.currentTarget.style.boxShadow = "none";
                  }}
                />
              </div>
            </div>

            {/* Password */}
            <div className="space-y-1.5">
              <div className="flex justify-between items-center">
                <label
                  className="uppercase tracking-widest font-mono"
                  style={{ fontSize: 10, color: "var(--sc-on-v)" }}
                >
                  {mode === "login" ? "Access_Credential" : "Password"}
                </label>
              </div>
              <div className="relative flex items-center rounded-lg">
                <span
                  className="material-symbols-outlined absolute left-3"
                  style={{ fontSize: 18, color: "var(--sc-outline)" }}
                >
                  lock_open
                </span>
                <input
                  type={showPass ? "text" : "password"}
                  required
                  autoComplete="new-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={mode === "register" ? "Min. 8 characters" : "••••••••••••"}
                  className="w-full rounded-lg pl-10 pr-12 py-3 text-sm outline-none transition-all"
                  style={{
                    background: "var(--sc-low)",
                    border: "1px solid var(--sc-border)",
                    color: "var(--sc-on)",
                  }}
                  onFocus={(e) => {
                    e.currentTarget.style.borderColor = "var(--sc-brand)";
                    e.currentTarget.style.boxShadow = "0 0 0 3px rgba(0,81,213,0.08)";
                  }}
                  onBlur={(e) => {
                    e.currentTarget.style.borderColor = "var(--sc-border)";
                    e.currentTarget.style.boxShadow = "none";
                  }}
                />
                <button
                  type="button"
                  onClick={() => setShowPass(!showPass)}
                  className="absolute right-3 transition-colors"
                  style={{ color: "var(--sc-outline)" }}
                >
                  <span className="material-symbols-outlined" style={{ fontSize: 18 }}>
                    {showPass ? "visibility_off" : "visibility"}
                  </span>
                </button>
              </div>
            </div>

            {/* Confirm password (register) */}
            {mode === "register" && (
              <div className="space-y-1.5">
                <label
                  className="uppercase tracking-widest font-mono"
                  style={{ fontSize: 10, color: "var(--sc-on-v)" }}
                >
                  Confirm Password
                </label>
                <div className="relative flex items-center rounded-lg">
                  <span
                    className="material-symbols-outlined absolute left-3"
                    style={{ fontSize: 18, color: "var(--sc-outline)" }}
                  >
                    lock
                  </span>
                  <input
                    type="password"
                    required
                    autoComplete="new-password"
                    value={confirmPassword}
                    onChange={(e) => setConfirm(e.target.value)}
                    placeholder="Repeat password"
                    className="w-full rounded-lg pl-10 pr-4 py-3 text-sm outline-none transition-all"
                    style={{
                      background: "var(--sc-low)",
                      border: `1px solid ${confirmPassword && confirmPassword !== password ? "var(--sc-error)" : "var(--sc-border)"}`,
                      color: "var(--sc-on)",
                    }}
                  />
                </div>
                {confirmPassword && confirmPassword !== password && (
                  <p style={{ fontSize: 11, color: "var(--sc-error)" }}>Passwords do not match</p>
                )}
              </div>
            )}

            {/* Remember me (login) */}
            {mode === "login" && (
              <div className="flex items-center gap-3">
                <input
                  type="checkbox"
                  id="remember"
                  checked={rememberMe}
                  onChange={(e) => setRememberMe(e.target.checked)}
                  className="w-4 h-4 rounded"
                  style={{ accentColor: "var(--sc-brand)" }}
                />
                <label
                  htmlFor="remember"
                  className="cursor-pointer select-none text-sm"
                  style={{ color: "var(--sc-on-v)" }}
                >
                  Keep session persistent
                </label>
              </div>
            )}

            {/* Error */}
            {error && (
              <div
                className="flex items-center gap-2 rounded-lg px-3 py-2 text-xs"
                style={{
                  background: "var(--sc-err-bg)",
                  border: "1px solid rgba(186,26,26,0.2)",
                  color: "var(--sc-err-on)",
                }}
              >
                <span className="material-symbols-outlined" style={{ fontSize: 16 }}>error</span>
                {error}
              </div>
            )}

            {/* Submit */}
            <button
              type="submit"
              disabled={loading}
              className="w-full py-4 rounded-xl flex items-center justify-center gap-2 font-bold transition-all active:scale-[0.98] uppercase tracking-widest disabled:opacity-60"
              style={{
                background: "var(--sc-on)",
                color: "#ffffff",
                boxShadow: "0 4px 16px rgba(0,0,0,0.15)",
                fontSize: 13,
                fontFamily: "'JetBrains Mono', monospace",
              }}
              onMouseEnter={(e) => {
                if (!loading) (e.currentTarget as HTMLElement).style.background = "var(--sc-pc)";
              }}
              onMouseLeave={(e) => {
                if (!loading) (e.currentTarget as HTMLElement).style.background = "var(--sc-on)";
              }}
            >
              {loading ? (
                <>
                  <span className="material-symbols-outlined animate-spin" style={{ fontSize: 18 }}>sync</span>
                  {submitted ? "Validating..." : "Please wait..."}
                </>
              ) : (
                <>
                  <span className="material-symbols-outlined" style={{ fontSize: 18 }}>login</span>
                  {mode === "login" ? "Authorize Access" : "Create Account"}
                </>
              )}
            </button>
          </form>

          {/* Status feedback (visible after submit) */}
          {submitted && !error && (
            <div
              className="mt-5 pt-5 flex items-start gap-3"
              style={{ borderTop: "1px solid var(--sc-border)" }}
            >
              <span
                className="material-symbols-outlined animate-pulse"
                style={{ fontSize: 16, color: "var(--sc-brand)" }}
              >
                terminal
              </span>
              <div className="font-mono" style={{ fontSize: 11, lineHeight: "1.6" }}>
                <p style={{ color: "var(--sc-brand)" }}>Initiating handshake protocol...</p>
                <p className="opacity-70" style={{ color: "var(--sc-on-v)" }}>Validating credentials...</p>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="mt-8 text-center space-y-3">
          <p style={{ fontSize: 13, color: "var(--sc-on-v)", opacity: 0.7 }}>
            Trusted by elite security analysts worldwide.
          </p>
          <div className="flex justify-center gap-6">
            {[
              { icon: "verified_user", label: "SOC2 Type II" },
              { icon: "encrypted",     label: "AES-256 GCM"  },
            ].map(({ icon, label }) => (
              <div key={label} className="flex items-center gap-1.5" style={{ color: "var(--sc-outline)", opacity: 0.6 }}>
                <span className="material-symbols-outlined" style={{ fontSize: 14 }}>{icon}</span>
                <span className="uppercase font-mono" style={{ fontSize: 10 }}>{label}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

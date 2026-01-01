import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Link, useNavigate } from 'react-router-dom';
import { supabase } from '../lib/supabase';

const AuthPage = () => {
  const [view, setView] = useState('login'); // 'login', 'signup', 'forgot-password'
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [message, setMessage] = useState(null);
  const navigate = useNavigate();

  const handleGoogleLogin = async () => {
    try {
      setLoading(true);
      setError(null);
      const { error } = await supabase.auth.signInWithOAuth({
        provider: 'google',
        options: {
          redirectTo: window.location.origin
        }
      });
      if (error) throw error;
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setMessage(null);

    try {
      if (view === 'login') {
        const { error } = await supabase.auth.signInWithPassword({
          email,
          password
        });
        if (error) throw error;
        navigate('/');
      } else if (view === 'signup') {
        if (password !== confirmPassword) {
          throw new Error("Passwords do not match");
        }
        const { error } = await supabase.auth.signUp({
          email,
          password
        });
        if (error) throw error;
        setMessage("Check your email for the confirmation link!");
      } else if (view === 'forgot-password') {
        const { error } = await supabase.auth.resetPasswordForEmail(email, {
          redirectTo: `${window.location.origin}/login`,
        });
        if (error) throw error;
        setMessage("Password reset link sent to your email.");
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const Logo = () => (
    <Link to="/" className="flex items-center gap-3 mb-8 transition-opacity hover:opacity-80">
      <div className="size-12 text-primary">
        <svg fill="none" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
          <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" stroke="#135bec" stroke-linecap="round" stroke-linejoin="round" stroke-width="4"></path>
          <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" stroke="#10b981" stroke-linecap="round" stroke-linejoin="round" stroke-width="4"></path>
        </svg>
      </div>
      <h2 className="text-3xl font-bold leading-tight tracking-tight text-white">
        <b><span className="text-[#10b981]">Good</span></b>
        <b><span className="text-[#135bec]"> Link</span></b>
      </h2>
    </Link>
  );

  return (
    <div className="min-h-screen w-full bg-[#101622] flex flex-col items-center justify-center px-6 py-12 relative overflow-hidden">
      {/* Background Orbs */}
      <div className="absolute top-[-10%] left-[-10%] size-96 bg-primary/20 blur-[120px] rounded-full"></div>
      <div className="absolute bottom-[-10%] right-[-10%] size-96 bg-[#10b981]/10 blur-[120px] rounded-full"></div>

      <div className="relative z-10 w-full max-w-md flex flex-col items-center">
        <Logo />

        <div className="w-full bg-white/5 backdrop-blur-xl border border-white/10 p-8 rounded-3xl shadow-2xl relative">
          <AnimatePresence mode="wait">
            {view === 'login' && (
              <motion.div
                key="login"
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 20 }}
                transition={{ duration: 0.3 }}
                className="flex flex-col gap-6"
              >
                <div className="text-center mb-2">
                  <h1 className="text-2xl font-bold text-white mb-2">Welcome Back</h1>
                  <p className="text-slate-400">Log in to your GoodLink.ai account</p>
                </div>

                {error && (
                  <div className="bg-red-500/10 border border-red-500/20 text-red-500 text-sm p-3 rounded-lg text-center animate-in fade-in zoom-in duration-200">
                    {error}
                  </div>
                )}

                {message && (
                  <div className="bg-green-500/10 border border-green-500/20 text-green-500 text-sm p-3 rounded-lg text-center animate-in fade-in zoom-in duration-200">
                    {message}
                  </div>
                )}

                <form onSubmit={handleSubmit} className="flex flex-col gap-4">
                  <div className="flex flex-col gap-2">
                    <label className="text-sm font-bold text-slate-300 ml-1">Email Address</label>
                    <input 
                      type="email" 
                      placeholder="name@example.com"
                      className="h-12 w-full bg-[#192233] border border-white/10 rounded-xl px-4 text-white focus:outline-none focus:border-primary/50 transition-colors"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      required
                    />
                  </div>
                  <div className="flex flex-col gap-2">
                    <div className="flex justify-between items-center ml-1">
                      <label className="text-sm font-bold text-slate-300">Password</label>
                      <button 
                        type="button"
                        onClick={() => {
                          setView('forgot-password');
                          setError(null);
                          setMessage(null);
                        }}
                        className="text-xs text-primary hover:text-primary/80 font-bold transition-colors"
                      >
                        Forgot?
                      </button>
                    </div>
                    <input 
                      type="password" 
                      placeholder="••••••••"
                      className="h-12 w-full bg-[#192233] border border-white/10 rounded-xl px-4 text-white focus:outline-none focus:border-primary/50 transition-colors"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      required
                    />
                  </div>
                  <button 
                    type="submit" 
                    disabled={loading}
                    className="h-12 w-full bg-primary hover:bg-primary/90 text-white font-bold rounded-xl transition-all shadow-lg shadow-primary/20 mt-2 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                  >
                    {loading && <div className="size-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>}
                    Sign In
                  </button>
                </form>

                <div className="relative flex items-center justify-center my-2">
                  <div className="absolute inset-0 flex items-center"><div className="w-full border-t border-white/10"></div></div>
                  <span className="relative z-10 bg-[#161d2b] px-4 text-xs text-slate-500 font-bold uppercase tracking-widest">Or continue with</span>
                </div>

                <button 
                  onClick={handleGoogleLogin}
                  disabled={loading}
                  className="h-12 w-full bg-white/5 hover:bg-white/10 border border-white/10 text-white font-bold rounded-xl flex items-center justify-center gap-3 transition-all disabled:opacity-50"
                >
                  <svg className="size-5" viewBox="0 0 24 24">
                    <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
                    <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
                    <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z" fill="#FBBC05"/>
                    <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
                  </svg>
                  Google
                </button>

                <p className="text-center text-sm text-slate-400 mt-2">
                  Don't have an account? {' '}
                  <button onClick={() => { setView('signup'); setError(null); setMessage(null); }} className="text-primary hover:text-primary/80 font-bold transition-colors underline-offset-4 hover:underline">
                    Create one for free
                  </button>
                </p>
              </motion.div>
            )}

            {view === 'signup' && (
              <motion.div
                key="signup"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                transition={{ duration: 0.3 }}
                className="flex flex-col gap-6"
              >
                <div className="text-center mb-2">
                  <h1 className="text-2xl font-bold text-white mb-2">Join GoodLink.ai</h1>
                  <p className="text-slate-400">Start securing your data today</p>
                </div>

                {error && (
                  <div className="bg-red-500/10 border border-red-500/20 text-red-500 text-sm p-3 rounded-lg text-center">
                    {error}
                  </div>
                )}

                {message && (
                  <div className="bg-green-500/10 border border-green-500/20 text-green-500 text-sm p-3 rounded-lg text-center">
                    {message}
                  </div>
                )}

                <form onSubmit={handleSubmit} className="flex flex-col gap-4">
                  <div className="flex flex-col gap-2">
                    <label className="text-sm font-bold text-slate-300 ml-1">Email Address</label>
                    <input 
                      type="email" 
                      placeholder="name@example.com"
                      className="h-12 w-full bg-[#192233] border border-white/10 rounded-xl px-4 text-white focus:outline-none focus:border-primary/50 transition-colors"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      required
                    />
                  </div>
                  <div className="flex flex-col gap-2">
                    <label className="text-sm font-bold text-slate-300 ml-1">Password</label>
                    <input 
                      type="password" 
                      placeholder="••••••••"
                      className="h-12 w-full bg-[#192233] border border-white/10 rounded-xl px-4 text-white focus:outline-none focus:border-primary/50 transition-colors"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      required
                    />
                  </div>
                  <div className="flex flex-col gap-2">
                    <label className="text-sm font-bold text-slate-300 ml-1">Confirm Password</label>
                    <input 
                      type="password" 
                      placeholder="••••••••"
                      className="h-12 w-full bg-[#192233] border border-white/10 rounded-xl px-4 text-white focus:outline-none focus:border-primary/50 transition-colors"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      required
                    />
                  </div>
                  <button type="submit" disabled={loading} className="h-12 w-full bg-primary hover:bg-primary/90 text-white font-bold rounded-xl transition-all shadow-lg shadow-primary/20 mt-2 disabled:opacity-50 flex items-center justify-center gap-2">
                    {loading && <div className="size-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>}
                    Create Account
                  </button>
                </form>

                <div className="relative flex items-center justify-center my-2">
                  <div className="absolute inset-0 flex items-center"><div className="w-full border-t border-white/10"></div></div>
                  <span className="relative z-10 bg-[#161d2b] px-4 text-xs text-slate-500 font-bold uppercase tracking-widest">Or join with</span>
                </div>

                <button onClick={handleGoogleLogin} disabled={loading} className="h-12 w-full bg-white/5 hover:bg-white/10 border border-white/10 text-white font-bold rounded-xl flex items-center justify-center gap-3 transition-all disabled:opacity-50">
                  <svg className="size-5" viewBox="0 0 24 24">
                    <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
                    <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
                    <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z" fill="#FBBC05"/>
                    <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
                  </svg>
                  Google
                </button>

                <p className="text-center text-sm text-slate-400 mt-2">
                  Already have an account? {' '}
                  <button onClick={() => { setView('login'); setError(null); setMessage(null); }} className="text-primary hover:text-primary/80 font-bold transition-colors underline-offset-4 hover:underline">
                    Sign In
                  </button>
                </p>
              </motion.div>
            )}

            {view === 'forgot-password' && (
              <motion.div
                key="forgot"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, y: -10 }}
                transition={{ duration: 0.3 }}
                className="flex flex-col gap-6"
              >
                <div className="text-center mb-2">
                  <h1 className="text-2xl font-bold text-white mb-2">Reset Password</h1>
                  <p className="text-slate-400">We'll send you recovery instructions</p>
                </div>

                {error && (
                  <div className="bg-red-500/10 border border-red-500/20 text-red-500 text-sm p-3 rounded-lg text-center">
                    {error}
                  </div>
                )}

                {message && (
                  <div className="bg-green-500/10 border border-green-500/20 text-green-500 text-sm p-3 rounded-lg text-center">
                    {message}
                  </div>
                )}

                <form onSubmit={handleSubmit} className="flex flex-col gap-6">
                  <div className="flex flex-col gap-2">
                    <label className="text-sm font-bold text-slate-300 ml-1">Email Address</label>
                    <input 
                      type="email" 
                      placeholder="name@example.com"
                      className="h-12 w-full bg-[#192233] border border-white/10 rounded-xl px-4 text-white focus:outline-none focus:border-primary/50 transition-colors"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      required
                    />
                  </div>
                  <button type="submit" disabled={loading} className="h-12 w-full bg-primary hover:bg-primary/90 text-white font-bold rounded-xl transition-all shadow-lg shadow-primary/20 flex items-center justify-center gap-2">
                    {loading && <div className="size-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>}
                    Send Link
                  </button>
                </form>

                <button 
                  onClick={() => { setView('login'); setError(null); setMessage(null); }}
                  className="flex items-center justify-center gap-2 text-sm text-slate-400 hover:text-white transition-colors group"
                >
                  <span className="material-symbols-outlined text-sm transition-transform group-hover:-translate-x-1">arrow_back</span>
                  Back to Login
                </button>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        <div className="mt-8 text-xs text-slate-500 text-center max-w-[280px]">
          By continuing, you agree to GoodLink's <a href="#" className="underline">Terms of Service</a> and <a href="#" className="underline">Privacy Policy</a>.
        </div>
      </div>
    </div>
  );
};

export default AuthPage;

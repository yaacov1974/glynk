import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { supabase } from '../lib/supabase';

const Navbar = () => {
  const [isOpen, setIsOpen] = useState(false);
  const [user, setUser] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    // Get initial user
    supabase.auth.getUser().then(({ data: { user } }) => {
      setUser(user);
    });

    // Listen for auth changes
    const { data: { subscription } } = supabase.auth.onAuthStateChange((event, session) => {
      setUser(session?.user ?? null);
      if (event === 'SIGNED_OUT') {
        navigate('/');
      }
    });

    return () => subscription.unsubscribe();
  }, [navigate]);

  const handleLogout = async () => {
    await supabase.auth.signOut();
    setIsOpen(false);
  };

  const navLinks = [
    { name: 'Features', href: '#features' },
    { name: 'Pricing', href: '#pricing' },
    { name: 'Resources', href: '#resources' },
  ];

  return (
    <header className="sticky top-0 z-50 flex flex-col border-b border-solid border-slate-200 dark:border-[#232f48] bg-background-light/80 dark:bg-background-dark/80 backdrop-blur-md">
      <div className="flex items-center justify-between px-6 py-4 lg:px-20">
        <Link to="/" className="flex items-center gap-3 text-white transition-opacity hover:opacity-80">
          <div className="size-10 text-primary">
            <svg fill="none" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
              <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" stroke="#135bec" strokeLinecap="round" strokeLinejoin="round" strokeWidth="3"></path>
              <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" stroke="#10b981" strokeLinecap="round" strokeLinejoin="round" strokeWidth="3"></path>
            </svg>
          </div>
          <h2 className="text-3xl font-bold leading-tight tracking-tight">
            <b><span className="text-[#10b981]">Good</span></b>
            <b><span className="text-[#135bec]"> Link</span></b>
          </h2>
        </Link>

        {/* Desktop Navigation */}
        <div className="hidden md:flex flex-1 justify-center">
          <div className="flex items-center gap-9">
            {navLinks.map((link) => (
              <a 
                key={link.name}
                className="text-slate-600 dark:text-slate-300 hover:text-primary dark:hover:text-primary transition-colors text-sm font-medium leading-normal" 
                href={link.href}
              >
                {link.name}
              </a>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Action Buttons - Hidden on mobile, shown in menu */}
          <div className="hidden sm:flex items-center gap-2">
            {user ? (
              <>
                <Link
                  to="/dashboard"
                  className="flex min-w-[84px] cursor-pointer items-center justify-center overflow-hidden rounded-lg h-10 px-4 bg-primary text-white hover:bg-primary/90 text-sm font-bold leading-normal tracking-[0.015em] transition-colors"
                >
                  <span className="truncate">Dashboard</span>
                </Link>
                <button 
                  onClick={handleLogout}
                  className="flex min-w-[84px] cursor-pointer items-center justify-center overflow-hidden rounded-lg h-10 px-4 bg-slate-200 dark:bg-[#232f48] hover:bg-slate-300 dark:hover:bg-[#324467] text-slate-900 dark:text-white text-sm font-bold leading-normal tracking-[0.015em] transition-colors"
                >
                  <span className="truncate">Logout</span>
                </button>
              </>
            ) : (
              <Link to="/login" className="flex min-w-[84px] cursor-pointer items-center justify-center overflow-hidden rounded-lg h-10 px-4 bg-primary hover:bg-primary/90 text-white text-sm font-bold leading-normal tracking-[0.015em] transition-colors shadow-lg shadow-primary/30">
                <span className="truncate">Login</span>
              </Link>
            )}
          </div>

          {/* Hamburger Menu Token */}
          <button 
            onClick={() => setIsOpen(!isOpen)}
            className="flex md:hidden items-center justify-center size-10 rounded-lg text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-[#232f48] transition-colors"
          >
            <span className="material-symbols-outlined text-2xl">
              {isOpen ? 'close' : 'menu'}
            </span>
          </button>
        </div>
      </div>

      {/* Mobile Menu Overlay with Smooth Animations */}
      <AnimatePresence mode="wait">
        {isOpen && (
          <motion.div 
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25, ease: [0.4, 0, 0.2, 1] }}
            className="md:hidden flex flex-col border-t border-slate-200 dark:border-[#232f48] bg-background-light dark:bg-background-dark overflow-hidden"
          >
            <motion.div 
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              transition={{ duration: 0.2, delay: 0.05 }}
              className="p-6 flex flex-col gap-6"
            >
          <div className="flex flex-col gap-4">
            {navLinks.map((link) => (
              <a 
                key={link.name}
                onClick={() => setIsOpen(false)}
                className="text-slate-900 dark:text-white hover:text-primary dark:hover:text-primary transition-colors text-lg font-bold" 
                href={link.href}
              >
                {link.name}
              </a>
            ))}
            {/* Mobile Dashboard Link when logged in */}
            {user && (
              <Link 
                to="/dashboard"
                onClick={() => setIsOpen(false)}
                className="text-slate-900 dark:text-white hover:text-primary dark:hover:text-primary transition-colors text-lg font-bold"
              >
                Dashboard
              </Link>
            )}
          </div>
          <div className="flex flex-col gap-3 pt-6 border-t border-slate-200 dark:border-[#232f48]">
            {user ? (
              <button 
                onClick={() => {
                  handleLogout();
                  setIsOpen(false);
                }}
                className="flex w-full cursor-pointer items-center justify-center rounded-lg h-12 bg-slate-200 dark:bg-[#232f48] text-slate-900 dark:text-white font-bold transition-colors"
              >
                Logout
              </button>
            ) : (
              <Link to="/login" onClick={() => setIsOpen(false)} className="flex w-full cursor-pointer items-center justify-center rounded-lg h-12 bg-primary text-white font-bold transition-colors shadow-lg shadow-primary/30">
                Login
              </Link>
            )}
            </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </header>
  );
};

export default Navbar;

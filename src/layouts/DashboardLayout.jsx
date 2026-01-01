import React, { useState } from 'react';
import { Outlet, Link } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import Sidebar from '../components/dashboard/Sidebar';

const DashboardLayout = () => {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  return (
    <div className="flex min-h-screen bg-[#0b0f19]">
      {/* Desktop Sidebar */}
      <div className="hidden lg:block fixed inset-y-0 left-0 z-50">
        <Sidebar className="w-64" />
      </div>

      {/* Main Content Area */}
      <div className="flex-1 lg:ml-64 flex flex-col min-h-screen">
         {/* Mobile Header */}
        <header className="lg:hidden h-16 bg-[#101622] border-b border-[#232f48] flex items-center justify-between px-4 sticky top-0 z-40">
           <Link to="/" className="flex items-center gap-2">
             <div className="size-8 text-primary">
                <svg fill="none" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                  <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" stroke="#135bec" strokeLinecap="round" strokeLinejoin="round" strokeWidth="3"></path>
                  <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" stroke="#10b981" strokeLinecap="round" strokeLinejoin="round" strokeWidth="3"></path>
                </svg>
              </div>
              <h2 className="text-xl font-bold leading-tight tracking-tight">
                <b><span className="text-[#10b981]">Good</span></b>
                <b><span className="text-[#135bec]"> Link</span></b>
              </h2>
           </Link>
           
           <button onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)} className="text-white p-2">
             <span className="material-symbols-outlined">{isMobileMenuOpen ? 'close' : 'menu'}</span>
           </button>
        </header>

        {/* Mobile Sidebar Overlay with Smooth Animations */}
        <AnimatePresence>
          {isMobileMenuOpen && (
            <div className="lg:hidden fixed inset-0 z-50">
              {/* Backdrop */}
              <motion.div 
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.3 }}
                className="absolute inset-0 bg-black/80 backdrop-blur-sm" 
                onClick={() => setIsMobileMenuOpen(false)}
              />
              
              {/* Sidebar Container */}
              <motion.div 
                initial={{ x: '-100%' }}
                animate={{ x: 0 }}
                exit={{ x: '-100%' }}
                transition={{ duration: 0.3, ease: 'easeInOut' }}
                className="absolute left-0 top-0 bottom-0 w-64 bg-[#101622] shadow-2xl"
              >
                <div className="flex justify-between items-center p-4 border-b border-[#232f48]">
                  <span className="text-white font-bold ml-2">Menu</span>
                  <button onClick={() => setIsMobileMenuOpen(false)} className="text-slate-400 hover:text-white">
                    <span className="material-symbols-outlined">close</span>
                  </button>
                </div>
                <Sidebar className="w-full h-full border-none pt-2" onLinkClick={() => setIsMobileMenuOpen(false)} />
              </motion.div>
            </div>
          )}
        </AnimatePresence>

        <main className="flex-1 p-4 lg:p-6 overflow-y-auto">
          <Outlet />
        </main>
      </div>
    </div>
  );
};

export default DashboardLayout;

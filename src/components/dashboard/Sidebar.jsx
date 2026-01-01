import React from 'react';
import { NavLink, useNavigate, Link } from 'react-router-dom';
import { supabase } from '../../lib/supabase';

const sidebarLinks = [
  { name: 'Overview', href: '/dashboard', icon: 'dashboard' },
  { name: 'Link Manager', href: '/dashboard/links', icon: 'link' },
  { name: 'Pixels', href: '/dashboard/pixels', icon: 'ads_click' },
  { name: 'Domains', href: '/dashboard/domains', icon: 'public' },
  { name: 'Analytics', href: '/dashboard/analytics', icon: 'insights' },
];

const Sidebar = ({ className = "", onLinkClick }) => {
  const navigate = useNavigate();

  const handleLogout = async () => {
    // Close mobile menu if open
    if (onLinkClick) {
      onLinkClick();
    }
    // Navigate to homepage first to avoid ProtectedRoute redirecting to /login
    navigate('/');
    await supabase.auth.signOut();
  };

  // Base classes with default width if not overridden
  const baseClasses = `flex flex-col bg-[#101622] border-r border-[#232f48] pt-6 ${className.includes('w-') ? '' : 'w-64'} ${className.includes('h-') ? '' : 'h-screen'} ${className}`;

  return (
    <aside className={baseClasses}>
      <div className="px-6 mb-8">
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
      </div>

      <nav className="flex-1 px-3 flex flex-col gap-1 overflow-y-auto">
        {sidebarLinks.map((link) => (
          <NavLink
            key={link.name}
            to={link.href}
            end={link.href === '/dashboard'} // Only match exact path for Overview
            onClick={onLinkClick}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-3 rounded-xl text-sm font-medium transition-all duration-200 ${
                isActive
                  ? 'bg-primary text-white shadow-lg shadow-primary/20'
                  : 'text-slate-400 hover:text-white hover:bg-white/5'
              }`
            }
          >
            <span className="material-symbols-outlined text-[20px]">{link.icon}</span>
            {link.name}
          </NavLink>
        ))}
      </nav>

      <div className="p-4 border-t border-[#232f48] flex flex-col gap-2">
        <div className="flex items-center gap-3 px-3 py-2">
            <div className="size-8 rounded-full bg-gradient-to-tr from-primary to-[#10b981] flex items-center justify-center text-white font-bold text-xs">
                U
            </div>
            <div className="flex flex-col">
                <span className="text-sm font-bold text-white">User</span>
                <span className="text-xs text-slate-500">Free Plan</span>
            </div>
        </div>
        
        <button 
          onClick={handleLogout}
          className="flex items-center justify-center gap-3 px-3 py-2 w-full text-slate-400 hover:text-white hover:bg-white/5 rounded-xl transition-all duration-200 text-sm font-medium"
        >
          <span className="material-symbols-outlined text-[20px]">logout</span>
          Logout
        </button>
      </div>
    </aside>
  );
};

export default Sidebar;

import React from 'react';

const Footer = () => {
  return (
    <footer className="border-t border-slate-200 dark:border-[#232f48] bg-white dark:bg-[#111722] py-12 px-6">
      <div className="mx-auto max-w-[1200px]">
        <div className="grid grid-cols-2 gap-8 md:grid-cols-4 lg:grid-cols-5">
          <div className="col-span-2 lg:col-span-2 flex flex-col gap-4">
            <a href="/" className="flex items-center gap-3 text-white transition-opacity hover:opacity-80">
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
            </a>
            <p className="text-sm text-slate-500 dark:text-slate-400 max-w-xs">
              The advanced link management platform for high-performance marketers. Track, optimize, and scale.
            </p>
          </div>
          <div className="flex flex-col gap-4">
            <h4 className="font-bold text-slate-900 dark:text-white">Product</h4>
            <a className="text-sm text-slate-500 dark:text-slate-400 hover:text-primary transition-colors" href="#">Features</a>
            <a className="text-sm text-slate-500 dark:text-slate-400 hover:text-primary transition-colors" href="#">Pricing</a>
            <a className="text-sm text-slate-500 dark:text-slate-400 hover:text-primary transition-colors" href="#">Integrations</a>
            <a className="text-sm text-slate-500 dark:text-slate-400 hover:text-primary transition-colors" href="#">API</a>
          </div>
          <div className="flex flex-col gap-4">
            <h4 className="font-bold text-slate-900 dark:text-white">Resources</h4>
            <a className="text-sm text-slate-500 dark:text-slate-400 hover:text-primary transition-colors" href="#">Documentation</a>
            <a className="text-sm text-slate-500 dark:text-slate-400 hover:text-primary transition-colors" href="#">Blog</a>
            <a className="text-sm text-slate-500 dark:text-slate-400 hover:text-primary transition-colors" href="#">Community</a>
            <a className="text-sm text-slate-500 dark:text-slate-400 hover:text-primary transition-colors" href="#">Help Center</a>
          </div>
          <div className="flex flex-col gap-4">
            <h4 className="font-bold text-slate-900 dark:text-white">Company</h4>
            <a className="text-sm text-slate-500 dark:text-slate-400 hover:text-primary transition-colors" href="#">About</a>
            <a className="text-sm text-slate-500 dark:text-slate-400 hover:text-primary transition-colors" href="#">Careers</a>
            <a className="text-sm text-slate-500 dark:text-slate-400 hover:text-primary transition-colors" href="#">Legal</a>
            <a className="text-sm text-slate-500 dark:text-slate-400 hover:text-primary transition-colors" href="#">Contact</a>
          </div>
        </div>
        <div className="mt-12 border-t border-slate-200 dark:border-[#232f48] pt-8 flex flex-col md:flex-row justify-between items-center gap-4">
          <p className="text-sm text-slate-500 dark:text-slate-400">© 2024 GoodLink.ai. All rights reserved.</p>
          <div className="flex gap-4">
            <a className="text-slate-400 hover:text-primary transition-colors" href="#"><span className="material-symbols-outlined">thumb_up</span></a>
            <a className="text-slate-400 hover:text-primary transition-colors" href="#"><span className="material-symbols-outlined">share</span></a>
            <a className="text-slate-400 hover:text-primary transition-colors" href="#"><span className="material-symbols-outlined">mail</span></a>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;

import React from 'react';
import { Routes, Route } from 'react-router-dom';
import Homepage from './pages/Homepage';
import AuthPage from './pages/AuthPage';
import { supabase } from './lib/supabase';

function App() {
  if (!supabase) {
    return (
      <div className="h-screen w-full bg-[#101622] flex items-center justify-center text-white px-6">
        <div className="max-w-md text-center">
          <h1 className="text-2xl font-bold text-red-500 mb-4">Configuration Required</h1>
          <p className="text-slate-400 mb-6">
            Supabase credentials are missing. Please add 
            <code className="bg-slate-800 px-2 py-1 rounded text-primary mx-1">VITE_SUPABASE_URL</code>
            and
            <code className="bg-slate-800 px-2 py-1 rounded text-primary mx-1">VITE_SUPABASE_ANON_KEY</code>
            to your Vercel project settings.
          </p>
          <a href="https://vercel.com/docs/projects/environment-variables" className="text-primary hover:underline" target="_blank">View Vercel Documentation &rarr;</a>
        </div>
      </div>
    );
  }

  return (
    <Routes>
      <Route path="/" element={<Homepage />} />
      <Route path="/login" element={<AuthPage />} />
    </Routes>
  );
}

export default App;

import React from 'react';

const CTASection = () => {
  return (
    <section id="pricing" className="py-20 px-6">
      <div className="mx-auto max-w-4xl rounded-2xl bg-primary px-6 py-16 text-center shadow-2xl relative overflow-hidden">
        <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjAiIGhlaWdodD0iMjAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PGNpcmNsZSBjeD0iMSIgY3k9IjEiIHI9IjEiIGZpbGw9InJnYmEoMjU1LDI1NSwyNTUsMC4xKSIvPjwvc3ZnPg==')] opacity-30"></div>
        <div className="relative z-10 flex flex-col items-center gap-6">
          <h2 className="text-3xl font-black text-white md:text-5xl">Ready to Maximize Your Profits?</h2>
          <p className="max-w-2xl text-lg text-white/90">Join the thousands of affiliate marketers who are scaling their campaigns with GoodLink.ai.</p>
          <div className="flex flex-wrap justify-center gap-4 pt-4">
            <button className="rounded-lg bg-white px-8 py-4 text-base font-bold text-primary hover:bg-slate-100 transition-colors shadow-lg">
              Get Started Now
            </button>
            <button className="rounded-lg border border-white/30 bg-primary/20 px-8 py-4 text-base font-bold text-white hover:bg-primary/30 transition-colors">
              Schedule Demo
            </button>
          </div>
        </div>
      </div>
    </section>
  );
};

export default CTASection;

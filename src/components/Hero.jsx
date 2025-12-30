import React from 'react';
import { motion } from 'framer-motion';

const Hero = () => {
  return (
    <section className="relative px-6 py-12 md:px-20 lg:py-24 overflow-hidden">
      <div className="layout-content-container mx-auto max-w-[1200px] flex flex-col">
        <div className="flex flex-col gap-10 lg:flex-row items-center">
          {/* Hero Text */}
          <motion.div 
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6, ease: "easeOut" }}
            className="flex flex-col gap-8 flex-1 text-center lg:text-left"
          >
            <div className="flex flex-col gap-4">
              <h1 className="text-slate-900 dark:text-white text-4xl font-black leading-tight tracking-tight md:text-5xl lg:text-6xl">
                Own Your Data. <br />
                <span className="text-primary">Secure Your Links.</span> <br />
                Maximize Profits.
              </h1>
              <h2 className="text-slate-600 dark:text-slate-400 text-lg font-normal leading-relaxed md:text-xl max-w-2xl mx-auto lg:mx-0">
                The ultimate link management ecosystem for elite affiliate marketers and media buyers. Track every click, pixel, and conversion with precision.
              </h2>
            </div>
            <div className="flex flex-wrap gap-4 justify-center lg:justify-start">
              <button className="flex h-12 min-w-[140px] cursor-pointer items-center justify-center rounded-lg bg-primary hover:bg-primary/90 px-6 text-white text-base font-bold transition-all shadow-lg shadow-primary/25">
                Get Started for Free
              </button>
              <button className="flex h-12 min-w-[140px] cursor-pointer items-center justify-center rounded-lg bg-slate-200 dark:bg-[#232f48] hover:bg-slate-300 dark:hover:bg-[#324467] px-6 text-slate-900 dark:text-white text-base font-bold transition-all">
                View Demo
              </button>
            </div>
            <div className="flex items-center gap-2 justify-center lg:justify-start text-sm text-slate-500 dark:text-slate-400">
              <span className="material-symbols-outlined text-lg">check_circle</span>
              <span>No credit card required</span>
              <span className="mx-2">•</span>
              <span className="material-symbols-outlined text-lg">bolt</span>
              <span>Setup in 2 minutes</span>
            </div>
          </motion.div>
          {/* Hero Image */}
          <motion.div 
            initial={{ opacity: 0, scale: 0.95 }}
            whileInView={{ opacity: 1, scale: 1 }}
            viewport={{ once: true }}
            transition={{ duration: 0.8, delay: 0.2 }}
            className="w-full flex-1 max-w-[600px] lg:max-w-none"
          >
            <div 
              className="w-full aspect-video bg-center bg-no-repeat bg-cover rounded-xl shadow-2xl shadow-primary/20 border border-slate-200 dark:border-[#232f48] overflow-hidden relative group" 
              style={{ backgroundImage: 'url("https://lh3.googleusercontent.com/aida-public/AB6AXuBoNfDCiWZcsItO-4obvc0B3RctHB51VHAk81kcYxmCzu4tHnj4izCgl27MwXdx2SO_Cv71ECszSAwKrm8RmIL_8P8UElStEyOQA16k2kmhOiyEHhHhDV-AoHikH0yTH2uSYyZlehHOHIB5S0yeGmz4slyaQZVW47nrrcDI_C3ZjGyKVE91_RV1SsWBoVBRcmGYfV8sAwzAsLsAubZthf2ELSOqB5iUyVJTJZCoCe20IcHEervV9_C0OB4Ymk8fGMVh3ku54y5Bt8o")' }}
            >
              <div className="absolute inset-0 bg-gradient-to-t from-background-light dark:from-background-dark/80 to-transparent"></div>
              {/* Floating Card 1 */}
              <motion.div 
                animate={{ y: [0, -10, 0] }}
                transition={{ duration: 4, repeat: Infinity, ease: "easeInOut" }}
                className="absolute top-4 right-4 sm:top-10 sm:right-10 bg-white/10 dark:bg-[#192233]/90 backdrop-blur-md p-3 sm:p-4 rounded-lg border border-white/20 dark:border-[#324467] shadow-xl w-32 sm:w-48"
              >
                <div className="flex items-center gap-2 sm:gap-3 mb-1 sm:mb-2">
                  <div className="size-6 sm:size-8 rounded-full bg-green-500/20 flex items-center justify-center text-green-500">
                    <span className="material-symbols-outlined text-[12px] sm:text-sm">trending_up</span>
                  </div>
                  <div>
                    <div className="text-[8px] sm:text-[10px] uppercase text-slate-400 font-bold">Conv. Rate</div>
                    <div className="text-xs sm:text-sm font-bold text-white">+12.4%</div>
                  </div>
                </div>
                <div className="h-0.5 sm:h-1 w-full bg-slate-700 rounded-full overflow-hidden">
                  <div className="h-full bg-green-500 w-[70%]"></div>
                </div>
              </motion.div>
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
};

export default Hero;

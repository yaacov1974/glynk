import React from 'react';
import Navbar from '../components/Navbar';
import Hero from '../components/Hero';
import SocialProof from '../components/SocialProof';
import Features from '../components/Features';
import AnalyticsSection from '../components/AnalyticsSection';
import CTASection from '../components/CTASection';
import Footer from '../components/Footer';

const Homepage = () => {
  return (
    <div className="relative flex min-h-screen w-full flex-col">
      <Navbar />
      <main className="flex-1">
        <Hero />
        <SocialProof />
        <Features />
        <AnalyticsSection />
        <CTASection />
      </main>
      <Footer />
    </div>
  );
};

export default Homepage;

import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { supabase } from '../../../lib/supabase';
import { checkUrlSafety } from '../../../lib/urlSafetyCheck';

// Utility function to fetch page title from URL
const fetchPageTitle = async (url) => {
  try {
    // Validate URL first
    new URL(url);
    
    // Use a CORS proxy to fetch the page
    const proxyUrl = `https://api.allorigins.win/get?url=${encodeURIComponent(url)}`;
    const response = await fetch(proxyUrl, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
    });
    
    if (!response.ok) {
      throw new Error('Failed to fetch page');
    }
    
    const data = await response.json();
    
    if (data.contents) {
      // Parse HTML to extract title
      const parser = new DOMParser();
      const doc = parser.parseFromString(data.contents, 'text/html');
      const title = doc.querySelector('title')?.textContent || '';
      return title.trim();
    }
    return '';
  } catch (error) {
    console.error('Error fetching page title:', error);
    // Return empty string on error - user can manually enter name
    return '';
  }
};

const Step1FastTrack = ({ formData, updateFormData, generateRandomSlug, onQuickCreate, onSafetyCheckUpdate }) => {
  const [domains, setDomains] = useState(['goodlink.ai']);
  const [loadingDomains, setLoadingDomains] = useState(false);
  const [fetchingTitle, setFetchingTitle] = useState(false);
  const [safetyCheck, setSafetyCheck] = useState({
    loading: false,
    isSafe: null,
    threatType: null,
    error: null,
  });

  useEffect(() => {
    const fetchDomains = async () => {
      setLoadingDomains(true);
      try {
        const { data: { user } } = await supabase.auth.getUser();
        if (user) {
          // TODO: Fetch from domains table when implemented
          setDomains(['goodlink.ai']);
        }
      } catch (error) {
        console.error('Error fetching domains:', error);
      } finally {
        setLoadingDomains(false);
      }
    };
    fetchDomains();
  }, []);

  // Helper function to normalize URL (add https:// if missing)
  const normalizeUrl = (urlString) => {
    if (!urlString || !urlString.trim()) return null;
    
    const trimmed = urlString.trim();
    
    // If already has protocol, return as is
    if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
      return trimmed;
    }
    
    // Add https:// if missing
    return `https://${trimmed}`;
  };

  // Safety check function - called when user leaves the field
  const performSafetyCheck = async () => {
    if (!formData.targetUrl || !formData.targetUrl.trim()) {
      setSafetyCheck({ loading: false, isSafe: null, threatType: null, error: null });
      // Reset safety in parent
      if (onSafetyCheckUpdate) {
        onSafetyCheckUpdate({ isSafe: null, threatType: null });
      }
      return;
    }

    // Normalize URL (add https:// if missing)
    const normalizedUrl = normalizeUrl(formData.targetUrl);
    if (!normalizedUrl) {
      setSafetyCheck({ loading: false, isSafe: null, threatType: null, error: null });
      return;
    }

    // Validate URL format
    try {
      new URL(normalizedUrl);
    } catch {
      setSafetyCheck({ loading: false, isSafe: null, threatType: null, error: 'Invalid URL format' });
      if (onSafetyCheckUpdate) {
        onSafetyCheckUpdate({ isSafe: null, threatType: null });
      }
      return;
    }

    // Perform safety check with normalized URL
    setSafetyCheck(prev => ({ ...prev, loading: true }));
    const result = await checkUrlSafety(normalizedUrl);
    const safetyState = {
      loading: false,
      isSafe: result.isSafe,
      threatType: result.threatType,
      error: result.error || null,
    };
    setSafetyCheck(safetyState);
    
    // Update parent component with safety check result
    if (onSafetyCheckUpdate) {
      onSafetyCheckUpdate({
        isSafe: result.isSafe,
        threatType: result.threatType,
      });
    }
  };

  // Auto-fetch title when URL changes - only after user stops typing
  useEffect(() => {
    const fetchTitle = async () => {
      if (!formData.targetUrl || !formData.targetUrl.trim()) {
        setFetchingTitle(false);
        // Clear name if URL is empty
        if (formData.name && formData.name.trim()) {
          updateFormData('name', '');
        }
        return;
      }

      // Normalize URL (add https:// if missing)
      const normalizedUrl = normalizeUrl(formData.targetUrl);
      if (!normalizedUrl) {
        setFetchingTitle(false);
        return;
      }

      // Validate URL format
      try {
        new URL(normalizedUrl);
        setFetchingTitle(true);
        const title = await fetchPageTitle(normalizedUrl);
        if (title && title.trim()) {
          updateFormData('name', title.trim());
        } else {
          // If no title found, use domain name as fallback
          try {
            const urlObj = new URL(normalizedUrl);
            const domainName = urlObj.hostname.replace('www.', '');
            updateFormData('name', domainName);
          } catch {
            // If still fails, leave empty
          }
        }
      } catch (error) {
        // Invalid URL, skip fetching
        console.log('Invalid URL format, skipping title fetch');
      } finally {
        setFetchingTitle(false);
      }
    };

    // Wait 2 seconds after user stops typing before fetching title
    const timeoutId = setTimeout(fetchTitle, 2000);
    return () => clearTimeout(timeoutId);
  }, [formData.targetUrl, updateFormData, formData.name]);

  const handleUrlChange = (e) => {
    const url = e.target.value;
    updateFormData('targetUrl', url);
    
    // Reset name when URL changes (will be auto-filled again by useEffect)
    if (url && url !== formData.targetUrl) {
      updateFormData('name', '');
    }
  };

  const handleUrlPaste = (e) => {
    // Let the onChange handler deal with it
    // The useEffect will automatically fetch the title
  };

  const handleMagicWand = () => {
    const randomSlug = generateRandomSlug();
    updateFormData('slug', randomSlug);
  };

  const handleDomainSelect = (domain) => {
    updateFormData('domain', domain);
  };

  const canCreate = formData.targetUrl && formData.targetUrl.trim();

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -20 }}
      className="space-y-8"
    >
      {/* Header */}
      <div className="text-center">
        <h3 className="text-2xl font-bold text-white mb-2">The Fast Track</h3>
        <p className="text-slate-400 text-sm">Destination & Identity</p>
      </div>

      {/* Large URL Input - Google Search Style */}
      <div className="flex flex-col items-center justify-center min-h-[200px]">
        <div className="w-full max-w-2xl">
          <div className="relative">
            <input
              type="text"
              value={formData.targetUrl}
              onChange={handleUrlChange}
              onPaste={handleUrlPaste}
              onBlur={performSafetyCheck}
              placeholder="Paste your URL here..."
              className={`w-full px-6 py-5 text-lg bg-[#0b0f19] border-2 rounded-2xl text-white placeholder-slate-500 focus:outline-none transition-all shadow-lg ${
                safetyCheck.isSafe === false
                  ? 'border-red-500 focus:border-red-500'
                  : safetyCheck.isSafe === true
                  ? 'border-green-500/50 focus:border-green-500'
                  : 'border-[#232f48] focus:border-primary'
              }`}
              autoFocus
            />
            <div className="absolute right-4 top-1/2 -translate-y-1/2 flex items-center gap-2">
              {safetyCheck.loading && (
                <div className="flex items-center gap-2 text-slate-400 text-sm">
                  <span className="material-symbols-outlined animate-spin text-primary text-lg">
                    refresh
                  </span>
                  <span className="hidden sm:inline">Scanning for safety...</span>
                </div>
              )}
              {!safetyCheck.loading && safetyCheck.isSafe === true && (
                <div className="flex items-center gap-1.5 px-2 py-1 bg-green-500/20 text-green-400 rounded-lg text-xs font-medium">
                  <span className="material-symbols-outlined text-sm">verified</span>
                  <span className="hidden sm:inline">Secure Link</span>
                </div>
              )}
              {!safetyCheck.loading && safetyCheck.isSafe === false && (
                <div className="flex items-center gap-1.5 px-2 py-1 bg-red-500/20 text-red-400 rounded-lg text-xs font-medium">
                  <span className="material-symbols-outlined text-sm">warning</span>
                  <span className="hidden sm:inline">Unsafe</span>
                </div>
              )}
              {fetchingTitle && !safetyCheck.loading && (
                <span className="material-symbols-outlined animate-spin text-primary text-lg">
                  refresh
                </span>
              )}
            </div>
          </div>
          
          {/* Safety Warning */}
          {!safetyCheck.loading && safetyCheck.isSafe === false && (
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              className="mt-4 p-4 bg-red-500/10 border-2 border-red-500/50 rounded-xl"
            >
              <div className="flex items-start gap-3">
                <span className="material-symbols-outlined text-red-400 text-xl flex-shrink-0">warning</span>
                <div className="flex-1">
                  <h4 className="text-red-400 font-bold text-sm mb-1">Unsafe Link Detected</h4>
                  <p className="text-red-300 text-xs">
                    This URL has been flagged as <strong>{safetyCheck.threatType || 'potentially unsafe'}</strong> by Google Safe Browsing.
                    We recommend not using this link for security reasons.
                  </p>
                </div>
              </div>
            </motion.div>
          )}
          
          {/* Auto-filled Name (appears below URL input) */}
          {formData.name && (
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              className="mt-4 p-4 bg-[#0b0f19] border border-[#232f48] rounded-xl"
            >
              <label className="block text-xs text-slate-500 mb-1">Internal Name (Auto-filled)</label>
              <input
                type="text"
                value={formData.name}
                onChange={(e) => updateFormData('name', e.target.value)}
                className="w-full px-3 py-2 bg-[#101622] border border-[#232f48] rounded-lg text-white text-sm focus:outline-none focus:border-primary transition-colors"
              />
            </motion.div>
          )}
        </div>
      </div>

      {/* Slug with Magic Wand */}
      <div className="max-w-2xl mx-auto">
        <label className="block text-sm font-medium text-white mb-2">
          Slug (URL Path)
        </label>
        <div className="flex gap-3">
          <input
            type="text"
            value={formData.slug}
            onChange={(e) => updateFormData('slug', e.target.value)}
            placeholder="e.g., iphone-deal"
            className="flex-1 px-4 py-3 bg-[#0b0f19] border border-[#232f48] rounded-xl text-white placeholder-slate-500 focus:outline-none focus:border-primary transition-colors"
          />
          <button
            onClick={handleMagicWand}
            className="px-5 py-3 bg-primary/10 hover:bg-primary/20 border border-primary/30 text-primary rounded-xl transition-colors flex items-center gap-2 font-medium"
            title="Generate random secure slug"
          >
            <span className="material-symbols-outlined">auto_awesome</span>
            <span className="hidden sm:inline">Magic</span>
          </button>
        </div>
        <p className="text-xs text-slate-500 mt-2">
          Leave empty to auto-generate, or click Magic to generate a random slug
        </p>
      </div>

      {/* Custom Domain Chips */}
      <div className="max-w-2xl mx-auto">
        <label className="block text-sm font-medium text-white mb-3">
          Custom Domain
        </label>
        <div className="flex flex-wrap gap-2">
          {domains.map((domain) => {
            const isSelected = (formData.domain || domains[0]) === domain;
            return (
              <button
                key={domain}
                onClick={() => handleDomainSelect(domain)}
                className={`px-4 py-2 rounded-lg font-medium text-sm transition-all ${
                  isSelected
                    ? 'bg-primary text-white shadow-lg shadow-primary/30'
                    : 'bg-[#0b0f19] border border-[#232f48] text-slate-300 hover:border-primary/50'
                }`}
              >
                {domain}
              </button>
            );
          })}
        </div>
      </div>

      {/* Preview */}
      {(formData.domain || domains[0]) && formData.slug && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="max-w-2xl mx-auto p-4 bg-[#0b0f19] border border-[#232f48] rounded-xl"
        >
          <p className="text-xs text-slate-500 mb-1">Preview:</p>
          <p className="text-primary font-mono text-sm break-all">
            https://{formData.domain || domains[0]}/{formData.slug}
          </p>
        </motion.div>
      )}

      {/* Quick Create Button - Only on Step 1 */}
      {canCreate && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="max-w-2xl mx-auto pt-4"
        >
          <button
            onClick={onQuickCreate}
            disabled={safetyCheck.isSafe === false}
            className={`w-full px-6 py-3 bg-slate-700 hover:bg-slate-600 text-white font-bold rounded-xl transition-colors flex items-center justify-center gap-2 ${
              safetyCheck.isSafe === false
                ? 'opacity-50 cursor-not-allowed'
                : ''
            }`}
            title={safetyCheck.isSafe === false ? 'Cannot create link with unsafe URL' : ''}
          >
            <span className="material-symbols-outlined">bolt</span>
            Create with Defaults (Skip Advanced Settings)
          </button>
          <p className="text-xs text-slate-500 text-center mt-2">
            You can create the link now with default settings, or continue to customize UTM, pixels, and security
          </p>
        </motion.div>
      )}
    </motion.div>
  );
};

export default Step1FastTrack;


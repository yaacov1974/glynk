import React, { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { supabase } from "../../../lib/supabase";
import { checkUrlSafety } from "../../../lib/urlSafetyCheck";
import { validateUrl } from "../../../lib/urlValidation";

// Utility function to fetch page title from URL
const fetchPageTitle = async (url) => {
  try {
    // Validate URL first
    new URL(url);

    // Use a CORS proxy to fetch the page
    const proxyUrl = `https://api.allorigins.win/get?url=${encodeURIComponent(
      url
    )}`;
    const response = await fetch(proxyUrl, {
      method: "GET",
      headers: {
        Accept: "application/json",
      },
    });

    if (!response.ok) {
      throw new Error("Failed to fetch page");
    }

    const data = await response.json();

    if (data.contents) {
      // Parse HTML to extract title
      const parser = new DOMParser();
      const doc = parser.parseFromString(data.contents, "text/html");
      const title = doc.querySelector("title")?.textContent || "";
      return title.trim();
    }
    return "";
  } catch (error) {
    console.error("Error fetching page title:", error);
    // Return empty string on error - user can manually enter name
    return "";
  }
};

const Step1FastTrack = ({
  formData,
  updateFormData,
  onQuickCreate,
  onSafetyCheckUpdate,
}) => {
  const [domains, setDomains] = useState(["goodlink.ai"]);
  const [hasCustomDomains, setHasCustomDomains] = useState(false);
  const [fetchingTitle, setFetchingTitle] = useState(false);
  const [checkingSlug, setCheckingSlug] = useState(false);
  const [slugError, setSlugError] = useState(null);
  const [isSlugAvailable, setIsSlugAvailable] = useState(null); // null = not checked, true = available, false = taken
  const [safetyCheck, setSafetyCheck] = useState({
    loading: false,
    isSafe: null,
    threatType: null,
    error: null,
    urlExists: false, // Track if URL already exists in links table
  });

  useEffect(() => {
    const fetchDomains = async () => {
      try {
        const {
          data: { user },
        } = await supabase.auth.getUser();
        if (user) {
          // Try to fetch from domains table first
          const { data: customDomains, error: domainsError } = await supabase
            .from("domains")
            .select("domain")
            .eq("user_id", user.id)
            .neq("domain", "goodlink.ai");

          if (!domainsError && customDomains && customDomains.length > 0) {
            // User has custom domains - show all options including default
            const customDomainList = customDomains.map((d) => d.domain);
            setDomains(["goodlink.ai", ...customDomainList]);
            setHasCustomDomains(true);
          } else {
            // No custom domains table or no custom domains found
            // Check if user has any links with custom domains in links table
            const { data: linksWithCustomDomains, error: linksError } =
              await supabase
                .from("links")
                .select("domain")
                .eq("user_id", user.id)
                .neq("domain", "goodlink.ai")
                .limit(1);

            if (
              !linksError &&
              linksWithCustomDomains &&
              linksWithCustomDomains.length > 0
            ) {
              // User has used custom domains before - get all unique domains
              const { data: allDomains } = await supabase
                .from("links")
                .select("domain")
                .eq("user_id", user.id);

              if (allDomains && allDomains.length > 0) {
                const uniqueDomains = [
                  ...new Set(allDomains.map((l) => l.domain)),
                ];
                setDomains(uniqueDomains);
                setHasCustomDomains(true);
              } else {
                // No custom domains - hide the section
                setDomains(["goodlink.ai"]);
                setHasCustomDomains(false);
              }
            } else {
              // No custom domains - hide the section
              setDomains(["goodlink.ai"]);
              setHasCustomDomains(false);
            }
          }
        }
      } catch (error) {
        console.error("Error fetching domains:", error);
        // On error, default to hiding custom domain selection
        setDomains(["goodlink.ai"]);
        setHasCustomDomains(false);
      }
    };
    fetchDomains();
  }, []);

  // Safety check function - called when user leaves the field
  const performSafetyCheck = async () => {
    if (!formData.targetUrl || !formData.targetUrl.trim()) {
      setSafetyCheck({
        loading: false,
        isSafe: null,
        threatType: null,
        error: null,
        urlExists: false,
      });
      // Reset safety in parent
      if (onSafetyCheckUpdate) {
        onSafetyCheckUpdate({ isSafe: null, threatType: null });
      }
      return;
    }

    // Comprehensive URL validation BEFORE making API calls
    const validation = validateUrl(formData.targetUrl);

    if (!validation.isValid) {
      setSafetyCheck({
        loading: false,
        isSafe: null,
        threatType: null,
        error: validation.error || "Invalid URL format",
        urlExists: false,
      });
      if (onSafetyCheckUpdate) {
        onSafetyCheckUpdate({ isSafe: null, threatType: null });
      }
      return;
    }

    // Use normalized URL from validation
    const normalizedUrl = validation.normalizedUrl;

    // Perform safety check with normalized URL (only if validation passed)
    setSafetyCheck((prev) => ({ ...prev, loading: true }));
    const result = await checkUrlSafety(normalizedUrl);

    // Check if URL already exists in links table (check always, not just if safe)
    let urlExists = false;
    try {
      const {
        data: { user },
      } = await supabase.auth.getUser();

      if (user) {
        // Get all links for this user to check for URL matches
        const { data: existingLinks, error: linksError } = await supabase
          .from("links")
          .select("id, target_url")
          .eq("user_id", user.id);

        if (!linksError && existingLinks && existingLinks.length > 0) {
          // Normalize URLs for comparison (remove trailing slashes, lowercase, etc.)
          const normalizeForComparison = (url) => {
            try {
              const urlObj = new URL(url);
              // Remove trailing slash, convert to lowercase, remove www. prefix
              let normalized = urlObj.href.toLowerCase().replace(/\/$/, "");
              // Remove www. prefix for comparison
              if (normalized.includes("://www.")) {
                normalized = normalized.replace("://www.", "://");
              }
              return normalized;
            } catch {
              return url.toLowerCase().replace(/\/$/, "");
            }
          };

          const normalizedInputUrl = normalizeForComparison(normalizedUrl);

          // Check if any existing link matches the normalized URL
          urlExists = existingLinks.some((link) => {
            if (!link.target_url) return false;
            const normalizedExistingUrl = normalizeForComparison(
              link.target_url
            );
            return normalizedExistingUrl === normalizedInputUrl;
          });
        }
      }
    } catch (error) {
      console.error("Error checking if URL exists:", error);
      // Don't block user on error, just log it
    }

    const safetyState = {
      loading: false,
      isSafe: result.isSafe && !urlExists, // URL is safe only if it's safe AND doesn't exist
      threatType: result.threatType,
      error: urlExists
        ? "This URL already exists in your links. Please use a different URL."
        : result.error || null,
      urlExists: urlExists,
    };
    setSafetyCheck(safetyState);

    // Update parent component with safety check result
    if (onSafetyCheckUpdate) {
      onSafetyCheckUpdate({
        isSafe: result.isSafe && !urlExists,
        threatType: result.threatType,
      });
    }
  };

  // Auto-fetch title function - called when user leaves the field
  const fetchTitle = async () => {
    if (!formData.targetUrl || !formData.targetUrl.trim()) {
      setFetchingTitle(false);
      // Clear name if URL is empty
      if (formData.name && formData.name.trim()) {
        updateFormData("name", "");
      }
      return;
    }

    // Comprehensive URL validation BEFORE making API calls
    const validation = validateUrl(formData.targetUrl);

    if (!validation.isValid) {
      setFetchingTitle(false);
      return;
    }

    // Use normalized URL from validation
    const normalizedUrl = validation.normalizedUrl;

    // Fetch title only if validation passed
    try {
      setFetchingTitle(true);
      const title = await fetchPageTitle(normalizedUrl);
      if (title && title.trim()) {
        updateFormData("name", title.trim());
      } else {
        // If no title found, use domain name as fallback
        try {
          const urlObj = new URL(normalizedUrl);
          const domainName = urlObj.hostname.replace("www.", "");
          updateFormData("name", domainName);
        } catch {
          // If still fails, leave empty
        }
      }
    } catch (error) {
      // Invalid URL, skip fetching
      console.log("Error fetching title:", error);
    } finally {
      setFetchingTitle(false);
    }
  };

  const handleUrlChange = (e) => {
    const url = e.target.value;
    updateFormData("targetUrl", url);

    // Reset name when URL changes (will be auto-filled again by useEffect)
    if (url && url !== formData.targetUrl) {
      updateFormData("name", "");
    }
  };

  const handleUrlPaste = () => {
    // Let the onChange handler deal with it
    // The useEffect will automatically fetch the title
  };

  const handleCheckSlug = async () => {
    // Clear previous error
    setSlugError(null);

    // Check if user has entered a slug
    if (!formData.slug || !formData.slug.trim()) {
      setSlugError("Please enter a slug before checking");
      setIsSlugAvailable(null);
      return;
    }

    const slugToCheck = formData.slug.trim();
    const selectedDomain = formData.domain || domains[0];

    setCheckingSlug(true);

    try {
      const {
        data: { user },
      } = await supabase.auth.getUser();

      if (!user) {
        setSlugError("You must be logged in to check slug availability");
        setIsSlugAvailable(null);
        setCheckingSlug(false);
        return;
      }

      // Check if slug already exists in links table for this user and domain
      const { data: existingLinks, error } = await supabase
        .from("links")
        .select("id, slug, domain")
        .eq("user_id", user.id)
        .eq("slug", slugToCheck)
        .eq("domain", selectedDomain)
        .limit(1);

      if (error) {
        console.error("Error checking slug:", error);
        setSlugError("Error checking slug availability. Please try again.");
        setIsSlugAvailable(null);
        setCheckingSlug(false);
        return;
      }

      if (existingLinks && existingLinks.length > 0) {
        setSlugError(
          `This slug "${slugToCheck}" is already taken for domain "${selectedDomain}". Please choose a different slug.`
        );
        setIsSlugAvailable(false);
      } else {
        // Slug is available - clear any previous error and mark as available
        setSlugError(null);
        setIsSlugAvailable(true);
      }
    } catch (error) {
      console.error("Error checking slug:", error);
      setSlugError("Error checking slug availability. Please try again.");
      setIsSlugAvailable(null);
    } finally {
      setCheckingSlug(false);
    }
  };

  const handleDomainSelect = (domain) => {
    updateFormData("domain", domain);
  };

  // Show "Create with Defaults" button only when:
  // 1. URL is verified (safety check passed)
  // 2. Slug is provided and verified (slug check passed)
  const canCreate =
    formData.targetUrl &&
    formData.targetUrl.trim() &&
    safetyCheck.isSafe === true &&
    formData.slug &&
    formData.slug.trim() &&
    isSlugAvailable === true;

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
              onBlur={() => {
                performSafetyCheck();
                fetchTitle();
              }}
              placeholder="Paste your URL here..."
              className={`w-full px-6 py-5 text-lg bg-[#0b0f19] border-2 rounded-2xl text-white placeholder-slate-500 focus:outline-none transition-all shadow-lg ${
                safetyCheck.isSafe === false
                  ? "border-red-500 focus:border-red-500"
                  : safetyCheck.isSafe === true
                  ? "border-green-500/50 focus:border-green-500"
                  : "border-[#232f48] focus:border-primary"
              }`}
              autoFocus
            />
            <div className="absolute right-4 top-1/2 -translate-y-1/2 flex items-center gap-2">
              {safetyCheck.loading && (
                <div className="flex items-center gap-2 text-slate-400 text-sm">
                  <span className="material-symbols-outlined animate-spin text-primary text-lg">
                    refresh
                  </span>
                  <span className="hidden sm:inline">
                    Scanning for safety...
                  </span>
                </div>
              )}
              {!safetyCheck.loading && safetyCheck.isSafe === true && (
                <div className="flex items-center gap-1.5 px-2 py-1 bg-green-500/20 text-green-400 rounded-lg text-xs font-medium">
                  <span className="material-symbols-outlined text-sm">
                    verified
                  </span>
                  <span className="hidden sm:inline">Secure Link</span>
                </div>
              )}
              {!safetyCheck.loading && safetyCheck.isSafe === false && (
                <div className="flex items-center gap-1.5 px-2 py-1 bg-red-500/20 text-red-400 rounded-lg text-xs font-medium">
                  <span className="material-symbols-outlined text-sm">
                    warning
                  </span>
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

          {/* Validation Error */}
          {!safetyCheck.loading &&
            safetyCheck.error &&
            safetyCheck.isSafe === null && (
              <motion.div
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                className="mt-4 p-4 bg-yellow-500/10 border-2 border-yellow-500/50 rounded-xl"
              >
                <div className="flex items-start gap-3">
                  <span className="material-symbols-outlined text-yellow-400 text-xl flex-shrink-0">
                    info
                  </span>
                  <div className="flex-1">
                    <h4 className="text-yellow-400 font-bold text-sm mb-1">
                      Invalid URL Format
                    </h4>
                    <p className="text-yellow-300 text-xs">
                      {safetyCheck.error}
                    </p>
                  </div>
                </div>
              </motion.div>
            )}

          {/* Safety Warning / URL Exists Warning */}
          {!safetyCheck.loading && safetyCheck.isSafe === false && (
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              className="mt-4 p-4 bg-red-500/10 border-2 border-red-500/50 rounded-xl"
            >
              <div className="flex items-start gap-3">
                <span className="material-symbols-outlined text-red-400 text-xl flex-shrink-0">
                  {safetyCheck.urlExists ? "link_off" : "warning"}
                </span>
                <div className="flex-1">
                  <h4 className="text-red-400 font-bold text-sm mb-1">
                    {safetyCheck.urlExists
                      ? "URL Already Exists"
                      : "Unsafe Link Detected"}
                  </h4>
                  <p className="text-red-300 text-xs">
                    {safetyCheck.urlExists
                      ? safetyCheck.error ||
                        "This URL already exists in your links. Please use a different URL."
                      : `This URL has been flagged as ${
                          safetyCheck.threatType || "potentially unsafe"
                        } by Google Safe Browsing. We recommend not using this link for security reasons.`}
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
              <label className="block text-xs text-slate-500 mb-1">
                Internal Name (Auto-filled)
              </label>
              <input
                type="text"
                value={formData.name}
                onChange={(e) => updateFormData("name", e.target.value)}
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
            onChange={(e) => {
              updateFormData("slug", e.target.value);
              // Clear error and reset availability when user types
              if (slugError) {
                setSlugError(null);
              }
              if (isSlugAvailable !== null) {
                setIsSlugAvailable(null); // Reset to blue/default when user changes slug
              }
            }}
            placeholder="e.g., iphone-deal"
            className={`flex-1 px-4 py-3 bg-[#0b0f19] border rounded-xl text-white placeholder-slate-500 focus:outline-none transition-colors ${
              slugError
                ? "border-red-500 focus:border-red-500"
                : isSlugAvailable === true
                ? "border-green-500 focus:border-green-500"
                : "border-[#232f48] focus:border-primary"
            }`}
          />
          <button
            onClick={handleCheckSlug}
            disabled={checkingSlug}
            className={`px-5 py-3 rounded-xl transition-colors flex items-center gap-2 font-medium disabled:opacity-50 disabled:cursor-not-allowed ${
              isSlugAvailable === true
                ? "bg-green-500/10 hover:bg-green-500/20 border border-green-500/30 text-green-400"
                : "bg-primary/10 hover:bg-primary/20 border border-primary/30 text-primary"
            }`}
            title="Check if slug is available"
          >
            {checkingSlug ? (
              <>
                <span className="material-symbols-outlined animate-spin">
                  refresh
                </span>
                <span className="hidden sm:inline">Checking...</span>
              </>
            ) : isSlugAvailable === true ? (
              <>
                <span className="material-symbols-outlined">check_circle</span>
                <span className="hidden sm:inline">Available</span>
              </>
            ) : (
              <>
                <span className="material-symbols-outlined">check_circle</span>
                <span className="hidden sm:inline">Check</span>
              </>
            )}
          </button>
        </div>
        {slugError ? (
          <motion.p
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-red-400 text-xs mt-2 text-left"
          >
            {slugError}
          </motion.p>
        ) : isSlugAvailable === true ? (
          <motion.p
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-green-400 text-xs mt-2 text-left"
          >
            ✓ Slug is available!
          </motion.p>
        ) : (
          <p className="text-xs text-slate-500 mt-2">
            Enter a slug and click Check to verify availability
          </p>
        )}
      </div>

      {/* Custom Domain Chips - Only show if user has at least one custom domain */}
      {hasCustomDomains && (
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
                      ? "bg-primary text-white shadow-lg shadow-primary/30"
                      : "bg-[#0b0f19] border border-[#232f48] text-slate-300 hover:border-primary/50"
                  }`}
                >
                  {domain}
                </button>
              );
            })}
          </div>
        </div>
      )}

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
                ? "opacity-50 cursor-not-allowed"
                : ""
            }`}
            title={
              safetyCheck.isSafe === false
                ? "Cannot create link with unsafe URL"
                : ""
            }
          >
            <span className="material-symbols-outlined">bolt</span>
            Create with Defaults (Skip Advanced Settings)
          </button>
          <p className="text-xs text-slate-500 text-center mt-2">
            You can create the link now with default settings, or continue to
            customize UTM, pixels, and security
          </p>
        </motion.div>
      )}
    </motion.div>
  );
};

export default Step1FastTrack;

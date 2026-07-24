/*
  Static-frontend hook: VulnLab can be split-deployed
  - Frontend splash on GitHub Pages
  - Backend vulnerable API on Render/Fly.io
  This script reads the API base from window.VULNLAB_API configured
  in index.html and proxies all user clicks via fetch.
  For local/dev mode, defaults to same-origin.
*/

(function () {
  window.VULNLAB_API = window.VULNLAB_API || ''; // e.g. 'https://vulnlab.onrender.com'

  // Faction join for static splash
  window.joinFaction = async function (faction) {
    try {
      const r = await fetch(window.VULNLAB_API + '/story/faction', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ faction }),
      });
      const j = await r.json();
      if (j.success) {
        window.location.href = window.VULNLAB_API + '/story/vault';
      } else {
        alert(j.error || 'Join failed');
      }
    } catch (e) {
      alert('Backend unreachable: ' + e.message + '\\nEnsure VULNLAB_API is set correctly.');
    }
  };
})();

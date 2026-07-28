/*
  Static-frontend hook: AIVault can be split-deployed
  - Frontend splash on GitHub Pages
  - Backend vulnerable API on Render/Fly.io
  This script reads the API base from window.AIVAULT_API configured
  in index.html and proxies all user clicks via fetch.
  For local/dev mode, defaults to same-origin.
*/

(function () {
  window.AIVAULT_API = window.AIVAULT_API || ''; // e.g. 'https://aivault.onrender.com'

  // Faction join for static splash
  window.joinFaction = async function (faction) {
    try {
      const r = await fetch(window.AIVAULT_API + '/story/faction', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ faction }),
      });
      const j = await r.json();
      if (j.success) {
        window.location.href = window.AIVAULT_API + '/story/vault';
      } else {
        alert(j.error || 'Join failed');
      }
    } catch (e) {
      alert('Backend unreachable: ' + e.message + '\nEnsure AIVAULT_API is set correctly.');
    }
  };
})();

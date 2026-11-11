(function () {
  try {
    var pref = localStorage.getItem('theme-preference') || 'system';
    var meta = document.querySelector('meta[name="color-scheme"]');
    if (meta) {
      if (pref === 'light') meta.setAttribute('content', 'light');
      else if (pref === 'dark') meta.setAttribute('content', 'dark');
      else meta.setAttribute('content', 'light dark');
    }
  } catch (_) {}
})();

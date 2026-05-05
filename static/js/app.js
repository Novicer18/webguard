document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('scan-form');
  const loading = document.getElementById('scan-loading');
  const themeToggle = document.getElementById('theme-toggle');

  if (form && loading) {
    form.addEventListener('submit', () => loading.classList.remove('d-none'));
  }

  if (themeToggle) {
    themeToggle.addEventListener('click', () => {
      const html = document.documentElement;
      const current = html.getAttribute('data-bs-theme') || 'dark';
      html.setAttribute('data-bs-theme', current === 'dark' ? 'light' : 'dark');
    });
  }
});

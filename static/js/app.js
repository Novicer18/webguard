document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('scan-form');
  const loading = document.getElementById('scan-loading');

  if (form && loading) {
    form.addEventListener('submit', () => loading.classList.remove('d-none'));
  }
});

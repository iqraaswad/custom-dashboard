document.addEventListener('DOMContentLoaded', () => {
  const autoRefresh = document.getElementById('updateTime');
  if (autoRefresh) {
    autoRefresh.textContent = 'Updated: ' + new Date().toLocaleString();
  }
});

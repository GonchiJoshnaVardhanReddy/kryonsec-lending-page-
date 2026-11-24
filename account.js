const message = document.querySelector('#account-message');
const providers = ['github', 'google'];
for (const provider of providers) {
  document.querySelector(`#${provider}-signin`).addEventListener('click', () => {
    location.assign(`/api/auth/${provider}/start?next=%2Fdashboard`);
  });
}
async function load() {
  try {
    const response = await fetch('/api/config', {credentials: 'same-origin', cache: 'no-store'});
    if (!response.ok) throw new Error('Could not check sign-in availability. Please refresh or use /signin.');
    const config = await response.json();
    if (config.signedIn) { location.replace('/dashboard'); return; }
    for (const provider of providers) {
      const available = config.providers?.includes(provider);
      document.querySelector(`#${provider}-signin`).disabled = !available;
      const label = provider === 'github' ? 'GitHub' : 'Google';
      document.querySelector(`#${provider}-status`).textContent = available ? '' : `${label} sign-in is not configured yet.`;
    }
    message.textContent = config.ready ? '' : 'Sign-in is temporarily unavailable. Please try again later.';
  } catch (error) { message.textContent = error.message; }
}
load();

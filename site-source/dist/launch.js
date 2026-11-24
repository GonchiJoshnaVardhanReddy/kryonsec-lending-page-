// Content is visible without JavaScript and when reduced motion is requested.
const revealTargets = document.querySelectorAll('.section > *, .hero-foot');
if ('IntersectionObserver' in window && !matchMedia('(prefers-reduced-motion: reduce)').matches) {
  const observer = new IntersectionObserver(entries => {
    entries.forEach(entry => { if(entry.isIntersecting){entry.target.classList.remove('reveal-pending');observer.unobserve(entry.target);} });
  }, {threshold: 0.08});
  revealTargets.forEach(el => {if(el.getBoundingClientRect().top > innerHeight){el.classList.add('reveal-pending');observer.observe(el);}});
  document.querySelector('#motion-control').addEventListener('click', () => {
    if(document.body.classList.contains('motion-paused')) {document.querySelectorAll('.reveal-pending').forEach(el=>el.classList.remove('reveal-pending'));observer.disconnect();}
  });
}

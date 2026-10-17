// Loading and duplicate-submit guard for /signin.
//
// The provider buttons are ordinary links, so they work with no JavaScript at
// all. This only adds the part a link cannot say: that the browser is on its
// way to the provider. A second click while the first is in flight is ignored,
// and returning to the page (including through the back/forward cache) puts
// the labels back the way they were.
(() => {
    const buttons = document.querySelectorAll('[data-provider]:not([disabled])');
    if (!buttons.length) return;

    const labels = new Map();
    buttons.forEach((button) => {
        const label = button.querySelector('.button-label');
        if (label) labels.set(button, label.textContent);
    });

    let pending = false;
    const reset = () => {
        pending = false;
        for (const [button, text] of labels) {
            button.classList.remove('is-loading');
            button.removeAttribute('aria-busy');
            const label = button.querySelector('.button-label');
            if (label) label.textContent = text;
        }
    };

    buttons.forEach((button) => {
        button.addEventListener('click', (event) => {
            if (pending) {
                event.preventDefault();
                return;
            }
            pending = true;
            button.classList.add('is-loading');
            button.setAttribute('aria-busy', 'true');
            const label = button.querySelector('.button-label');
            if (label) label.textContent = 'CONNECTING…';
        });
    });

    // The click may be cancelled (back button, network failure) without
    // unloading the page; restore the labels when it becomes visible again.
    window.addEventListener('pageshow', reset);
})();

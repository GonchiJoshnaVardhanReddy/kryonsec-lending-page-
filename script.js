(() => {
    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    const themeToggle = document.querySelector('#theme-toggle');
    const themeLabel = themeToggle?.querySelector('.theme-label');
    const themeIcon = themeToggle?.querySelector('.theme-icon');
    const themeColor = document.querySelector('#theme-color');
    const applyTheme = (theme) => {
        const dark = theme === 'dark';
        document.documentElement.removeAttribute('data-theme');
        if (dark) document.documentElement.dataset.theme = 'dark';
        if (themeToggle) {
            themeToggle.setAttribute('aria-pressed', String(dark));
            themeToggle.setAttribute('aria-label', dark ? 'Switch to light mode' : 'Switch to dark mode');
        }
        if (themeLabel) themeLabel.textContent = dark ? 'LIGHT MODE' : 'DARK MODE';
        if (themeIcon) themeIcon.textContent = dark ? '◑' : '◐';
        if (themeColor) themeColor.content = dark ? '#111112' : '#f5f5f0';
    };
    applyTheme(document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light');
    themeToggle?.addEventListener('click', () => {
        const nextTheme = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
        applyTheme(nextTheme);
        try { localStorage.setItem('kryonsec-theme', nextTheme); } catch (_) {}
    });

    const mobileMenuToggle = document.querySelector('#mobile-menu-toggle');
    const siteNav = document.querySelector('#primary-navigation');
    const closeMobileMenu = () => {
        siteNav?.classList.remove('is-open');
        mobileMenuToggle?.setAttribute('aria-expanded', 'false');
        mobileMenuToggle?.setAttribute('aria-label', 'Open navigation menu');
    };
    mobileMenuToggle?.addEventListener('click', () => {
        const isOpen = siteNav?.classList.toggle('is-open') || false;
        mobileMenuToggle.setAttribute('aria-expanded', String(isOpen));
        mobileMenuToggle.setAttribute('aria-label', isOpen ? 'Close navigation menu' : 'Open navigation menu');
    });
    siteNav?.querySelectorAll('a').forEach((link) => link.addEventListener('click', closeMobileMenu));

    const feedbackForm = document.querySelector('#feedback-form');
    const feedbackStatus = document.querySelector('#feedback-submit-status');
    const feedbackSubmit = feedbackForm?.querySelector('button[type="submit"]');
    const feedbackSubmittedAt = document.querySelector('#feedback-submitted-at');
    let feedbackPending = false;
    const restoreFeedbackSubmit = () => {
        if (feedbackSubmit) {
            feedbackSubmit.disabled = false;
            feedbackSubmit.innerHTML = 'SEND FEEDBACK <span aria-hidden="true">↗</span>';
        }
    };
    feedbackForm?.addEventListener('submit', async (event) => {
        event.preventDefault();
        if (feedbackPending) return;
        feedbackPending = true;
        if (feedbackSubmittedAt) feedbackSubmittedAt.value = new Date().toISOString();
        if (feedbackSubmit) {
            feedbackSubmit.disabled = true;
            feedbackSubmit.textContent = 'SENDING...';
        }
        if (feedbackStatus) feedbackStatus.textContent = 'SENDING FEEDBACK...';
        try {
            // Same origin, so no CORS and no hidden iframe. The old iframe said
            // "sent" on any load, including an error page; reading the real
            // status is what makes a dropped submission visible.
            const response = await fetch(feedbackForm.action, {
                method: 'POST',
                body: new FormData(feedbackForm),
            });
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            feedbackForm.reset();
            if (feedbackStatus) feedbackStatus.textContent = 'FEEDBACK SENT — THANK YOU.';
        } catch {
            if (feedbackStatus) feedbackStatus.textContent = 'COULD NOT SEND — TRY AGAIN LATER.';
        } finally {
            feedbackPending = false;
            restoreFeedbackSubmit();
        }
    });

    document.querySelectorAll('a[href^="#"]').forEach((anchor) => {
        anchor.addEventListener('click', (event) => {
            const selector = anchor.getAttribute('href');
            if (!selector || selector === '#') return;
            const target = document.querySelector(selector);
            if (!target) return;
            event.preventDefault();
            target.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'start' });
            window.history.replaceState(null, '', selector);
        });
    });

})();

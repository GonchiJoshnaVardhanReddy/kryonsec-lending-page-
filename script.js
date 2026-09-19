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

    const installCopyTriggers = document.querySelectorAll('.install-copy-trigger');
    const installCopyStatus = document.querySelector('#install-copy-status');
    const copyText = async (text) => {
        try {
            await navigator.clipboard.writeText(text);
            return true;
        } catch (_) {
            const field = document.createElement('textarea');
            field.value = text;
            field.setAttribute('readonly', '');
            field.style.position = 'fixed';
            field.style.opacity = '0';
            document.body.appendChild(field);
            field.select();
            let copied = false;
            try { copied = document.execCommand('copy'); } catch (_) {}
            document.body.removeChild(field);
            return copied;
        }
    };
    installCopyTriggers.forEach((trigger) => {
        const label = trigger.innerHTML;
        let resetTimer;
        trigger.addEventListener('click', async () => {
            const target = document.querySelector(`#${trigger.dataset.copyTarget}`);
            if (!target) return;
            const copied = await copyText(target.textContent.trim());
            window.clearTimeout(resetTimer);
            trigger.innerHTML = copied ? 'COPIED ✓' : 'COPY FAILED';
            if (installCopyStatus) installCopyStatus.textContent = copied
                ? 'Command copied — paste it into your terminal.'
                : 'Copy blocked by the browser — select the command and copy it manually.';
            resetTimer = window.setTimeout(() => {
                trigger.innerHTML = label;
                if (installCopyStatus) installCopyStatus.textContent = 'Paste it into your terminal. That is the whole setup.';
            }, 2400);
        });
    });

    const feedbackForm = document.querySelector('#feedback-form');
    const feedbackStatus = document.querySelector('#feedback-submit-status');
    const feedbackSubmit = feedbackForm?.querySelector('button[type="submit"]');
    const feedbackFrame = document.querySelector('#feedback-response-frame');
    const feedbackSubmittedAt = document.querySelector('#feedback-submitted-at');
    let feedbackPending = false;
    let feedbackTimeout;
    const restoreFeedbackSubmit = () => {
        if (feedbackSubmit) {
            feedbackSubmit.disabled = false;
            feedbackSubmit.innerHTML = 'SEND FEEDBACK <span aria-hidden="true">↗</span>';
        }
    };
    feedbackFrame?.addEventListener('load', () => {
        if (!feedbackPending) return;
        feedbackPending = false;
        window.clearTimeout(feedbackTimeout);
        feedbackForm?.reset();
        if (feedbackStatus) feedbackStatus.textContent = 'FEEDBACK SENT — THANK YOU.';
        restoreFeedbackSubmit();
    });
    feedbackForm?.addEventListener('submit', () => {
        feedbackPending = true;
        if (feedbackSubmittedAt) feedbackSubmittedAt.value = new Date().toISOString();
        if (feedbackSubmit) {
            feedbackSubmit.disabled = true;
            feedbackSubmit.textContent = 'SENDING...';
        }
        if (feedbackStatus) feedbackStatus.textContent = 'SENDING FEEDBACK...';
        feedbackTimeout = window.setTimeout(() => {
            if (!feedbackPending) return;
            feedbackPending = false;
            if (feedbackStatus) feedbackStatus.textContent = 'NO RESPONSE OBSERVED — TRY AGAIN LATER.';
            restoreFeedbackSubmit();
        }, 15000);
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

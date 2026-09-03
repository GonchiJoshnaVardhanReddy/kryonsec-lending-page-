try {
    if (localStorage.getItem('kryonsec-theme') === 'dark') {
        document.documentElement.dataset.theme = 'dark';
    }
} catch (_) {}

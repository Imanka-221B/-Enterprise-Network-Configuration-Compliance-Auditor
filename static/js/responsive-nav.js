(function () {
    const shell = document.querySelector('.app-shell');
    const sidebar = document.querySelector('.sidebar');
    const toggle = document.querySelector('.mobile-nav-toggle');
    if (!shell || !sidebar || !toggle) return;

    let overlay = document.querySelector('.mobile-nav-overlay');
    if (!overlay) {
        overlay = document.createElement('button');
        overlay.type = 'button';
        overlay.className = 'mobile-nav-overlay';
        overlay.setAttribute('aria-label', 'Close navigation');
        document.body.appendChild(overlay);
    }

    function setOpen(open) {
        shell.classList.toggle('mobile-nav-open', open);
        toggle.setAttribute('aria-expanded', String(open));
        toggle.setAttribute('aria-label', open ? 'Close navigation' : 'Open navigation');
        sidebar.setAttribute('aria-hidden', String(!open));
        if (open) {
            const firstLink = sidebar.querySelector('.nav-item');
            firstLink?.focus();
        } else {
            toggle.focus();
        }
    }

    sidebar.setAttribute('aria-hidden', String(window.innerWidth <= 820));
    toggle.addEventListener('click', () => setOpen(!shell.classList.contains('mobile-nav-open')));
    overlay.addEventListener('click', () => setOpen(false));
    sidebar.addEventListener('click', event => {
        if (event.target.closest('.nav-item, .logout-link')) setOpen(false);
    });
    document.addEventListener('keydown', event => {
        if (event.key === 'Escape' && shell.classList.contains('mobile-nav-open')) setOpen(false);
    });
    window.addEventListener('resize', () => {
        if (window.innerWidth > 680 && shell.classList.contains('mobile-nav-open')) setOpen(false);
    });
})();

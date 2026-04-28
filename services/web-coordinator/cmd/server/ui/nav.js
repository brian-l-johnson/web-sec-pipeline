'use strict';
(function () {
  // ── CSS ──────────────────────────────────────────────────────────────────────
  const style = document.createElement('style');
  style.textContent = `
    #site-nav {
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      padding: 0 24px;
      display: flex;
      align-items: center;
      gap: 0;
      height: 48px;
    }
    #site-nav .dot {
      width: 8px; height: 8px; border-radius: 50%;
      background: var(--green); box-shadow: 0 0 6px var(--green);
      flex-shrink: 0; margin-right: 12px;
    }
    #site-nav .brand {
      color: var(--text); text-decoration: none;
      font-size: 15px; font-weight: 600; letter-spacing: .3px;
      white-space: nowrap; margin-right: 20px;
    }
    #site-nav .brand:hover { opacity: .85; }
    #site-nav .nav-links { display: flex; gap: 2px; }
    #site-nav .nav-links a {
      color: var(--muted); text-decoration: none;
      font-size: 13px; font-weight: 500;
      padding: 6px 12px; border-radius: 6px;
      transition: background .12s, color .12s;
      white-space: nowrap;
    }
    #site-nav .nav-links a:hover {
      color: var(--text); background: rgba(255,255,255,.05);
    }
    #site-nav .nav-links a.active {
      color: var(--text); background: rgba(255,255,255,.08);
    }
    #site-nav .nav-right {
      margin-left: auto;
      display: flex; align-items: center; gap: 12px;
      font-size: 12px; color: var(--muted);
    }
  `;
  document.head.appendChild(style);

  // ── Nav links ─────────────────────────────────────────────────────────────────
  const links = [
    {
      href: '/ui/',
      label: 'Jobs',
      match: p => p === '/ui/' || p === '/ui/index.html' || p.startsWith('/ui/job'),
    },
    {
      href: '/ui/targets.html',
      label: 'Targets',
      match: p => p.startsWith('/ui/targets'),
    },
  ];

  const path = location.pathname;
  const navLinksHTML = links
    .map(l => `<a href="${l.href}"${l.match(path) ? ' class="active"' : ''}>${l.label}</a>`)
    .join('');

  // ── Build and inject ──────────────────────────────────────────────────────────
  const nav = document.createElement('header');
  nav.id = 'site-nav';
  nav.innerHTML =
    '<div class="dot"></div>' +
    '<a class="brand" href="/ui/">Web Security Scanner</a>' +
    '<div class="nav-links">' + navLinksHTML + '</div>' +
    '<div class="nav-right"><span id="last-refresh"></span></div>';

  document.body.insertBefore(nav, document.body.firstChild);
})();

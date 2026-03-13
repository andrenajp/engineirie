/**
 * cookie-consent.js — Engine Irie
 * Module autonome de gestion du consentement aux cookies (RGPD)
 * Usage : <script src="cookie-consent.js"></script>
 * Le script s'initialise automatiquement au chargement de la page.
 */

(function () {
    "use strict";

    // ─── Configuration ────────────────────────────────────────────────────────
    const CONFIG = {
        storageKey: "cookie-consent",
        storageDateKey: "cookie-consent-date",
        logKey: "cookie-consent-log",
        endpoint: "save-consent.php", // script PHP dans le même dossier que index.html
        privacyPolicyUrl: "politique-cookies.html",
    };

    // ─── Styles injectés ──────────────────────────────────────────────────────
    const CSS = `
    /* ── Reset complet pour isoler du Tailwind preflight ── */
    #cc-banner, #cc-banner *,
    #cc-modal,  #cc-modal *,
    #cc-overlay,
    #cc-toast,  #cc-toast * {
      all: revert;
      box-sizing: border-box !important;
      font-family: 'Inter', system-ui, sans-serif !important;
    }

    /* Banner */
    #cc-banner {
      position: fixed !important;
      bottom: 0 !important;
      left: 0 !important;
      right: 0 !important;
      z-index: 99998 !important;
      background: #141414 !important;
      border-top: 1px solid #27272a !important;
      padding: 16px 24px !important;
      display: none !important;
      margin: 0 !important;
    }
    #cc-banner.cc-visible {
      display: block !important;
    }
    #cc-banner-inner {
      max-width: 1200px !important;
      margin: 0 auto !important;
      display: flex !important;
      flex-wrap: wrap !important;
      align-items: center !important;
      justify-content: space-between !important;
      gap: 12px !important;
    }
    #cc-banner-text {
      font-size: 13px !important;
      color: #a1a1aa !important;
      flex: 1 !important;
      min-width: 200px !important;
      line-height: 1.5 !important;
      margin: 0 !important;
    }
    #cc-banner-text a {
      color: #0ea5e9 !important;
      text-decoration: none !important;
    }
    #cc-banner-text a:hover {
      text-decoration: underline !important;
    }
    #cc-banner-actions {
      display: flex !important;
      gap: 8px !important;
      flex-wrap: wrap !important;
      align-items: center !important;
    }

    /* Buttons */
    .cc-btn {
      display: inline-flex !important;
      align-items: center !important;
      justify-content: center !important;
      padding: 8px 16px !important;
      font-size: 13px !important;
      font-family: 'Inter', system-ui, sans-serif !important;
      font-weight: 500 !important;
      border-radius: 8px !important;
      cursor: pointer !important;
      transition: opacity 0.2s !important;
      white-space: nowrap !important;
      line-height: 1 !important;
      text-decoration: none !important;
      margin: 0 !important;
    }
    .cc-btn:hover { opacity: 0.85 !important; }
    .cc-btn-primary {
      background: #0ea5e9 !important;
      color: #0a0a0a !important;
      border: none !important;
    }
    .cc-btn-secondary {
      background: transparent !important;
      color: #fafafa !important;
      border: 1px solid #27272a !important;
    }

    /* Overlay */
    #cc-overlay {
      display: none !important;
      position: fixed !important;
      inset: 0 !important;
      z-index: 99998 !important;
      background: rgba(10,10,10,0.75) !important;
      backdrop-filter: blur(4px) !important;
      margin: 0 !important;
      padding: 0 !important;
    }
    #cc-overlay.cc-visible { display: block !important; }

    /* Modal */
    #cc-modal {
      display: none !important;
      position: fixed !important;
      left: 50% !important;
      top: 50% !important;
      transform: translate(-50%, -50%) !important;
      z-index: 99999 !important;
      width: calc(100% - 32px) !important;
      max-width: 480px !important;
      max-height: 90vh !important;
      overflow-y: auto !important;
      background: #141414 !important;
      border: 1px solid #27272a !important;
      border-radius: 16px !important;
      padding: 24px !important;
      margin: 0 !important;
    }
    #cc-modal.cc-visible { display: block !important; }

    #cc-modal-header {
      display: flex !important;
      align-items: center !important;
      justify-content: space-between !important;
      margin: 0 0 20px 0 !important;
      padding: 0 !important;
    }
    #cc-modal-title {
      font-size: 18px !important;
      font-weight: 600 !important;
      color: #fafafa !important;
      margin: 0 !important;
    }
    #cc-modal-close {
      background: none !important;
      border: none !important;
      cursor: pointer !important;
      color: #a1a1aa !important;
      padding: 4px !important;
      line-height: 1 !important;
      font-size: 20px !important;
      transition: color 0.2s !important;
      margin: 0 !important;
    }
    #cc-modal-close:hover { color: #fafafa !important; }

    .cc-row {
      background: #1e1e1e !important;
      border-radius: 10px !important;
      padding: 14px 16px !important;
      margin: 0 0 10px 0 !important;
    }
    .cc-row-header {
      display: flex !important;
      align-items: center !important;
      justify-content: space-between !important;
      margin: 0 0 6px 0 !important;
      padding: 0 !important;
    }
    .cc-row-label {
      font-size: 14px !important;
      font-weight: 500 !important;
      color: #fafafa !important;
      margin: 0 !important;
    }
    .cc-row-desc {
      font-size: 12px !important;
      color: #a1a1aa !important;
      line-height: 1.5 !important;
      margin: 0 !important;
    }
    .cc-badge {
      font-size: 11px !important;
      padding: 2px 8px !important;
      border-radius: 4px !important;
      background: rgba(14,165,233,0.15) !important;
      color: #0ea5e9 !important;
      white-space: nowrap !important;
      margin: 0 !important;
    }

    /* Toggle switch */
    .cc-toggle {
      position: relative !important;
      display: inline-block !important;
      width: 40px !important;
      height: 22px !important;
      flex-shrink: 0 !important;
      margin: 0 !important;
      padding: 0 !important;
    }
    .cc-toggle input {
      opacity: 0 !important;
      width: 0 !important;
      height: 0 !important;
      position: absolute !important;
      margin: 0 !important;
    }
    .cc-toggle-slider {
      position: absolute !important;
      cursor: pointer !important;
      inset: 0 !important;
      background: #27272a !important;
      border-radius: 22px !important;
      transition: background 0.3s !important;
      margin: 0 !important;
    }
    .cc-toggle-slider::before {
      content: '' !important;
      position: absolute !important;
      height: 16px !important;
      width: 16px !important;
      left: 3px !important;
      top: 3px !important;
      background: white !important;
      border-radius: 50% !important;
      transition: transform 0.3s !important;
    }
    .cc-toggle input:checked + .cc-toggle-slider {
      background: #0ea5e9 !important;
    }
    .cc-toggle input:checked + .cc-toggle-slider::before {
      transform: translateX(18px) !important;
    }

    #cc-modal-footer {
      display: flex !important;
      gap: 10px !important;
      margin: 20px 0 0 0 !important;
      padding: 0 !important;
    }
    #cc-modal-footer .cc-btn {
      flex: 1 !important;
    }

    /* Toast */
    #cc-toast {
      position: fixed !important;
      bottom: 24px !important;
      right: 24px !important;
      z-index: 100000 !important;
      background: #141414 !important;
      border: 1px solid #27272a !important;
      border-radius: 10px !important;
      padding: 12px 18px !important;
      font-size: 13px !important;
      color: #fafafa !important;
      display: flex !important;
      align-items: center !important;
      gap: 10px !important;
      opacity: 0 !important;
      transform: translateY(10px) !important;
      transition: opacity 0.3s, transform 0.3s !important;
      pointer-events: none !important;
      margin: 0 !important;
    }
    #cc-toast.cc-visible {
      opacity: 1 !important;
      transform: translateY(0) !important;
    }
    #cc-toast-icon {
      width: 20px !important;
      height: 20px !important;
      background: rgba(34,197,94,0.15) !important;
      border-radius: 50% !important;
      display: flex !important;
      align-items: center !important;
      justify-content: center !important;
      flex-shrink: 0 !important;
      color: #22c55e !important;
      font-size: 12px !important;
      margin: 0 !important;
      padding: 0 !important;
    }
    #cc-toast-msg {
      margin: 0 !important;
      padding: 0 !important;
    }

    @media (max-width: 600px) {
      #cc-banner-inner { flex-direction: column !important; align-items: flex-start !important; }
      #cc-modal { padding: 18px !important; }
      #cc-modal-footer { flex-direction: column !important; }
    }
  `;

    // ─── HTML du banner ────────────────────────────────────────────────────────
    function createBannerHTML() {
        return `
      <div id="cc-banner-inner">
        <p id="cc-banner-text">
          Nous utilisons des cookies pour améliorer votre expérience. En continuant, vous acceptez notre
          <a href="${CONFIG.privacyPolicyUrl}">politique de cookies</a>.
        </p>
        <div id="cc-banner-actions">
          <button class="cc-btn cc-btn-secondary" id="cc-btn-reject">Refuser</button>
          <button class="cc-btn cc-btn-secondary" id="cc-btn-settings">Paramétrer</button>
          <button class="cc-btn cc-btn-primary" id="cc-btn-accept">Accepter tout</button>
        </div>
      </div>
    `;
    }

    // ─── HTML du modal ─────────────────────────────────────────────────────────
    function createModalHTML() {
        return `
      <div id="cc-modal-header">
        <span id="cc-modal-title">Paramètres des cookies</span>
        <button id="cc-modal-close" aria-label="Fermer">✕</button>
      </div>

      <div class="cc-row">
        <div class="cc-row-header">
          <span class="cc-row-label">Cookies essentiels</span>
          <span class="cc-badge">Toujours actifs</span>
        </div>
        <p class="cc-row-desc">Nécessaires au fonctionnement du site. Ne peuvent pas être désactivés.</p>
      </div>

      <div class="cc-row">
        <div class="cc-row-header">
          <span class="cc-row-label">Cookies analytiques</span>
          <label class="cc-toggle">
            <input type="checkbox" id="cc-toggle-analytics">
            <span class="cc-toggle-slider"></span>
          </label>
        </div>
        <p class="cc-row-desc">Nous aident à comprendre comment vous utilisez le site pour l'améliorer.</p>
      </div>

      <div class="cc-row">
        <div class="cc-row-header">
          <span class="cc-row-label">Cookies marketing</span>
          <label class="cc-toggle">
            <input type="checkbox" id="cc-toggle-marketing">
            <span class="cc-toggle-slider"></span>
          </label>
        </div>
        <p class="cc-row-desc">Utilisés pour vous proposer des publicités pertinentes.</p>
      </div>

      <div id="cc-modal-footer">
        <button class="cc-btn cc-btn-primary" id="cc-btn-save">Enregistrer mes choix</button>
        <button class="cc-btn cc-btn-secondary" id="cc-btn-accept-all">Tout accepter</button>
      </div>
    `;
    }

    // ─── HTML du toast ─────────────────────────────────────────────────────────
    function createToastHTML() {
        return `
      <span id="cc-toast-icon">✓</span>
      <span id="cc-toast-msg">Préférences enregistrées</span>
    `;
    }

    // ─── Injection du DOM ──────────────────────────────────────────────────────
    function injectDOM() {
        // Styles
        const style = document.createElement("style");
        style.textContent = CSS;
        document.head.appendChild(style);

        // Banner
        const banner = document.createElement("div");
        banner.id = "cc-banner";
        banner.innerHTML = createBannerHTML();
        document.body.appendChild(banner);

        // Overlay
        const overlay = document.createElement("div");
        overlay.id = "cc-overlay";
        document.body.appendChild(overlay);

        // Modal
        const modal = document.createElement("div");
        modal.id = "cc-modal";
        modal.setAttribute("role", "dialog");
        modal.setAttribute("aria-modal", "true");
        modal.setAttribute("aria-labelledby", "cc-modal-title");
        modal.innerHTML = createModalHTML();
        document.body.appendChild(modal);

        // Toast
        const toast = document.createElement("div");
        toast.id = "cc-toast";
        toast.setAttribute("role", "status");
        toast.setAttribute("aria-live", "polite");
        toast.innerHTML = createToastHTML();
        document.body.appendChild(toast);
    }

    // ─── Collecte des infos utilisateur / session ─────────────────────────────

    function parseUserAgent(ua) {
        // Navigateur
        let browser = "Inconnu";
        if (/Edg\//.test(ua)) browser = "Edge";
        else if (/OPR\/|Opera/.test(ua)) browser = "Opera";
        else if (/Chrome\//.test(ua)) browser = "Chrome";
        else if (/Safari\//.test(ua)) browser = "Safari";
        else if (/Firefox\//.test(ua)) browser = "Firefox";
        else if (/MSIE|Trident/.test(ua)) browser = "Internet Explorer";

        // OS
        let os = "Inconnu";
        if (/Windows NT 10/.test(ua)) os = "Windows 10/11";
        else if (/Windows NT 6\.3/.test(ua)) os = "Windows 8.1";
        else if (/Windows NT 6\.1/.test(ua)) os = "Windows 7";
        else if (/Windows/.test(ua)) os = "Windows";
        else if (/Android/.test(ua)) os = "Android";
        else if (/iPhone|iPad/.test(ua)) os = "iOS";
        else if (/Mac OS X/.test(ua)) os = "macOS";
        else if (/Linux/.test(ua)) os = "Linux";

        // Type d'appareil
        let device = "Desktop";
        if (/Mobi|Android|iPhone/.test(ua)) device = "Mobile";
        else if (/iPad|Tablet/.test(ua)) device = "Tablette";

        return { browser, os, device };
    }

    function getSessionInfo() {
        // Durée sur la page (en secondes depuis le chargement)
        const sessionDuration = Math.round(
            (Date.now() - performance.timing.navigationStart) / 1000,
        );

        // Pages visitées (stockées dans sessionStorage)
        let pagesVisited = [];
        try {
            const raw = sessionStorage.getItem("cc-pages");
            pagesVisited = raw ? JSON.parse(raw) : [];
        } catch (_) {
            pagesVisited = [];
        }

        // Ajouter la page courante si pas déjà dedans
        const currentPage = window.location.pathname;
        if (!pagesVisited.includes(currentPage)) {
            pagesVisited.push(currentPage);
            try {
                sessionStorage.setItem(
                    "cc-pages",
                    JSON.stringify(pagesVisited),
                );
            } catch (_) {}
        }

        return { sessionDuration, pagesVisited };
    }

    function buildEntry(preferences) {
        const ua = navigator.userAgent;
        const { browser, os, device } = parseUserAgent(ua);
        const { sessionDuration, pagesVisited } = getSessionInfo();

        return {
            date: new Date().toISOString(),
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            site: window.location.origin,
            page: window.location.pathname,
            referrer: document.referrer || null,
            language: navigator.language,
            languages: navigator.languages ? [...navigator.languages] : [],
            screen: `${screen.width}x${screen.height}`,
            viewport: `${window.innerWidth}x${window.innerHeight}`,
            colorDepth: screen.colorDepth,
            cookiesEnabled: navigator.cookieEnabled,
            doNotTrack: navigator.doNotTrack === "1",
            browser,
            os,
            device,
            userAgent: ua,
            sessionDuration,
            pagesVisited,
            preferences,
            // L'IP est récupérée côté PHP (plus fiable et sécurisé)
        };
    }

    function appendToLocalLog(entry) {
        let log = [];
        try {
            const raw = localStorage.getItem(CONFIG.logKey);
            log = raw ? JSON.parse(raw) : [];
        } catch (_) {
            log = [];
        }
        log.push(entry);
        try {
            localStorage.setItem(CONFIG.logKey, JSON.stringify(log));
        } catch (_) {}
    }

    async function sendToServer(entry) {
        try {
            const res = await fetch(CONFIG.endpoint, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(entry),
            });
            if (!res.ok)
                console.warn("[cc-manager] Serveur a répondu :", res.status);
        } catch (err) {
            console.warn("[cc-manager] Impossible d'envoyer au serveur :", err);
        }
    }

    function logAndSend(preferences) {
        const entry = buildEntry(preferences);
        appendToLocalLog(entry); // sauvegarde locale (localStorage)
        sendToServer(entry); // envoi au serveur PHP → consents.json
    }

    // ─── Toast ─────────────────────────────────────────────────────────────────
    function showToast(message) {
        const toast = document.getElementById("cc-toast");
        const msg = document.getElementById("cc-toast-msg");
        if (!toast) return;
        msg.textContent = message || "Préférences enregistrées";
        toast.classList.add("cc-visible");
        setTimeout(() => toast.classList.remove("cc-visible"), 3000);
    }

    // ─── Sauvegarder les préférences ───────────────────────────────────────────
    function savePreferences(preferences) {
        // 1. LocalStorage
        localStorage.setItem(CONFIG.storageKey, JSON.stringify(preferences));
        localStorage.setItem(CONFIG.storageDateKey, new Date().toISOString());

        // 2. Envoi au serveur PHP + sauvegarde locale
        logAndSend(preferences);

        // 3. Fermer banner + modal
        hideBanner();
        hideModal();

        // 4. Toast
        showToast("Préférences enregistrées");

        // 5. Callbacks publics
        if (preferences.analytics || preferences.marketing) {
            if (typeof window.CookieConsent?.onAccept === "function") {
                window.CookieConsent.onAccept(preferences);
            }
        } else {
            if (typeof window.CookieConsent?.onReject === "function") {
                window.CookieConsent.onReject(preferences);
            }
        }

        // 6. Événement personnalisé
        window.dispatchEvent(
            new CustomEvent("cc:saved", { detail: preferences }),
        );
    }

    // ─── Banner ────────────────────────────────────────────────────────────────
    function showBanner() {
        document.getElementById("cc-banner")?.classList.add("cc-visible");
    }
    function hideBanner() {
        document.getElementById("cc-banner")?.classList.remove("cc-visible");
    }

    // ─── Modal ─────────────────────────────────────────────────────────────────
    function showModal() {
        // Pré-remplir les toggles avec les prefs existantes
        const saved = getPreferences();
        if (saved) {
            const toggleA = document.getElementById("cc-toggle-analytics");
            const toggleM = document.getElementById("cc-toggle-marketing");
            if (toggleA) toggleA.checked = !!saved.analytics;
            if (toggleM) toggleM.checked = !!saved.marketing;
        }
        document.getElementById("cc-overlay")?.classList.add("cc-visible");
        document.getElementById("cc-modal")?.classList.add("cc-visible");
    }
    function hideModal() {
        document.getElementById("cc-overlay")?.classList.remove("cc-visible");
        document.getElementById("cc-modal")?.classList.remove("cc-visible");
    }

    // ─── Lire les préférences ──────────────────────────────────────────────────
    function getPreferences() {
        try {
            const raw = localStorage.getItem(CONFIG.storageKey);
            return raw ? JSON.parse(raw) : null;
        } catch (_) {
            return null;
        }
    }

    // ─── Event listeners ───────────────────────────────────────────────────────
    function bindEvents() {
        // Banner
        document
            .getElementById("cc-btn-accept")
            ?.addEventListener("click", () => {
                savePreferences({
                    essential: true,
                    analytics: true,
                    marketing: true,
                });
            });

        document
            .getElementById("cc-btn-reject")
            ?.addEventListener("click", () => {
                savePreferences({
                    essential: true,
                    analytics: false,
                    marketing: false,
                });
            });

        document
            .getElementById("cc-btn-settings")
            ?.addEventListener("click", showModal);

        // Modal
        document
            .getElementById("cc-modal-close")
            ?.addEventListener("click", hideModal);
        document
            .getElementById("cc-overlay")
            ?.addEventListener("click", hideModal);

        document
            .getElementById("cc-btn-save")
            ?.addEventListener("click", () => {
                const analytics =
                    document.getElementById("cc-toggle-analytics")?.checked ||
                    false;
                const marketing =
                    document.getElementById("cc-toggle-marketing")?.checked ||
                    false;
                savePreferences({ essential: true, analytics, marketing });
            });

        document
            .getElementById("cc-btn-accept-all")
            ?.addEventListener("click", () => {
                savePreferences({
                    essential: true,
                    analytics: true,
                    marketing: true,
                });
            });

        // Fermer modal avec Escape
        document.addEventListener("keydown", (e) => {
            if (e.key === "Escape") hideModal();
        });
    }

    // ─── Initialisation ────────────────────────────────────────────────────────
    function init() {
        injectDOM();
        bindEvents();

        const prefs = getPreferences();
        if (!prefs) {
            // Aucun consentement encore — afficher la bannière
            showBanner();
        } else {
            // Appliquer les préférences sauvegardées sans re-télécharger le JSON
            window.dispatchEvent(
                new CustomEvent("cc:loaded", { detail: prefs }),
            );
        }
    }

    // ─── API publique ──────────────────────────────────────────────────────────
    window.CookieConsent = {
        openSettings: showModal,
        getPreferences: getPreferences,
        getLog: () => {
            try {
                const raw = localStorage.getItem(CONFIG.logKey);
                return raw ? JSON.parse(raw) : [];
            } catch (_) {
                return [];
            }
        },
        onAccept: null,
        onReject: null,
    };

    // Lancer après le chargement du DOM
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();

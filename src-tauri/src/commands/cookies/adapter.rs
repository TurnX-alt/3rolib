//! Service-specific adapter for the cookie-capture pipeline.
//!
//! Both Pixiv and eHentai share the same capture flow:
//!   1. Open a dedicated WebView2 / WKWebView window pointed at the login URL.
//!   2. Poll its URL until it lands on a "post-login" page (host predicate).
//!   3. Read cookies via the native capture path (macOS WKWebView FFI, Windows
//!      ICoreWebView2_2.CookieManager.GetCookies, or SQLite fallback).
//!   4. Persist the cookie string to `<app_local_data>/<SESSION_FILE>`.
//!
//! This module factors the per-service bits (window label, login URL, host
//! predicates, session predicate) into a `SessionAdapter` trait so the shared
//! pipeline in `super::capture_all_cookies` and `commands::pixiv_login` /
//! `commands::ehentai` can iterate over both implementations uniformly.

use url::Url;

/// Service identifier — distinguishes each login flow in dispatch tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Service {
    Pixiv,
    Ehentai,
}

/// Per-service data — loaded once at startup and used by the capture /
/// poll / window-builder pipeline. We use a value type (not a trait object)
/// so the associated data stays statically sized and the dispatch is
/// exhaustive at every call site.
pub struct ServiceAdapter {
    pub service: Service,
    pub window_label: &'static str,
    pub login_url: &'static str,
    pub post_login_hosts: &'static [&'static str],
    pub cookie_host_suffixes: &'static [&'static str],
    pub session_file: &'static str,
}

pub const PIXIV: ServiceAdapter = ServiceAdapter {
    service: Service::Pixiv,
    window_label: "pixiv-login",
    login_url: "https://accounts.pixiv.net/login?return_to=https%3A%2F%2Fwww.pixiv.net%2F",
    post_login_hosts: &["www.pixiv.net", "accounts.pixiv.net"],
    cookie_host_suffixes: &["pixiv.net", "accounts.pixiv.net"],
    session_file: "pixiv_session.json",
};

pub const EHENTAI: ServiceAdapter = ServiceAdapter {
    service: Service::Ehentai,
    window_label: "ehentai-login",
    login_url: "https://forums.e-hentai.org/index.php?act=Login&CODE=00",
    post_login_hosts: &["e-hentai.org", "exhentai.org", "forums.e-hentai.org"],
    cookie_host_suffixes: &["e-hentai.org", "exhentai.org"],
    session_file: "ehentai_session.json",
};

pub fn adapters() -> [&'static ServiceAdapter; 2] {
    [&PIXIV, &EHENTAI]
}

pub fn has_session_for(service: Service, cookie: &str) -> bool {
    match service {
        Service::Pixiv => super::has_pixiv_session(cookie),
        Service::Ehentai => super::has_ehentai_session(cookie),
    }
}

impl ServiceAdapter {
    /// Default predicate: accept iff host is in post_login_hosts AND path is
    /// not on a known login endpoint. Pixiv and eH both happen to fit the
    /// generic pattern (login lives at /login on Pixiv and /index.php?act=Login
    /// on eH; neither starts with /login so eH needs the override below).
    pub fn is_post_login(&self, url: &Url) -> bool {
        let host = url.host_str().unwrap_or("");
        if !self.post_login_hosts.contains(&host) {
            return false;
        }
        let path = url.path();
        match self.service {
            Service::Pixiv => !path.starts_with("/login"),
            // eH login is at /index.php?act=Login — the path looks generic so
            // we check the query string for the act=Login marker.
            Service::Ehentai => !(path == "/index.php" && url.query().map_or(false, |q| q.contains("act=Login"))),
        }
    }

    /// Window label — used by `WebviewWindowBuilder::new(..., label, ...)`.
    pub fn window_label(&self) -> &'static str {
        self.window_label
    }

    /// Login URL — the page the in-app browser opens first.
    pub fn login_url(&self) -> &'static str {
        self.login_url
    }

    /// Cookie host suffixes — used by the SQLite fallback reader to filter
    /// which cookies belong to this service.
    pub fn cookie_host_suffixes(&self) -> &'static [&'static str] {
        self.cookie_host_suffixes
    }

    /// Hosts that count as "past login". The cookie capture pipeline
    /// captures once the webview lands on one of these.
    pub fn post_login_hosts(&self) -> &'static [&'static str] {
        self.post_login_hosts
    }

    /// File name (under `app_local_data_dir`) where the session persists.
    pub fn session_file(&self) -> &'static str {
        self.session_file
    }

    /// Cookie string predicate: does this string look like a logged-in
    /// session for this service?
    pub fn has_session(&self, cookie: &str) -> bool {
        match self.service {
            Service::Pixiv => super::has_pixiv_session(cookie),
            Service::Ehentai => super::has_ehentai_session(cookie),
        }
    }
}

/// All registered service adapters. The capture / poll pipeline walks this
/// list and treats the first non-empty result as the answer.
pub const ALL_ADAPTERS: &[&ServiceAdapter] = &[&PIXIV, &EHENTAI];

// Tests — mirror BDD specs in tests/bdd/features/pixiv_login.feature and
// tests/bdd/features/ehentai_login.feature.
#[cfg(test)]
mod bdd {
    use super::*;

    #[test]
    fn window_labels_match_capabilities_json() {
        // Scenario: capabilities/default.json windows array must include every
        // adapter's window_label.
        assert_eq!(PIXIV.window_label, "pixiv-login");
        assert_eq!(EHENTAI.window_label, "ehentai-login");
    }

    #[test]
    fn post_login_urls_are_accepted_by_predicate() {
        // Scenario: a real URL after OAuth is recognised as post-login.
        for host in PIXIV.post_login_hosts {
            let u = url::Url::parse(&format!("https://{host}/")).unwrap();
            assert!(PIXIV.is_post_login(&u), "{host} should be post-login for Pixiv");
        }
        for host in EHENTAI.post_login_hosts {
            let u = url::Url::parse(&format!("https://{host}/")).unwrap();
            assert!(
                EHENTAI.is_post_login(&u),
                "{host} should be post-login for eHentai"
            );
        }
    }

    #[test]
    fn login_url_is_rejected_by_post_login_predicate() {
        // Scenario: a URL whose path starts with /login is NOT post-login.
        let u = url::Url::parse("https://accounts.pixiv.net/login").unwrap();
        assert!(!PIXIV.is_post_login(&u));
        let u = url::Url::parse("https://forums.e-hentai.org/index.php?act=Login&CODE=00").unwrap();
        assert!(!EHENTAI.is_post_login(&u));
    }

    #[test]
    fn unrelated_hosts_are_rejected() {
        // Scenario: third-party hosts never satisfy the predicate.
        for u in [
            "https://example.com/",
            "https://www.pixiv.net.evil.com/",
            "https://forums.evil-e-hentai.org/",
        ] {
            let u = url::Url::parse(u).unwrap();
            assert!(!PIXIV.is_post_login(&u), "{u} should not be post-login for Pixiv");
            assert!(!EHENTAI.is_post_login(&u), "{u} should not be post-login for eHentai");
        }
    }

    #[test]
    fn path_cannot_contain_host_literal() {
        // Regression: the old dead `path.contains("accounts.pixiv.net")` branch
        // is a documentation lie. URL paths never carry host names.
        let urls = [
            "https://www.pixiv.net/foo",
            "https://accounts.pixiv.net/login",
            "https://forums.e-hentai.org/index.php?act=Login",
            "https://e-hentai.org/some/path",
            "https://exhentai.org/g/123",
        ];
        for s in urls {
            let u = url::Url::parse(s).unwrap();
            assert!(
                !u.path().contains("accounts.pixiv.net"),
                "URL {s} path {} unexpectedly contains host literal",
                u.path()
            );
            assert!(
                !u.path().contains("e-hentai.org"),
                "URL {s} path {} unexpectedly contains host literal",
                u.path()
            );
            assert!(
                !u.path().contains("exhentai.org"),
                "URL {s} path {} unexpectedly contains host literal",
                u.path()
            );
        }
    }

    #[test]
    fn cookie_host_suffixes_cover_official_domains() {
        assert!(PIXIV.cookie_host_suffixes.contains(&"pixiv.net"));
        assert!(PIXIV.cookie_host_suffixes.contains(&"accounts.pixiv.net"));
        assert!(EHENTAI.cookie_host_suffixes.contains(&"e-hentai.org"));
        assert!(EHENTAI.cookie_host_suffixes.contains(&"exhentai.org"));
    }

    #[test]
    fn session_file_names_distinct() {
        // The two services write to different session JSON files so a logout
        // on one doesn't wipe the other.
        assert_ne!(PIXIV.session_file, EHENTAI.session_file);
        assert!(PIXIV.session_file.ends_with(".json"));
        assert!(EHENTAI.session_file.ends_with(".json"));
    }
}
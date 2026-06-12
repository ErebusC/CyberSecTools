/// Configuration for a clickjacker session.
pub struct Config {
    pub target_url: String,
    pub collab_url: Option<String>,
    pub logo: Option<LogoSource>,
    pub port: u16,
}

/// Where the nav-bar logo image comes from.
pub enum LogoSource {
    /// A remote URL served directly to the browser.
    RemoteUrl(String),
    /// A local file the server reads and re-serves at `/logo-img`.
    LocalFile(std::path::PathBuf),
}

impl Default for Config {
    fn default() -> Self {
        Self {
            target_url: "https://economist.com".to_owned(),
            collab_url: None,
            logo: None,
            port: 9999,
        }
    }
}

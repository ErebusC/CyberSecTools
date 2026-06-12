use std::borrow::Cow;

/// Pre-defined decoy overlay templates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecoyTemplate {
    FakeButton,
    Survey,
    Security,
    Reward,
    Custom(String),
}

impl DecoyTemplate {
    /// Returns the HTML string for this template.
    pub fn html(&self) -> Cow<str> {
        match self {
            DecoyTemplate::FakeButton => Cow::Borrowed(
                r#"<button style="padding:10px 24px;font-size:1em;background:#4a90e2;color:white;border:none;border-radius:4px;cursor:pointer;">Click to Continue</button>"#,
            ),
            DecoyTemplate::Survey => Cow::Borrowed(
                r#"<div style="background:white;color:#333;padding:14px 18px;border-radius:6px;box-shadow:0 2px 8px rgba(0,0,0,.3);text-align:center;font-family:Arial,sans-serif;cursor:pointer;">
    &#128203; Quick survey!<br><strong>Click to participate</strong>
  </div>"#,
            ),
            DecoyTemplate::Security => Cow::Borrowed(
                r#"<div style="background:#c0392b;color:white;padding:14px 18px;border-radius:4px;text-align:center;font-family:Arial,sans-serif;cursor:pointer;font-weight:bold;">
    &#9888; Security verification required<br>
    <span style="font-weight:normal;font-size:.9em;">Click to proceed</span>
  </div>"#,
            ),
            DecoyTemplate::Reward => Cow::Borrowed(
                r#"<div style="background:#e67e22;color:white;padding:14px 18px;border-radius:6px;text-align:center;font-family:Arial,sans-serif;cursor:pointer;font-weight:bold;">
    &#127881; Congratulations! You've won.<br>
    <span style="font-weight:normal;font-size:.9em;">Click to claim your reward</span>
  </div>"#,
            ),
            DecoyTemplate::Custom(html) => Cow::Owned(html.clone()),
        }
    }

    /// Parse a template key string as used in the select element.
    pub fn from_key(key: &str) -> Option<Self> {
        match key {
            "fake-button" => Some(DecoyTemplate::FakeButton),
            "survey" => Some(DecoyTemplate::Survey),
            "security" => Some(DecoyTemplate::Security),
            "reward" => Some(DecoyTemplate::Reward),
            "custom" => Some(DecoyTemplate::Custom(String::new())),
            _ => None,
        }
    }
}

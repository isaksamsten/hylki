//! Optional, read-only LDAP recipient lookup. Never query the directory on the UI thread.
use ldap3::{LdapConn, LdapConnSettings, Scope, SearchEntry, SearchOptions};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::contacts::Suggestion;

#[derive(Clone, Deserialize, Serialize)]
pub struct Directory {
    /// Only verified LDAPS or LDAP upgraded with StartTLS is permitted.
    pub url: String,
    pub base_dn: String,
    #[serde(default)]
    pub bind_dn: String,
    /// Keyring lookup name; password is stored as `ldap:<password_key>`.
    #[serde(default)]
    pub password_key: String,
}

#[derive(Deserialize, Serialize)]
struct Config {
    #[serde(default)]
    directories: Vec<Directory>,
}

fn path() -> std::io::Result<std::path::PathBuf> {
    crate::config::config_base()
        .map(|d| d.join("hylki/ldap.toml"))
        .ok_or_else(|| std::io::Error::other("Configuration directory is unavailable"))
}

pub fn load_directories() -> Result<Vec<Directory>, String> {
    let path = path().map_err(|e| e.to_string())?;
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.to_string()),
    };
    toml::from_str::<Config>(&text)
        .map(|c| c.directories)
        .map_err(|e| e.to_string())
}

pub fn save_directories(directories: &[Directory]) -> Result<(), String> {
    let text = toml::to_string_pretty(&Config {
        directories: directories.to_vec(),
    })
    .map_err(|e| e.to_string())?;
    let path = path().map_err(|e| e.to_string())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    crate::config::write_private_file(&path, &text).map_err(|e| e.to_string())
}

pub fn directories() -> Vec<Directory> {
    match load_directories() {
        Ok(dirs) => dirs,
        Err(e) => {
            tracing::warn!("Could not read LDAP configuration: {e}");
            Vec::new()
        }
    }
}

/// RFC 4515 assertion value escaping (including NUL and filter metacharacters).
fn escape_filter(input: &str) -> String {
    let mut escaped = String::new();
    for ch in input.chars() {
        match ch {
            '*' => escaped.push_str("\\2a"),
            '(' => escaped.push_str("\\28"),
            ')' => escaped.push_str("\\29"),
            '\\' => escaped.push_str("\\5c"),
            '\0' => escaped.push_str("\\00"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

pub fn search(dirs: &[Directory], query: &str) -> Vec<Suggestion> {
    if query.chars().count() < 3 || query.len() > 128 {
        return Vec::new();
    }
    tracing::debug!(directories = dirs.len(), query_length = query.chars().count(), "LDAP lookup started");
    let mut out = Vec::new();
    for dir in dirs {
        match search_one(dir, query) {
            Ok(found) => {
                tracing::debug!(url = %dir.url, base_dn = %dir.base_dn, count = found.len(), "LDAP directory returned suggestions");
                out.extend(found);
            }
            Err(err) => tracing::warn!(url = %dir.url, base_dn = %dir.base_dn, "LDAP recipient lookup failed: {err}"),
        }
    }
    tracing::debug!(count = out.len(), "LDAP lookup finished");
    out
}

fn search_one(dir: &Directory, query: &str) -> ldap3::result::Result<Vec<Suggestion>> {
    let starttls = dir.url.starts_with("ldap://");
    if !starttls && !dir.url.starts_with("ldaps://") {
        tracing::warn!("LDAP directory must use ldap:// (StartTLS) or ldaps://");
        return Ok(Vec::new());
    }
    let settings = LdapConnSettings::new()
        .set_conn_timeout(Duration::from_secs(3))
        .set_starttls(starttls);
    let mut conn = LdapConn::with_settings(settings, &dir.url)?;
    if !dir.bind_dn.is_empty() {
        let password = crate::config::load_cloud_password(&format!("ldap:{}", dir.password_key));
        let Some(password) = password else {
            tracing::warn!(url = %dir.url, "LDAP bind password is unavailable in the keyring");
            return Ok(Vec::new());
        };
        conn.with_timeout(Duration::from_secs(3))
            .simple_bind(&dir.bind_dn, &password)?
            .success()?;
    }
    let q = escape_filter(query);
    let filter = format!("(&(mail=*)(|(cn=*{q}*)(mail=*{q}*)))");
    let result = conn
        .with_timeout(Duration::from_secs(3))
        .with_search_options(SearchOptions::new().sizelimit(20).timelimit(3))
        .search(&dir.base_dn, Scope::Subtree, &filter, vec!["cn", "mail"])?;
    // A server may return sizeLimitExceeded *with* the first 20 useful entries.
    let entries = if result.1.rc == 4 {
        tracing::debug!(url = %dir.url, count = result.0.len(), "LDAP server size limit reached; using returned entries");
        result.0
    } else {
        result.success()?.0
    };
    let mut out = Vec::new();
    for entry in entries {
        let entry = SearchEntry::construct(entry);
        let name = entry
            .attrs
            .get("cn")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();
        if let Some(emails) = entry.attrs.get("mail") {
            for email in emails {
                if !email.contains('@') || email.contains(['\r', '\n']) {
                    continue;
                }
                out.push(Suggestion {
                    name: name.clone(),
                    email: email.clone(),
                    from_contacts: true,
                    score: 0,
                    own: false,
                });
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::escape_filter;
    #[test]
    fn filter_injection_is_escaped() {
        assert_eq!(
            escape_filter("a*)(mail=*)\\\0"),
            "a\\2a\\29\\28mail=\\2a\\29\\5c\\00"
        );
    }
}

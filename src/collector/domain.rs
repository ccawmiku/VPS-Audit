use std::net::IpAddr;

pub const UNIDENTIFIED_DOMAIN: &str = "未识别";

/// Normalizes a raw SNI or HTTP Host value into a lowercase hostname without port or trailing dot.
pub fn normalize_hostname(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('.');
    if trimmed.is_empty() || trimmed.len() > 255 {
        return None;
    }

    // Strip optional `:port` (handle bracketed IPv6 if any, though v1 targets IPv4).
    let host_no_port = if let Some(rest) = trimmed.strip_prefix('[') {
        rest.split(']').next()?
    } else if let Some((host, port)) = trimmed.rsplit_once(':') {
        if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
            host
        } else {
            trimmed
        }
    } else {
        trimmed
    };

    let normalized = host_no_port.trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() || normalized.len() > 253 {
        return None;
    }

    // Reject control chars / whitespace / invalid slashes.
    if !normalized
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_' || b == b':')
    {
        return None;
    }

    // Reject consecutive dots or leading/trailing dots/hyphens on labels.
    if normalized.parse::<IpAddr>().is_err() {
        for label in normalized.split('.') {
            if label.is_empty() || label.len() > 63 {
                return None;
            }
            if label.starts_with('-') || label.ends_with('-') {
                return None;
            }
        }
    }

    Some(normalized)
}

/// Extracts the registrable root domain using the Public Suffix List.
pub fn extract_root_domain(host: &str) -> String {
    if host == UNIDENTIFIED_DOMAIN {
        return UNIDENTIFIED_DOMAIN.to_string();
    }
    if host.parse::<IpAddr>().is_ok() {
        return host.to_string();
    }
    match psl::domain_str(host) {
        Some(root) if !root.is_empty() => root.to_string(),
        _ => host.to_string(),
    }
}

/// Optional human-friendly service label for well-known domains / CDNs.
pub fn service_label(root_domain: &str) -> Option<&'static str> {
    match root_domain {
        "googlevideo.com" => Some("YouTube 视频流"),
        "youtube.com" | "youtu.be" => Some("YouTube"),
        "ytimg.com" | "ggpht.com" => Some("YouTube 静态资源"),
        "google.com" | "googleapis.com" | "gstatic.com" | "googleusercontent.com" => Some("Google"),
        "github.com" | "githubusercontent.com" | "githubassets.com" => Some("GitHub"),
        "x.com" | "twitter.com" | "twimg.com" | "t.co" => Some("X / Twitter"),
        "openai.com" | "chatgpt.com" | "oaistatic.com" | "oaiusercontent.com" => Some("OpenAI / ChatGPT"),
        "anthropic.com" | "claude.ai" => Some("Claude"),
        "telegram.org" | "t.me" | "tdesktop.com" => Some("Telegram"),
        "microsoft.com" | "msn.com" | "live.com" | "azure.com" | "windowsupdate.com" => Some("Microsoft"),
        "apple.com" | "icloud.com" | "mzstatic.com" => Some("Apple"),
        "cloudflare.com" | "cloudflare-ech.com" | "cloudflareinsights.com" => Some("Cloudflare"),
        "netflix.com" | "nflxvideo.net" | "nflximg.net" => Some("Netflix"),
        "reddit.com" | "redd.it" | "redditmedia.com" => Some("Reddit"),
        "discord.com" | "discordapp.com" | "discord.gg" => Some("Discord"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_and_extracts_psl_root() {
        assert_eq!(
            normalize_hostname("API.GitHub.COM:443.").as_deref(),
            Some("api.github.com")
        );
        assert_eq!(
            extract_root_domain("rr3---sn-ogueln7z.googlevideo.com"),
            "googlevideo.com"
        );
        assert_eq!(extract_root_domain("sub.example.co.jp"), "example.co.jp");
        assert_eq!(extract_root_domain("1.1.1.1"), "1.1.1.1");
        assert_eq!(normalize_hostname("bad/host"), None);
    }
}

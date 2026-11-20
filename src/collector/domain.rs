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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficKind {
    Ai,
    Video,
    Social,
    Development,
    Cloud,
    Platform,
    Games,
    Files,
    Other,
    Unidentified,
}

/// Maps a registrable domain or an explicitly known host to its service and traffic category.
fn service(domain: &str) -> Option<(&'static str, TrafficKind)> {
    use TrafficKind::*;

    Some(match domain {
        "openai.com" | "chatgpt.com" | "oaistatic.com" | "oaiusercontent.com"
        | "oaistatsig.com" | "openaimerge.com" => ("OpenAI / ChatGPT", Ai),
        "anthropic.com" | "claude.ai" | "claudeusercontent.com" => ("Anthropic / Claude", Ai),
        "gemini.google.com" | "aistudio.google.com" | "generativelanguage.googleapis.com" => {
            ("Google Gemini", Ai)
        }
        "copilot.microsoft.com" | "copilot.com" => ("Microsoft Copilot", Ai),
        "deepseek.com" => ("DeepSeek", Ai),
        "grok.com" | "x.ai" => ("xAI / Grok", Ai),
        "perplexity.ai" => ("Perplexity", Ai),
        "kimi.com" | "moonshot.cn" | "moonshot.ai" => ("Kimi / Moonshot", Ai),
        "qwen.ai" => ("Qwen", Ai),
        "openrouter.ai" => ("OpenRouter", Ai),
        "poe.com" => ("Poe", Ai),
        "cursor.com" | "cursor.sh" => ("Cursor", Ai),
        "windsurf.com" | "codeium.com" => ("Windsurf", Ai),
        "midjourney.com" => ("Midjourney", Ai),
        "huggingface.co" | "hf.co" => ("Hugging Face", Ai),
        "mistral.ai" => ("Mistral AI", Ai),

        "googlevideo.com" => ("YouTube 视频流", Video),
        "youtube.com" | "youtu.be" | "youtube-nocookie.com" => ("YouTube", Video),
        "ytimg.com" | "ggpht.com" => ("YouTube 静态资源", Video),
        "netflix.com" | "nflxvideo.net" | "nflximg.net" | "nflxext.com" | "nflxso.net" => {
            ("Netflix", Video)
        }
        "twitch.tv" | "ttvnw.net" | "jtvnw.net" | "twitchcdn.net" => ("Twitch", Video),
        "bilibili.com" | "bilivideo.com" | "bilivideo.cn" | "hdslb.com" | "b23.tv" => {
            ("哔哩哔哩", Video)
        }
        "disneyplus.com" | "disney-plus.net" => ("Disney+", Video),
        "primevideo.com" | "amazonvideo.com" | "aiv-cdn.net" => ("Prime Video", Video),
        "tiktok.com" | "tiktokcdn.com" | "tiktokv.com" => ("TikTok", Video),
        "vimeo.com" | "vimeocdn.com" => ("Vimeo", Video),
        "spotify.com" | "spotifycdn.com" | "scdn.co" => ("Spotify", Video),
        "douyin.com" | "douyinvod.com" => ("抖音", Video),

        "x.com" | "twitter.com" | "twimg.com" | "t.co" => ("X / Twitter", Social),
        "telegram.org" | "t.me" | "tdesktop.com" | "telegram.me" => ("Telegram", Social),
        "reddit.com" | "redd.it" | "redditmedia.com" | "redditstatic.com" => ("Reddit", Social),
        "discord.com" | "discordapp.com" | "discord.gg" | "discordapp.net" => ("Discord", Social),
        "facebook.com" | "fbcdn.net" | "fb.com" | "messenger.com" => {
            ("Facebook / Messenger", Social)
        }
        "instagram.com" | "cdninstagram.com" => ("Instagram", Social),
        "whatsapp.com" | "whatsapp.net" => ("WhatsApp", Social),
        "linkedin.com" | "licdn.com" => ("LinkedIn", Social),
        "signal.org" => ("Signal", Social),
        "line.me" | "line-scdn.net" => ("LINE", Social),
        "weibo.com" | "weibo.cn" | "sinaimg.cn" => ("微博", Social),
        "xiaohongshu.com" | "xhscdn.com" | "xhslink.com" => ("小红书", Social),

        "github.com" | "githubusercontent.com" | "githubassets.com" => ("GitHub", Development),
        "gitlab.com" => ("GitLab", Development),
        "bitbucket.org" => ("Bitbucket", Development),
        "npmjs.com" | "npmjs.org" => ("npm", Development),
        "pypi.org" | "pythonhosted.org" => ("PyPI", Development),
        "crates.io" | "rust-lang.org" => ("Rust / crates.io", Development),
        "golang.org" | "go.dev" => ("Go", Development),
        "docker.com" | "docker.io" => ("Docker", Development),
        "stackoverflow.com" | "stackexchange.com" => ("Stack Overflow", Development),
        "mozilla.org" | "addons.mozilla.org" => ("Mozilla", Development),
        "visualstudio.com" | "vscode.dev" => ("Visual Studio / VS Code", Development),
        "sentry.io" | "sentry-cdn.com" => ("Sentry", Development),
        "datadoghq.com" | "datadoghq.eu" => ("Datadog", Development),

        "cloudflare.com"
        | "cloudflare-ech.com"
        | "cloudflareinsights.com"
        | "cloudflareaccess.com"
        | "cfargotunnel.com" => ("Cloudflare", Cloud),
        "workers.dev" | "pages.dev" => ("Cloudflare 托管", Cloud),
        "amazonaws.com" | "awsstatic.com" => ("Amazon Web Services", Cloud),
        "cloudfront.net" => ("Amazon CloudFront", Cloud),
        "azure.com" | "azurewebsites.net" | "azureedge.net" | "windows.net" => {
            ("Microsoft Azure", Cloud)
        }
        "fastly.net" | "fastly.com" => ("Fastly", Cloud),
        "akamai.net" | "akamaihd.net" | "akamaized.net" | "edgekey.net" | "edgesuite.net" => {
            ("Akamai", Cloud)
        }
        "jsdelivr.net" | "jsdelivr.com" => ("jsDelivr", Cloud),
        "vercel.app" | "vercel.com" => ("Vercel", Cloud),
        "netlify.app" | "netlify.com" => ("Netlify", Cloud),
        "aliyuncs.com" | "alicdn.com" => ("阿里云 / CDN", Cloud),
        "myqcloud.com" | "qcloud.com" | "qcloudcdn.com" => ("腾讯云 / CDN", Cloud),

        "google.com" | "gstatic.com" | "googleusercontent.com" => ("Google", Platform),
        "googleapis.com" => ("Google APIs", Platform),
        "gmail.com" | "googlemail.com" => ("Gmail", Platform),
        "microsoft.com" | "msn.com" | "live.com" | "office.com" | "microsoftonline.com" => {
            ("Microsoft", Platform)
        }
        "windowsupdate.com" => ("Windows Update", Platform),
        "bing.com" => ("必应", Platform),
        "apple.com" | "mzstatic.com" | "apple-cloudkit.com" => ("Apple", Platform),
        "duckduckgo.com" => ("DuckDuckGo", Platform),
        "baidu.com" | "bdstatic.com" => ("百度", Platform),
        "yahoo.com" | "yimg.com" => ("Yahoo", Platform),
        "wikipedia.org" | "wikimedia.org" => ("维基百科", Platform),
        "amazon.com" | "media-amazon.com" => ("Amazon", Platform),
        "taobao.com" | "tmall.com" => ("淘宝 / 天猫", Platform),
        "jd.com" | "360buyimg.com" => ("京东", Platform),

        "steampowered.com" | "steamcommunity.com" | "steamstatic.com" | "steamcontent.com" => {
            ("Steam", Games)
        }
        "epicgames.com" | "epicgames.dev" => ("Epic Games", Games),
        "xbox.com" | "xboxlive.com" => ("Xbox", Games),
        "playstation.com" | "playstation.net" => ("PlayStation", Games),
        "riotgames.com" | "riotcdn.net" | "leagueoflegends.com" => ("Riot Games", Games),
        "blizzard.com" | "battle.net" => ("暴雪 / 战网", Games),
        "roblox.com" | "rbxcdn.com" => ("Roblox", Games),

        "dropbox.com" | "dropboxusercontent.com" | "dropboxstatic.com" => ("Dropbox", Files),
        "icloud.com" | "icloud-content.com" => ("iCloud", Files),
        "onedrive.com" | "1drv.ms" | "sharepoint.com" => ("OneDrive / SharePoint", Files),
        "drive.google.com" | "docs.google.com" => ("Google Drive / Docs", Files),
        "mega.nz" | "mega.io" => ("MEGA", Files),
        "box.com" | "boxcdn.net" => ("Box", Files),
        "wetransfer.com" | "we.tl" => ("WeTransfer", Files),

        _ if domain.ends_with(".github.io") => ("GitHub Pages", Cloud),
        _ if domain.ends_with(".amazonaws.com") => ("Amazon Web Services", Cloud),
        _ if domain.ends_with(".cloudfront.net") => ("Amazon CloudFront", Cloud),
        _ if domain.ends_with(".workers.dev") || domain.ends_with(".pages.dev") => {
            ("Cloudflare 托管", Cloud)
        }
        _ if domain.ends_with(".azurewebsites.net")
            || domain.ends_with(".blob.core.windows.net") =>
        {
            ("Microsoft Azure", Cloud)
        }
        _ if domain.ends_with(".vercel.app") => ("Vercel", Cloud),
        _ if domain.ends_with(".netlify.app") => ("Netlify", Cloud),
        _ if domain.ends_with(".sharepoint.com") => ("OneDrive / SharePoint", Files),
        _ => return None,
    })
}

pub fn service_label(domain: &str) -> Option<&'static str> {
    service(domain).map(|(label, _)| label)
}

pub fn traffic_kind(domain: &str) -> TrafficKind {
    if domain == UNIDENTIFIED_DOMAIN {
        TrafficKind::Unidentified
    } else {
        service(domain).map_or(TrafficKind::Other, |(_, kind)| kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_observed_domains_without_matching_unrelated_suffixes() {
        assert_eq!(traffic_kind("oaistatsig.com"), TrafficKind::Ai);
        assert_eq!(service_label("gemini.google.com"), Some("Google Gemini"));
        assert_eq!(traffic_kind("google.com"), TrafficKind::Platform);
        assert_eq!(traffic_kind("example.workers.dev"), TrafficKind::Cloud);
        assert_eq!(traffic_kind("workers.dev.example.com"), TrafficKind::Other);
        assert_eq!(traffic_kind(UNIDENTIFIED_DOMAIN), TrafficKind::Unidentified);
    }

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

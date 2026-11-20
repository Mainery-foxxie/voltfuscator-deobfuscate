use serde_json::Value;
use serenity::{
    Client,
    all::{Context, CreateAttachment, CreateMessage, EventHandler, GatewayIntents, Message, Ready},
    async_trait,
};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::sync::Semaphore;

const MAX_INPUT: usize = 2 * 1024 * 1024;
const MAX_OUTPUT: u64 = 7 * 1024 * 1024;

struct Bot {
    users: HashSet<u64>,
    slot: Arc<Semaphore>,
    download: reqwest::Client,
}

fn valid_attachment(url: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(url) else {
        return false;
    };
    url.scheme() == "https"
        && matches!(
            url.host_str(),
            Some("cdn.discordapp.com" | "media.discordapp.net")
        )
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
}

fn is_deobf_command(content: &str) -> bool {
    content.split_whitespace().next() == Some("!deobf")
}

fn manifest_artifact(output: &Path, name: &str) -> Result<PathBuf, String> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err("Worker manifest contains an unsafe artifact name".into());
    }
    let root = std::fs::canonicalize(output)
        .map_err(|_| "Worker output directory is unavailable".to_string())?;
    let path = output.join(name);
    let canonical = std::fs::canonicalize(&path)
        .map_err(|_| "Worker manifest references a missing artifact".to_string())?;
    if canonical.parent() != Some(root.as_path()) {
        return Err("Worker manifest artifact is outside its output directory".into());
    }
    Ok(path)
}

fn read_manifest_artifact(output: &Path, name: &str) -> Result<Vec<u8>, String> {
    let path = manifest_artifact(output, name)?;
    let metadata = std::fs::metadata(&path)
        .map_err(|_| "Worker artifact metadata is unavailable".to_string())?;
    if !metadata.is_file() || metadata.len() > MAX_OUTPUT {
        return Err("Worker artifact exceeds the 7 MiB limit".into());
    }
    let bytes = std::fs::read(path).map_err(|_| "Worker artifact could not be read".to_string())?;
    if bytes.len() as u64 > MAX_OUTPUT {
        return Err("Worker artifact exceeds the 7 MiB limit".into());
    }
    Ok(bytes)
}

fn artifact_names_for_status(status: &str, value: &Value) -> Result<Vec<String>, String> {
    let values = value
        .as_array()
        .ok_or("Worker report has no artifact manifest")?;
    let mut names = Vec::with_capacity(values.len());
    for value in values {
        let name = value
            .as_str()
            .ok_or("Worker report contains a non-string artifact name")?;
        if names.iter().any(|existing| existing == name) {
            return Err("Worker report contains a duplicate artifact name".into());
        }
        names.push(name.to_string());
    }
    if !names.iter().any(|name| name == "report.json") {
        return Err("Worker report is not listed as an artifact".into());
    }
    match status {
        "clean_lift" => {
            if !names.iter().any(|name| {
                matches!(
                    name.as_str(),
                    "CoPlay_Legit_Trivia_Only.clean.luau" | "chess.lifted.luau"
                )
            }) || names
                .iter()
                .any(|name| name.ends_with(".partial.luau") || name == "lifted-ir.json")
            {
                return Err("Clean report contains no safe clean source artifact".into());
            }
            if names.iter().any(|name| {
                !matches!(
                    name.as_str(),
                    "CoPlay_Legit_Trivia_Only.clean.luau"
                        | "chess.lifted.luau"
                        | "anti-tamper-report.json"
                        | "lift-report.json"
                        | "report.json"
                )
            }) {
                return Err("Clean report contains an unapproved artifact".into());
            }
        }
        "partial" => {
            if !names
                .iter()
                .any(|name| matches!(name.as_str(), "source.partial.luau" | "chess.partial.luau"))
                || names
                    .iter()
                    .any(|name| name == "chess.lifted.luau" || name.ends_with(".clean.luau"))
            {
                return Err("Partial report contains no safe partial source artifact".into());
            }
            if names.iter().any(|name| {
                !matches!(
                    name.as_str(),
                    "source.partial.luau" | "chess.partial.luau" | "report.json"
                )
            }) {
                return Err("Partial report contains an unapproved artifact".into());
            }
        }
        "unsupported" | "error" => {
            if names != ["report.json"] {
                return Err("Unsupported or error reports may attach only report.json".into());
            }
        }
        _ => return Err("Worker report has an unknown status".into()),
    }
    Ok(names)
}

fn reply_for_status(status: &str) -> &'static str {
    match status {
        "clean_lift" => "Clean lift completed. The source and validation reports are attached.",
        "partial" => {
            "Partial recovery completed. The artifact remains incomplete; read the coverage report."
        }
        "unsupported" => "This input is unsupported. The diagnostic report is attached.",
        _ => "Recovery failed operationally. The diagnostic report is attached.",
    }
}

struct RecoveryResult {
    status: String,
    files: Vec<(String, Vec<u8>)>,
}

impl Bot {
    async fn recover(&self, message: &Message) -> Result<RecoveryResult, String> {
        let attachment = message
            .attachments
            .first()
            .ok_or("Attach one .luau, .lua, or .txt file to !deobf.")?;
        if message.attachments.len() != 1 {
            return Err("Attach one file per request.".into());
        }
        if attachment.size as usize > MAX_INPUT {
            return Err("Input exceeds the 2 MiB limit.".into());
        }
        let extension = attachment
            .filename
            .rsplit('.')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        if !matches!(extension.as_str(), "lua" | "luau" | "txt") {
            return Err("Expected a .lua, .luau, or .txt attachment.".into());
        }
        if !valid_attachment(&attachment.url) {
            return Err("Attachment URL is outside Discord's CDN.".into());
        }
        let mut response = self
            .download
            .get(&attachment.url)
            .send()
            .await
            .map_err(|_| "Attachment download failed")?
            .error_for_status()
            .map_err(|_| "Discord rejected the attachment download")?;
        let mut source = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| "Attachment download interrupted")?
        {
            if source.len() + chunk.len() > MAX_INPUT {
                return Err("Downloaded input exceeds the 2 MiB limit.".into());
            }
            source.extend_from_slice(&chunk);
        }
        let work = tempfile::tempdir().map_err(|_| "Cannot create job directory")?;
        let input = work.path().join("input.luau");
        tokio::fs::write(&input, &source)
            .await
            .map_err(|_| "Cannot write job input")?;
        let worker = std::env::current_exe()
            .map_err(|_| "Cannot locate worker")?
            .with_file_name(if cfg!(windows) {
                "chess-deobf.exe"
            } else {
                "chess-deobf"
            });
        let output = work.path().join("result");
        let mut command = tokio::process::Command::new(worker);
        command
            .args(["--auto"])
            .arg(&input)
            .arg(&output)
            .kill_on_drop(true)
            .current_dir(work.path())
            .env_remove("DISCORD_TOKEN")
            .stdin(std::process::Stdio::null());
        let result = tokio::time::timeout(Duration::from_secs(90), command.output())
            .await
            .map_err(|_| "Recovery exceeded the 90-second limit")?
            .map_err(|_| "Cannot start worker; build both binaries first")?;
        if !result.status.success() {
            return Err("Recovery failed or this Voltfuscator build is unsupported. No complete result was produced.".into());
        }
        if tokio::fs::read(&input)
            .await
            .map_err(|_| "Worker input could not be verified")?
            != source
        {
            return Err("Worker changed the recovery input".into());
        }
        let report_bytes = read_manifest_artifact(&output, "report.json")?;
        let report: Value =
            serde_json::from_slice(&report_bytes).map_err(|_| "Worker report is not valid JSON")?;
        let status = report["status"]
            .as_str()
            .ok_or("Worker report has no status")?
            .to_string();
        let names = artifact_names_for_status(&status, &report["artifacts"])?;
        let files = names
            .into_iter()
            .map(|name| {
                let bytes = if name == "report.json" {
                    report_bytes.clone()
                } else {
                    read_manifest_artifact(&output, &name)?
                };
                Ok((name, bytes))
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(RecoveryResult { status, files })
    }
}

#[async_trait]
impl EventHandler for Bot {
    async fn ready(&self, _: Context, ready: Ready) {
        println!(
            "Connected as {}. !deobf is limited to configured users.",
            ready.user.name
        );
    }
    async fn message(&self, ctx: Context, message: Message) {
        if message.author.bot
            || !self.users.contains(&message.author.id.get())
            || !is_deobf_command(&message.content)
        {
            return;
        }
        let Ok(_permit) = self.slot.clone().try_acquire_owned() else {
            let _ = message
                .reply(
                    &ctx.http,
                    "The worker is busy. Try again after its current job finishes.",
                )
                .await;
            return;
        };
        let _typing = message.channel_id.start_typing(&ctx.http);
        match self.recover(&message).await {
            Ok(result) => {
                let reply = CreateMessage::new()
                    .reference_message(&message)
                    .content(reply_for_status(&result.status))
                    .files(
                        result
                            .files
                            .into_iter()
                            .map(|(name, bytes)| CreateAttachment::bytes(bytes, name)),
                    );
                if let Err(error) = message.channel_id.send_message(&ctx.http, reply).await {
                    eprintln!("Cannot send recovery attachments: {error}");
                }
            }
            Err(error) => {
                if let Err(error) = message.reply(&ctx.http, error).await {
                    eprintln!("Cannot send recovery error: {error}");
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let token =
        std::env::var("DISCORD_TOKEN").map_err(|_| "Set DISCORD_TOKEN in the environment")?;
    let users: HashSet<u64> = std::env::var("DISCORD_ALLOWED_USERS")
        .map_err(|_| "Set DISCORD_ALLOWED_USERS to comma-separated Discord user IDs")?
        .split(',')
        .map(str::trim)
        .map(str::parse)
        .collect::<Result<_, _>>()?;
    if users.is_empty() {
        return Err("Configure at least one allowed user".into());
    }
    let handler = Bot {
        users,
        slot: Arc::new(Semaphore::new(1)),
        download: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()?,
    };
    let intents = GatewayIntents::GUILD_MESSAGES
        | GatewayIntents::DIRECT_MESSAGES
        | GatewayIntents::MESSAGE_CONTENT;
    Client::builder(token, intents)
        .event_handler(handler)
        .await?
        .start()
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn attachments_only_use_discord_https() {
        assert!(valid_attachment(
            "https://cdn.discordapp.com/attachments/1/2/script.luau"
        ));
        for url in [
            "http://cdn.discordapp.com/a",
            "https://cdn.discordapp.com.evil.test/a",
            "https://user@cdn.discordapp.com/a",
            "https://127.0.0.1/a",
            "https://cdn.discordapp.com:444/a",
        ] {
            assert!(!valid_attachment(url), "{url}");
        }
    }

    #[test]
    fn manifest_names_must_be_plain_files_inside_output() {
        let root = std::env::temp_dir().join(format!("bot-manifest-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("good.json"), b"{}").unwrap();
        assert!(manifest_artifact(&root, "good.json").is_ok());
        for name in [
            "../good.json",
            "nested/good.json",
            "\\good.json",
            "C:\\good.json",
            ".",
            "",
        ] {
            assert!(manifest_artifact(&root, name).is_err(), "{name}");
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn status_selects_only_appropriate_reply_and_artifacts() {
        assert_eq!(
            reply_for_status("clean_lift"),
            "Clean lift completed. The source and validation reports are attached."
        );
        assert_eq!(
            reply_for_status("partial"),
            "Partial recovery completed. The artifact remains incomplete; read the coverage report."
        );
        assert_eq!(
            reply_for_status("unsupported"),
            "This input is unsupported. The diagnostic report is attached."
        );
        assert_eq!(
            reply_for_status("error"),
            "Recovery failed operationally. The diagnostic report is attached."
        );
        assert_eq!(
            reply_for_status("other"),
            "Recovery failed operationally. The diagnostic report is attached."
        );
        assert_eq!(
            artifact_names_for_status(
                "clean_lift",
                &serde_json::json!([
                    "chess.lifted.luau",
                    "anti-tamper-report.json",
                    "report.json"
                ])
            )
            .unwrap(),
            vec![
                "chess.lifted.luau",
                "anti-tamper-report.json",
                "report.json"
            ]
        );
        assert!(
            artifact_names_for_status(
                "clean_lift",
                &serde_json::json!(["source.partial.luau", "report.json"])
            )
            .is_err()
        );
        assert_eq!(
            artifact_names_for_status(
                "partial",
                &serde_json::json!(["source.partial.luau", "report.json"])
            )
            .unwrap(),
            vec!["source.partial.luau", "report.json"]
        );
        assert_eq!(
            artifact_names_for_status("unsupported", &serde_json::json!(["report.json"])).unwrap(),
            vec!["report.json"]
        );
    }

    #[test]
    fn manifest_artifacts_have_a_seven_mib_limit() {
        let root = std::env::temp_dir().join(format!("bot-size-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("small"), vec![0u8; 7 * 1024 * 1024]).unwrap();
        std::fs::write(root.join("large"), vec![0u8; 7 * 1024 * 1024 + 1]).unwrap();
        assert!(read_manifest_artifact(&root, "small").is_ok());
        assert!(read_manifest_artifact(&root, "large").is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn deobf_command_matches_only_the_leading_command_token() {
        assert!(is_deobf_command("!deobf"));
        assert!(is_deobf_command("!deobf please"));
        assert!(!is_deobf_command("hello !deobf"));
        assert!(!is_deobf_command("!deobfuscate"));
    }
}

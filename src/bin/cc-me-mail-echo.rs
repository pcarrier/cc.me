use std::{
    env,
    error::Error,
    hash::{DefaultHasher, Hash, Hasher},
    io::{self, Read, Write},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use time::{OffsetDateTime, format_description::well_known::Rfc2822};

const DEFAULT_FROM: &str = "echo@cc.me";
const DEFAULT_HOST: &str = "cc.me";
const DEFAULT_SENDMAIL: &str = "/usr/sbin/sendmail";

fn main() -> Result<(), Box<dyn Error>> {
    let mut message = String::new();
    io::stdin().read_to_string(&mut message)?;

    let envelope_sender = env::args().nth(1).or_else(|| env::var("SENDER").ok());
    let config = Config::from_env();

    let Some(reply) = build_reply(&message, envelope_sender.as_deref(), &config)? else {
        return Ok(());
    };

    if config.sendmail == "-" {
        io::stdout().write_all(reply.as_bytes())?;
        return Ok(());
    }

    let mut child = Command::new(&config.sendmail)
        .args(&config.sendmail_args)
        .stdin(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .as_mut()
        .ok_or("sendmail stdin unavailable")?
        .write_all(reply.as_bytes())?;
    let status = child.wait()?;
    if !status.success() {
        return Err(format!("sendmail exited with {status}").into());
    }

    Ok(())
}

struct Config {
    from: String,
    host: String,
    sendmail: String,
    sendmail_args: Vec<String>,
}

impl Config {
    fn from_env() -> Self {
        Self {
            from: env::var("CC_ME_ECHO_FROM").unwrap_or_else(|_| DEFAULT_FROM.to_string()),
            host: env::var("CC_ME_MAIL_HOST").unwrap_or_else(|_| DEFAULT_HOST.to_string()),
            sendmail: env::var("CC_ME_SENDMAIL").unwrap_or_else(|_| DEFAULT_SENDMAIL.to_string()),
            sendmail_args: env::var("CC_ME_SENDMAIL_ARGS")
                .map(|args| split_args(&args))
                .unwrap_or_else(|_| vec!["-oi".to_string(), "-t".to_string()]),
        }
    }
}

fn split_args(args: &str) -> Vec<String> {
    args.split_whitespace().map(str::to_string).collect()
}

fn build_reply(
    message: &str,
    envelope_sender: Option<&str>,
    config: &Config,
) -> Result<Option<String>, Box<dyn Error>> {
    let headers = Headers::parse(message);
    let sender = envelope_sender
        .map(clean_one_line)
        .filter(|sender| !sender.is_empty())
        .or_else(|| headers.get("from").and_then(extract_address));

    let Some(sender) = sender else {
        return Ok(None);
    };
    if sender == "<>" {
        return Ok(None);
    }
    if is_auto_submitted(&headers) || is_bulkish(&headers) {
        return Ok(None);
    }

    let subject = reply_subject(headers.get("subject").as_deref(), &config.from);
    let date = OffsetDateTime::now_utc().format(&Rfc2822)?;
    let message_id = reply_message_id(message, &config.host);
    let original_message_id = headers.get("message-id").map(|value| clean_one_line(&value));

    let mut reply = String::new();
    push_header(&mut reply, "From", &config.from);
    push_header(&mut reply, "To", &sender);
    push_header(&mut reply, "Subject", &subject);
    push_header(&mut reply, "Date", &date);
    push_header(&mut reply, "Message-ID", &format!("<{message_id}>"));
    if let Some(original_message_id) = original_message_id.filter(|value| !value.is_empty()) {
        push_header(&mut reply, "In-Reply-To", &original_message_id);
        push_header(&mut reply, "References", &original_message_id);
    }
    push_header(&mut reply, "Auto-Submitted", "auto-replied");
    push_header(&mut reply, "MIME-Version", "1.0");
    push_header(&mut reply, "Content-Type", "text/plain; charset=UTF-8");
    push_header(&mut reply, "Content-Transfer-Encoding", "8bit");
    reply.push('\n');
    reply.push_str("cc.me echo service received your message and is sending it back.\n\n");
    reply.push_str("Envelope sender: ");
    reply.push_str(&sender);
    reply.push_str("\n\n----- original message -----\n");
    for line in message.lines() {
        reply.push_str("> ");
        reply.push_str(line);
        reply.push('\n');
    }

    Ok(Some(reply))
}

fn push_header(reply: &mut String, name: &str, value: &str) {
    reply.push_str(name);
    reply.push_str(": ");
    reply.push_str(&clean_one_line(value));
    reply.push('\n');
}

fn clean_one_line(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch == '\r' || ch == '\n' { ' ' } else { ch })
        .collect::<String>()
        .trim()
        .to_string()
}

fn reply_subject(subject: Option<&str>, from: &str) -> String {
    let subject = subject.map(clean_one_line).unwrap_or_default();
    if subject.is_empty() {
        return format!("Re: message to {from}");
    }
    if subject
        .get(..3)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("re:"))
    {
        subject
    } else {
        format!("Re: {subject}")
    }
}

fn reply_message_id(message: &str, host: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let mut hasher = DefaultHasher::new();
    message.hash(&mut hasher);
    format!("{now}.{}.{}@{host}", std::process::id(), hasher.finish())
}

fn is_auto_submitted(headers: &Headers) -> bool {
    headers
        .get("auto-submitted")
        .map(|value| {
            let value = value.trim();
            !value.is_empty() && !value.eq_ignore_ascii_case("no")
        })
        .unwrap_or(false)
}

fn is_bulkish(headers: &Headers) -> bool {
    headers
        .get("precedence")
        .map(|value| {
            let value = value.to_ascii_lowercase();
            value.contains("bulk") || value.contains("junk") || value.contains("list")
        })
        .unwrap_or(false)
}

fn extract_address(value: String) -> Option<String> {
    let value = clean_one_line(&value);
    if let (Some(start), Some(end)) = (value.find('<'), value.find('>')) {
        let candidate = value[start + 1..end].trim();
        if looks_like_address(candidate) {
            return Some(candidate.to_string());
        }
    }
    value
        .split(|ch: char| ch == ',' || ch == ';' || ch.is_whitespace())
        .find(|part| looks_like_address(part.trim()))
        .map(|part| part.trim().to_string())
}

fn looks_like_address(value: &str) -> bool {
    let value = value.trim_matches(|ch| ch == '<' || ch == '>');
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && !value.contains(char::is_whitespace)
        && !value.contains('<')
        && !value.contains('>')
}

#[derive(Debug)]
struct Headers(Vec<(String, String)>);

impl Headers {
    fn parse(message: &str) -> Self {
        let mut headers: Vec<(String, String)> = Vec::new();
        for line in message.lines() {
            let line = line.trim_end_matches('\r');
            if line.is_empty() {
                break;
            }
            if line.starts_with(' ') || line.starts_with('\t') {
                if let Some((_, value)) = headers.last_mut() {
                    value.push(' ');
                    value.push_str(line.trim());
                }
                continue;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
            }
        }
        Self(headers)
    }

    fn get(&self, name: &str) -> Option<String> {
        let wanted = name.to_ascii_lowercase();
        self.0
            .iter()
            .rev()
            .find_map(|(header, value)| (header == &wanted).then(|| value.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config {
            from: "echo@cc.me".to_string(),
            host: "cc.me".to_string(),
            sendmail: "-".to_string(),
            sendmail_args: Vec::new(),
        }
    }

    #[test]
    fn builds_reply_to_envelope_sender() {
        let reply = build_reply(
            "From: Alice <alice@example.net>\nSubject: Test\nMessage-ID: <m@example.net>\n\nHello\n",
            Some("bounce@example.net"),
            &config(),
        )
        .unwrap()
        .unwrap();

        assert!(reply.contains("To: bounce@example.net\n"));
        assert!(reply.contains("Subject: Re: Test\n"));
        assert!(reply.contains("In-Reply-To: <m@example.net>\n"));
        assert!(reply.contains("> Hello\n"));
    }

    #[test]
    fn falls_back_to_from_header() {
        let reply = build_reply("From: Alice <alice@example.net>\n\nHello\n", None, &config())
            .unwrap()
            .unwrap();

        assert!(reply.contains("To: alice@example.net\n"));
    }

    #[test]
    fn suppresses_auto_replies() {
        let reply = build_reply(
            "From: bot@example.net\nAuto-Submitted: auto-replied\n\nHello\n",
            Some("bot@example.net"),
            &config(),
        )
        .unwrap();

        assert!(reply.is_none());
    }

    #[test]
    fn suppresses_null_sender() {
        let reply = build_reply("From: mailer-daemon@example.net\n\nHello\n", Some("<>"), &config())
            .unwrap();

        assert!(reply.is_none());
    }

    #[test]
    fn preserves_existing_reply_subject() {
        let reply = build_reply("From: a@example.net\nSubject: Re: Already\n\nHello\n", None, &config())
            .unwrap()
            .unwrap();

        assert!(reply.contains("Subject: Re: Already\n"));
    }
}

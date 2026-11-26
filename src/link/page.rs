//! The page a person sees: the Secret, its Description, one input per Field it
//! asks for. Every piece of text on it is HTML-escaped.

use super::{Input, LIFETIME, Link};

/// The form's name for the Field at `index`.
pub fn input_name(index: usize) -> String {
    format!("f{index}")
}

pub fn form(link: &Link, problem: Option<&str>) -> String {
    let fields: String = link
        .fields
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let label = escape(&f.label);
            let name = input_name(i);
            let kind = match f.input {
                Input::AlreadySet => {
                    return format!("<p class=\"set\"><b>{label}</b>: already set</p>\n");
                }
                Input::Password => "password",
                Input::Text => "text",
            };
            format!(
                "<label for=\"{name}\">{label}</label>\n<input id=\"{name}\" name=\"{name}\" type=\"{kind}\" required autocomplete=\"off\" autocapitalize=\"off\" spellcheck=\"false\">\n"
            )
        })
        .collect();
    let about = link
        .description
        .as_deref()
        .map(|d| format!("<p class=\"about\">{}</p>\n", escape(d)))
        .unwrap_or_default();
    let problem = problem
        .map(|p| format!("<p class=\"problem\">{}</p>\n", escape(p)))
        .unwrap_or_default();
    let minutes = LIFETIME.as_secs() / 60;
    page(
        link,
        &format!(
            "{about}{problem}<form method=\"post\" action=\"{}\">\n{fields}<button type=\"submit\">Store</button>\n</form>\n<p class=\"note\">This link works once and expires {minutes} minutes after it was made.</p>",
            link.path()
        ),
    )
}

pub fn sent(link: &Link) -> String {
    page(
        link,
        "<p>optokens received the values and is storing them. This link no longer works.</p>",
    )
}

fn page(link: &Link, body: &str) -> String {
    let secret = escape(&link.secret);
    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<meta name=\"robots\" content=\"noindex\">\n<title>optokens: {secret}</title>\n<style>\nbody {{ font: 16px system-ui, sans-serif; margin: 0 auto; max-width: 28rem; padding: 1.5rem 1rem; }}\nlabel {{ display: block; margin: 1rem 0 .25rem; font-weight: 600; }}\ninput, button {{ box-sizing: border-box; width: 100%; font-size: 1rem; padding: .6rem; }}\nbutton {{ margin-top: 1.25rem; }}\n.problem {{ color: #d70015; }}\n.note {{ color: #86868b; font-size: .875rem; }}\n</style></head><body>\n<h1>{secret}</h1>\n{body}\n</body></html>\n"
    )
}

/// `text` as HTML text or an attribute's value.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

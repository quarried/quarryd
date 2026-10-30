use std::fmt::Write as _;

use tracing::{Event, Subscriber};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::format::{Format, Json, JsonFields, Writer};
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;

struct NodeTagged
{
    inner: Format<Json>,
    prefix: String,
}

impl<S, N> FormatEvent<S, N> for NodeTagged
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        context: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result
    {
        let mut line = String::new();
        self.inner
            .format_event(context, Writer::new(&mut line), event)?;
        match line.strip_prefix('{')
        {
            Some(rest) => write!(writer, "{{{}{}", self.prefix, rest),
            None => writer.write_str(&line),
        }
    }
}

fn json_string(value: &str) -> String
{
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for character in value.chars()
    {
        match character
        {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            control if control.is_control() =>
            {
                let _ = write!(escaped, "\\u{:04x}", control as u32);
            }
            other => escaped.push(other),
        }
    }
    escaped.push('"');
    escaped
}

pub fn init(node_id: &str)
{
    let format = NodeTagged {
        inner: tracing_subscriber::fmt::format()
            .json()
            .with_current_span(true)
            .with_span_list(false),
        prefix: format!("\"node_id\":{},", json_string(node_id)),
    };
    let filter = EnvFilter::try_from_env("QUARRYD_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .fmt_fields(JsonFields::new())
        .event_format(format)
        .with_writer(std::io::stdout)
        .try_init();
}

#[cfg(test)]
mod tests
{
    use super::json_string;

    #[test]
    fn escapes_json()
    {
        assert_eq!(json_string("a\"b\\c\n"), "\"a\\\"b\\\\c\\u000a\"");
    }
}

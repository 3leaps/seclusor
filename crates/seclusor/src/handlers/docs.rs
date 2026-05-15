use crate::cli::{DocsFormatArg, DocsListArgs, DocsShowArgs, DocsSubcommand};
use crate::error::{CliError, CliResult};

#[derive(Debug, Clone, Copy)]
struct EmbeddedDoc {
    slug: &'static str,
    title: &'static str,
    topic: &'static str,
    content: &'static str,
}

include!(concat!(env!("OUT_DIR"), "/embedded_docs.rs"));

pub(crate) fn handle_docs_command(command: DocsSubcommand) -> CliResult<()> {
    match command {
        DocsSubcommand::List(args) => handle_docs_list(args),
        DocsSubcommand::Show(args) => handle_docs_show(args),
    }
}

fn handle_docs_list(args: DocsListArgs) -> CliResult<()> {
    match args.format {
        DocsFormatArg::Plain => {
            for doc in EMBEDDED_DOCS {
                println!("{:<32} {}", doc.slug, doc.title);
            }
        }
        DocsFormatArg::Json => {
            let out: Vec<serde_json::Value> = EMBEDDED_DOCS
                .iter()
                .map(|doc| {
                    serde_json::json!({
                        "slug": doc.slug,
                        "title": doc.title,
                        "topic": doc.topic
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
    }
    Ok(())
}

fn handle_docs_show(args: DocsShowArgs) -> CliResult<()> {
    let doc = find_embedded_doc(&args.slug).ok_or_else(|| {
        let mut known: Vec<&str> = EMBEDDED_DOCS.iter().map(|d| d.slug).collect();
        known.sort_unstable();
        CliError::Message(format!(
            "unknown docs slug {:?}; run `seclusor docs list` (known: {})",
            args.slug,
            known.join(", ")
        ))
    })?;

    match args.format {
        DocsFormatArg::Plain => println!("{}", doc.content),
        DocsFormatArg::Json => {
            let out = serde_json::json!({
                "slug": doc.slug,
                "title": doc.title,
                "topic": doc.topic,
                "content": doc.content
            });
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
    }

    Ok(())
}

fn find_embedded_doc(slug: &str) -> Option<&'static EmbeddedDoc> {
    EMBEDDED_DOCS.iter().find(|doc| doc.slug == slug)
}

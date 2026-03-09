use glob::{glob_with, MatchOptions, Pattern};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
struct EmbedManifest {
    version: String,
    topics: BTreeMap<String, EmbedTopic>,
}

#[derive(Debug, Deserialize)]
struct EmbedTopic {
    title: String,
    #[allow(dead_code)]
    description: Option<String>,
    include: Vec<String>,
    exclude: Option<Vec<String>>,
    #[allow(dead_code)]
    tags: Option<Vec<String>>,
}

#[derive(Debug)]
struct EmbeddedDoc {
    slug: String,
    title: String,
    topic: String,
    content: String,
}

fn main() {
    let manifest_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf();
    let docs_root = workspace_root.join("docs");
    let manifest_path = docs_root.join("embed-manifest.yaml");

    println!("cargo:rerun-if-changed={}", manifest_path.display());

    let manifest_raw = fs::read_to_string(&manifest_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", manifest_path.display()));
    let manifest: EmbedManifest = serde_yaml::from_str(&manifest_raw)
        .unwrap_or_else(|e| panic!("invalid {}: {e}", manifest_path.display()));

    if manifest.version != "1.0.0" {
        panic!(
            "unsupported embed manifest version {:?}; expected \"1.0.0\"",
            manifest.version
        );
    }

    let mut docs = Vec::new();
    for (topic_key, topic) in &manifest.topics {
        let files = resolve_topic_files(&docs_root, topic);
        if files.is_empty() {
            panic!("topic {topic_key:?} resolved zero files");
        }

        let is_single = files.len() == 1;
        for file in files {
            println!("cargo:rerun-if-changed={}", file.display());
            let rel = file
                .strip_prefix(&docs_root)
                .unwrap_or_else(|_| panic!("file outside docs root: {}", file.display()));
            let content = fs::read_to_string(&file)
                .unwrap_or_else(|e| panic!("failed to read {}: {e}", file.display()));

            let slug = if is_single {
                topic_key.clone()
            } else {
                format!("{}/{}", topic_key, slug_stem(rel))
            };

            let title = if is_single {
                topic.title.clone()
            } else {
                heading_from_markdown(&content).unwrap_or_else(|| title_from_path(rel))
            };

            docs.push(EmbeddedDoc {
                slug,
                title,
                topic: topic_key.clone(),
                content,
            });
        }
    }

    docs.sort_by(|a, b| a.slug.cmp(&b.slug));

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let out_file = out_dir.join("embedded_docs.rs");

    let mut generated = String::new();
    generated.push_str("static EMBEDDED_DOCS: &[EmbeddedDoc] = &[\n");
    for doc in docs {
        generated.push_str("    EmbeddedDoc {\n");
        generated.push_str(&format!("        slug: {},\n", json_lit(&doc.slug)));
        generated.push_str(&format!("        title: {},\n", json_lit(&doc.title)));
        generated.push_str(&format!("        topic: {},\n", json_lit(&doc.topic)));
        generated.push_str(&format!("        content: {},\n", json_lit(&doc.content)));
        generated.push_str("    },\n");
    }
    generated.push_str("];\n");

    fs::write(&out_file, generated)
        .unwrap_or_else(|e| panic!("failed to write {}: {e}", out_file.display()));
}

fn resolve_topic_files(docs_root: &Path, topic: &EmbedTopic) -> Vec<PathBuf> {
    let mut included = BTreeSet::new();
    let opts = MatchOptions {
        case_sensitive: true,
        require_literal_separator: false,
        require_literal_leading_dot: false,
    };

    for pattern in &topic.include {
        let absolute = docs_root.join(pattern);
        let glob_pat = absolute.to_string_lossy().replace('\\', "/");
        let entries = glob_with(&glob_pat, opts)
            .unwrap_or_else(|e| panic!("invalid include glob {pattern:?}: {e}"));
        for entry in entries {
            let path = entry.unwrap_or_else(|e| panic!("glob entry error for {pattern:?}: {e}"));
            if path.is_file() {
                included.insert(path);
            }
        }
    }

    let excludes: Vec<Pattern> = topic
        .exclude
        .as_ref()
        .map(|patterns| {
            patterns
                .iter()
                .map(|p| {
                    Pattern::new(p).unwrap_or_else(|e| panic!("invalid exclude glob {p:?}: {e}"))
                })
                .collect()
        })
        .unwrap_or_default();

    included
        .into_iter()
        .filter(|path| {
            let rel = path
                .strip_prefix(docs_root)
                .unwrap_or_else(|_| panic!("file outside docs root: {}", path.display()));
            let rel_s = rel.to_string_lossy().replace('\\', "/");
            !excludes.iter().any(|p| p.matches(&rel_s))
        })
        .collect()
}

fn heading_from_markdown(content: &str) -> Option<String> {
    content
        .lines()
        .find_map(|line| line.strip_prefix("# ").map(str::trim))
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
}

fn slug_stem(path: &Path) -> String {
    path.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("doc")
        .to_string()
}

fn title_from_path(path: &Path) -> String {
    let stem = slug_stem(path);
    stem.split('-')
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn json_lit(value: &str) -> String {
    serde_json::to_string(value).expect("json string literal")
}

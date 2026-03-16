use std::collections::BTreeMap;
use std::env;
use std::process;

fn main() {
    let mut args = env::args().skip(1);
    let Some(mode) = args.next() else {
        eprintln!("usage: run-fixture <dump|exit> [args...]");
        process::exit(2);
    };

    match mode.as_str() {
        "dump" => dump(args.collect()),
        "exit" => exit_with(args.next()),
        _ => {
            eprintln!("unknown mode: {mode}");
            process::exit(2);
        }
    }
}

fn dump(args: Vec<String>) {
    let keys = env::var("SECLUSOR_TEST_CAPTURE_KEYS")
        .ok()
        .map(|raw| {
            raw.split(',')
                .filter(|key| !key.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let mut env_map = BTreeMap::new();
    for key in keys {
        env_map.insert(key.clone(), env::var(&key).ok());
    }

    print!("{{\"args\":[");
    for (idx, arg) in args.iter().enumerate() {
        if idx > 0 {
            print!(",");
        }
        print!("\"{}\"", escape_json(arg));
    }
    print!("],\"env\":{{");
    for (idx, (key, value)) in env_map.iter().enumerate() {
        if idx > 0 {
            print!(",");
        }
        print!("\"{}\":", escape_json(key));
        match value {
            Some(value) => print!("\"{}\"", escape_json(value)),
            None => print!("null"),
        }
    }
    println!("}}}}");
}

fn exit_with(code: Option<String>) {
    let Some(code) = code else {
        eprintln!("usage: run-fixture exit <code>");
        process::exit(2);
    };
    let parsed = code.parse::<i32>().unwrap_or(2);
    process::exit(parsed);
}

fn escape_json(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

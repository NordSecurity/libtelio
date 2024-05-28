#![allow(unwrap_check)]

use std::{fs, io::Write, sync::Arc, time::SystemTime};

use anyhow::{anyhow, Result};
use clap::Parser;
use dirs::home_dir;
use parking_lot::Mutex;
use regex::Regex;
use tracing::level_filters::LevelFilter;

use telio_model::{config::Server, event::Event as DevEvent, features::Features};

use tcli::cli;

#[derive(Parser)]
struct Args {
    /// Pass [Features] in json format. Configure optional features.
    #[clap(short, long)]
    features: Option<String>,
    #[clap(long)]
    less_spam: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let (non_blocking_writer, _tracing_worker_guard) =
        tracing_appender::non_blocking(fs::File::create("tcli.log")?);
    tracing_subscriber::fmt()
        .with_max_level(LevelFilter::TRACE)
        .with_writer(non_blocking_writer)
        .with_ansi(false)
        .with_line_number(true)
        .with_level(true)
        .init();

    let token = std::env::var("NORD_TOKEN").ok();

    let features: Features = args
        .features
        .map(|s| serde_json::from_str(&s))
        .transpose()?
        .unwrap_or_default();

    let derp_server = Arc::new(Mutex::<Option<Server>>::new(None));

    let mut cli = cli::Cli::new(features, token, derp_server)?;
    let mut stdout = std::io::stdout();

    let less_spam = args.less_spam;
    if !less_spam {
        println!("telio dev cli");
        println!();
        println!("write 'help' to see all comands.\n");
    }

    let config = rustyline::config::Builder::new()
        .auto_add_history(true)
        .build();
    let mut rl = rustyline::DefaultEditor::with_config(config)?;

    let history_file_path = home_dir().map(|hp| hp.join(".tcli_history.txt"));
    if let Some(path) = history_file_path.as_ref() {
        let _ = rl.load_history(path).is_err();
    } else {
        println!("Home directory could not be found - the history won't be loaded and saved.\n");
    }

    let prompt = if less_spam { "" } else { ">>> " };

    loop {
        stdout.flush()?;
        let mut cmd = rl.readline(prompt).unwrap_or_else(|_| "quit".to_string());

        let mut message_idx: Option<&str> = None;
        let re = Regex::new(r"^MESSAGE_ID=(\d+) (.*)")?;
        let temp = cmd.clone();
        if let Some(captures) = re.captures(&temp) {
            message_idx = Some(
                captures
                    .get(1)
                    .ok_or_else(|| anyhow!("missing message idx"))?
                    .as_str(),
            );
            cmd = captures
                .get(2)
                .ok_or_else(|| anyhow!("missing cmd"))?
                .as_str()
                .to_string();
        }

        for resp in cli.exec(&cmd) {
            use cli::Resp::*;
            match resp {
                Info(i) => println!("- {}", i),
                Event { ts, event } => match *event {
                    DevEvent::Node { body: Some(b) } => print_event(ts, "node", &b)?,
                    DevEvent::Relay { body: Some(b) } => print_event(ts, "relay", &b)?,
                    DevEvent::Error { body: Some(b) } => print_event(ts, "error", &b)?,
                    _ => (),
                },
                Error(e) => {
                    println!("error: {e:#?}")
                }
                Quit => {
                    if let Some(idx) = message_idx {
                        println!("MESSAGE_DONE={}", idx);
                    }

                    if let Some(path) = history_file_path.as_ref() {
                        if let Err(err) = rl.save_history(path) {
                            println!("TCLI history could not be saved: {}", err);
                        }
                    }

                    return Ok(());
                }
            }
        }

        if let Some(idx) = message_idx {
            println!("MESSAGE_DONE={}", idx);
        }
    }
}

fn print_event(
    ts: SystemTime,
    ty: impl std::fmt::Display,
    ev: &impl serde::Serialize,
) -> anyhow::Result<()> {
    let mut stdout = std::io::stdout().lock();

    write!(&mut stdout, "event [")?;
    time::OffsetDateTime::from(ts)
        .format_into(&mut stdout, &time::format_description::well_known::Rfc3339)?;

    write!(&mut stdout, "] {ty}: ")?;
    serde_json::to_writer(&mut stdout, ev)?;

    writeln!(&mut stdout)?;
    Ok(())
}

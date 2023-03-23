#![allow(unwrap_check)]

mod cli;
mod derp;
mod nord;

use clap::Parser;
use dirs::home_dir;
use regex::Regex;
use std::io::Write;
use telio_model::{api_config::Features, event::Event as DevEvent};

#[derive(Parser)]
struct Args {
    /// Pass [Features] in json format. Configure optional features.
    #[clap(short, long)]
    features: Option<String>,
    #[clap(long)]
    less_spam: bool,
}

fn main() {
    let args = Args::parse();

    let token = std::env::var("NORD_TOKEN").ok();

    let features: Features = args
        .features
        .map(|s| serde_json::from_str(&s).expect("Invalid json"))
        .unwrap_or_default();

    let mut cli = cli::Cli::new(features, token);
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
    let mut rl = rustyline::DefaultEditor::with_config(config).unwrap();

    let history_file_path = home_dir().map(|hp| hp.join(".tcli_history.txt"));
    if let Some(path) = history_file_path.as_ref() {
        let _ = rl.load_history(path).is_err();
    } else {
        println!("Home directory could not be found - the history won't be loaded and saved.\n");
    }

    let prompt = if less_spam { "" } else { ">>> " };

    loop {
        stdout.flush().unwrap();
        let mut cmd = rl.readline(prompt).unwrap_or("quit".to_string());

        let mut message_idx: Option<&str> = None;
        let re = Regex::new(r"^MESSAGE_ID=(\d+) (.*)").unwrap();
        let temp = cmd.clone();
        if let Some(captures) = re.captures(&temp) {
            message_idx = Some(captures.get(1).unwrap().as_str());
            cmd = captures.get(2).unwrap().as_str().to_string();
        }

        for resp in cli.exec(&cmd) {
            use cli::Resp::*;
            match resp {
                Info(i) => println!("- {}", i),
                Event(e) => match *e {
                    DevEvent::Node { body } => {
                        if let Some(b) = body {
                            println!(
                                "event node: {:?}:{};  Path = {:?}",
                                b.state.unwrap(),
                                b.public_key,
                                b.path
                            );
                        }
                    }
                    DevEvent::Relay { body } => {
                        if let Some(b) = body {
                            println!(
                                "event relay: {}",
                                serde_json::to_string(&b).unwrap_or("".to_string())
                            );
                        }
                    }
                    _ => (),
                },
                Error(e) => {
                    println!("error: {}", e)
                }
                Quit => {
                    if message_idx.is_some() {
                        println!("MESSAGE_DONE={}", message_idx.unwrap());
                    }

                    if let Some(path) = history_file_path.as_ref() {
                        if let Err(err) = rl.save_history(path) {
                            println!("TCLI history could not be saved: {}", err);
                        }
                    }

                    return;
                }
            }
        }

        if message_idx.is_some() {
            println!("MESSAGE_DONE={}", message_idx.unwrap());
        }
    }
}

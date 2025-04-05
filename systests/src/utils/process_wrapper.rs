use std::time::{SystemTime, UNIX_EPOCH};

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};

use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    sync::mpsc,
};

use crate::test_device::Command as DeviceCommand;

const IGNORED_OUTPUT: [&str; 3] = ["done", "error", "connected"];

pub struct ProcessWrapper {
    child: Option<Child>,
    stdin: ChildStdin,
    stdout_rx: mpsc::Receiver<String>,
}

impl ProcessWrapper {
    pub fn new(bin: &str, tag: String) -> anyhow::Result<Self> {
        let mut child = Command::new(bin)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;

        let stdin = child.stdin.take().expect("Failed to open stdin");
        let stdout = child.stdout.take().expect("Failed to open stdout");
        let stderr = child.stderr.take().unwrap();

        let (stdout_tx, stdout_rx) = mpsc::channel(10);
        tokio::spawn(Self::stdout_loop(stdout, stdout_tx, tag.clone()));
        tokio::spawn(Self::stderr_loop(stderr, tag));

        Ok(Self {
            child: Some(child),
            stdin,
            stdout_rx,
        })
    }

    pub async fn kill(mut self) {
        if let Some(mut child) = self.child.take() {
            child.kill().await.unwrap();
        }
    }

    async fn stdout_loop(stdout: ChildStdout, tx: mpsc::Sender<String>, tag: String) {
        let reader = BufReader::new(stdout);
        let mut lines = reader.lines();

        while let Ok(Some(line)) = lines.next_line().await {
            if !IGNORED_OUTPUT.contains(&line.as_str()) {
                let duration_since_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
                let datetime =
                    OffsetDateTime::from_unix_timestamp(duration_since_epoch.as_secs() as i64)
                        .unwrap()
                        .replace_nanosecond(duration_since_epoch.subsec_nanos())
                        .unwrap();

                let formatted = datetime.format(&Rfc3339).unwrap();

                println!("[{tag}] {formatted}: {line}");
            }
            let _ = tx.send(line).await;
        }
    }

    async fn stderr_loop(stderr: ChildStderr, tag: String) {
        let reader = BufReader::new(stderr);
        let mut lines = reader.lines();

        while let Ok(Some(line)) = lines.next_line().await {
            let duration_since_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            let datetime =
                OffsetDateTime::from_unix_timestamp(duration_since_epoch.as_secs() as i64)
                    .unwrap()
                    .replace_nanosecond(duration_since_epoch.subsec_nanos())
                    .unwrap();

            let formatted = datetime.format(&Rfc3339).unwrap();

            println!("[{tag} - stderr] {formatted} - {line}");
        }
    }

    pub async fn write_stdin(&mut self, msg: &str) -> anyhow::Result<()> {
        self.stdin.write_all(msg.as_bytes()).await?;
        self.stdin.write_all(b"\n").await?;
        self.stdin.flush().await?;
        Ok(())
    }

    pub async fn read_stdout(&mut self) -> Option<String> {
        self.stdout_rx.recv().await
    }

    pub async fn exec_cmd(&mut self, cmd: DeviceCommand) {
        let cmd = serde_json::to_string(&cmd).unwrap();
        self.write_stdin(&cmd).await.unwrap();
        let start = std::time::Instant::now();
        while let Some(line) = self.read_stdout().await {
            if line == "done" {
                return;
            } else if line == "error" {
                panic!("Remote process returned error");
            }
            if start.elapsed() > std::time::Duration::from_secs(10) {
                panic!();
            }
        }
    }
}

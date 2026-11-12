//! A list host on 127.0.0.1 for block filter tests: serves a body per path,
//! counts the downloads it answers, and can hold one or fail them all.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

#[derive(Default)]
struct Served {
    bodies: HashMap<String, String>,
    failing: bool,
    downloads: usize,
    /// The next download waits until this fires or is dropped.
    hold: Option<oneshot::Receiver<()>>,
}

pub struct ListHost {
    base: String,
    served: Arc<Mutex<Served>>,
}

impl ListHost {
    pub async fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let served = Arc::new(Mutex::new(Served::default()));
        let state = Arc::clone(&served);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(answer(stream, Arc::clone(&state)));
            }
        });
        Self { base, served }
    }

    /// Serves `body` at `path` from now on; returns its URL.
    pub fn serve(&self, path: &str, body: &str) -> String {
        self.served
            .lock()
            .unwrap()
            .bodies
            .insert(path.to_owned(), body.to_owned());
        format!("{}{path}", self.base)
    }

    /// Closes every later connection unanswered, so each download fails.
    pub fn fail(&self) {
        self.served.lock().unwrap().failing = true;
    }

    /// Holds the next download until the returned sender fires or is dropped.
    pub fn hold_next(&self) -> oneshot::Sender<()> {
        let (release, hold) = oneshot::channel();
        self.served.lock().unwrap().hold = Some(hold);
        release
    }

    /// Downloads answered so far, held ones included.
    pub fn downloads(&self) -> usize {
        self.served.lock().unwrap().downloads
    }
}

async fn answer(stream: TcpStream, served: Arc<Mutex<Served>>) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    if reader.read_line(&mut line).await.is_err() {
        return;
    }
    let path = line
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) | Err(_) => return,
            Ok(_) if line == "\r\n" => break,
            Ok(_) => {}
        }
    }

    let (body, hold) = {
        let mut served = served.lock().unwrap();
        if served.failing {
            return;
        }
        served.downloads += 1;
        (served.bodies.get(&path).cloned(), served.hold.take())
    };
    if let Some(hold) = hold {
        let _ = hold.await;
    }
    let response = match body {
        Some(body) => format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
        None => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
    };
    let mut stream = reader.into_inner();
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

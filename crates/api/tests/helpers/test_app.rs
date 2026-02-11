#![allow(dead_code)]
pub struct TestApp;

impl TestApp {
    pub async fn new() -> Self {
        Self
    }
}

pub struct TestResponse;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_placeholder() {
        let _app = TestApp::new().await;
        assert!(true);
    }
}

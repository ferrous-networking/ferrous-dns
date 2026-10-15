use crate::ports::ClientRepository;
use ferrous_dns_domain::DomainError;
use std::sync::Arc;
use tracing::instrument;

/// Sets or clears the comment of a client. Kept apart from
/// `UpdateClientUseCase`, whose callers do not send a comment and so cannot
/// clear one by omission.
pub struct SetClientCommentUseCase {
    client_repo: Arc<dyn ClientRepository>,
}

impl SetClientCommentUseCase {
    pub fn new(client_repo: Arc<dyn ClientRepository>) -> Self {
        Self { client_repo }
    }

    #[instrument(skip(self))]
    pub async fn execute(
        &self,
        client_id: i64,
        comment: Option<String>,
    ) -> Result<(), DomainError> {
        let comment = comment.filter(|c| !c.trim().is_empty());
        self.client_repo.set_comment(client_id, comment).await
    }
}

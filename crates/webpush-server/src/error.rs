//! Handler errors: a status code plus the headers that status needs.

use std::time::Duration;

use axum::{
    http::{HeaderName, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};

use crate::{BoxError, headers::Invalid};

/// A handler failure: a protocol status, or 500 for a storage error.
#[derive(Debug)]
pub struct Error {
    /// Response status.
    status: StatusCode,
    /// A header the status requires, such as `WWW-Authenticate`.
    header: Option<(HeaderName, HeaderValue)>,
}

impl Error {
    /// 401 with a `WWW-Authenticate` challenge for `scheme` (RFC 9110
    /// §11.6.1).
    pub fn unauthorized(scheme: &'static str) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            header: Some((header::WWW_AUTHENTICATE, HeaderValue::from_static(scheme))),
        }
    }

    /// `status` with `Retry-After` in whole seconds, when known.
    pub fn retry_after(status: StatusCode, after: Option<Duration>) -> Self {
        Self {
            status,
            header: after.map(|d| (header::RETRY_AFTER, HeaderValue::from(d.as_secs().max(1)))),
        }
    }
}

impl From<StatusCode> for Error {
    fn from(status: StatusCode) -> Self {
        Self {
            status,
            header: None,
        }
    }
}

impl From<Invalid> for Error {
    fn from(_: Invalid) -> Self {
        StatusCode::BAD_REQUEST.into()
    }
}

impl From<BoxError> for Error {
    fn from(e: BoxError) -> Self {
        tracing::error!(error = %e, "storage");
        StatusCode::INTERNAL_SERVER_ERROR.into()
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        match self.header {
            Some(h) => (self.status, [h]).into_response(),
            None => self.status.into_response(),
        }
    }
}

/// Handler result: a response, or an [`Error`].
pub type Result<T = Response> = std::result::Result<T, Error>;

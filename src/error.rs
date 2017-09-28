use rusoto_core;
use serde_json;
use base64;
use std;
use rusoto_cognito_identity;

#[derive(Debug)]
pub enum Error {
    CredentialsError(rusoto_core::CredentialsError),
    TlsError(rusoto_core::TlsError),
    IllegalParameterError(String),
    JsonError(serde_json::Error),
    HttpDispatchError(rusoto_core::HttpDispatchError),
    BadResponseError(String),
    DecodeError(base64::DecodeError),
    IoError(std::io::Error),
    RuntimeError(String),
    GetIdError(rusoto_cognito_identity::GetIdError),
    NotAuthorizedError(String),
    ResourceNotFoundError(String),
    UserNotFoundError(String),
}
impl From<rusoto_core::CredentialsError> for Error { fn from(x: rusoto_core::CredentialsError) -> Error { Error::CredentialsError(x) } }
impl From<rusoto_core::TlsError> for Error { fn from(x: rusoto_core::TlsError) -> Error { Error::TlsError(x) } }
impl From<serde_json::Error> for Error { fn from(x: serde_json::Error) -> Error { Error::JsonError(x) } }
impl From<rusoto_core::HttpDispatchError> for Error { fn from(x: rusoto_core::HttpDispatchError) -> Error { Error::HttpDispatchError(x) } }
impl From<std::io::Error> for Error { fn from(x: std::io::Error) -> Error { Error::IoError(x) } }
impl From<base64::DecodeError> for Error { fn from(x: base64::DecodeError) -> Error { Error::DecodeError(x) } }
impl From<rusoto_cognito_identity::GetIdError> for Error { fn from(x: rusoto_cognito_identity::GetIdError) -> Error { Error::GetIdError(x) } }

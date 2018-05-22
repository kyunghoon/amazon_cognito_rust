use rusoto_core;
use rusoto_sts;
use serde_json;
use base64;
use std;
use cognito;

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
    //GetIdError(rusoto_cognito_identity::GetIdError),
    NotAuthorizedError(String),
    ResourceNotFoundError(String),
    UserNotFoundError(String),
    GetCredentialsForIdentityError(cognito::requests::GetCredentialsForIdentityError),
    GetOpenIdTokenError(cognito::requests::GetOpenIdTokenError),
    GetIdError(cognito::requests::GetIdError),
    AssumeRoleWithWebIdentityError(rusoto_sts::AssumeRoleWithWebIdentityError),
}
impl From<rusoto_core::CredentialsError> for Error { fn from(x: rusoto_core::CredentialsError) -> Error { Error::CredentialsError(x) } }
impl From<rusoto_core::TlsError> for Error { fn from(x: rusoto_core::TlsError) -> Error { Error::TlsError(x) } }
impl From<serde_json::Error> for Error { fn from(x: serde_json::Error) -> Error { Error::JsonError(x) } }
impl From<rusoto_core::HttpDispatchError> for Error { fn from(x: rusoto_core::HttpDispatchError) -> Error { Error::HttpDispatchError(x) } }
impl From<std::io::Error> for Error { fn from(x: std::io::Error) -> Error { Error::IoError(x) } }
impl From<base64::DecodeError> for Error { fn from(x: base64::DecodeError) -> Error { Error::DecodeError(x) } }
impl From<rusoto_sts::AssumeRoleWithWebIdentityError> for Error { fn from(x: rusoto_sts::AssumeRoleWithWebIdentityError) -> Error { Error::AssumeRoleWithWebIdentityError(x) } }

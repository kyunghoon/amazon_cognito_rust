use rusoto_core::{DispatchSignedRequest, CredentialsError, SignedRequest, Region};
use rusoto_core::request::HttpDispatchError;
use hyper::status::StatusCode;
use hyper::Client;
use serde_json::{from_str};
use serde_json::value::Value as SerdeJsonValue;
use serde_json;
use std::collections::HashMap;
use ::tools::DEFAULT_USER_AGENT;
use ::error::Error;

#[allow(non_snake_case)]
#[doc="<p>Input to the GetId action.</p>"]
#[derive(Default,Debug,Clone,Serialize)]
pub struct GetIdInput {
    pub IdentityPoolId: String,
    pub Logins: Option<HashMap<String, String>>,
}

#[allow(non_snake_case)]
#[doc="<p>Returned in response to a GetId request.</p>"]
#[derive(Default,Debug,Clone,Deserialize)]
pub struct GetIdResponse {
    pub IdentityId: String,
}

/// Errors returned by GetId
#[derive(Debug, PartialEq)]
pub enum GetIdError {
    /// <p>An exception thrown when a dependent service such as Facebook or Twitter is not responding</p>
    ExternalService(String),
    /// <p>Thrown when the service encounters an error during processing the request.</p>
    InternalError(String),
    /// <p>Thrown for missing or bad input parameter(s).</p>
    InvalidParameter(String),
    /// <p>Thrown when the total number of user pools has exceeded a preset limit.</p>
    LimitExceeded(String),
    /// <p>Thrown when a user is not authorized to access the requested resource.</p>
    NotAuthorized(String),
    /// <p>Thrown when a user tries to use a login which is already linked to another account.</p>
    ResourceConflict(String),
    /// <p>Thrown when the requested resource (for example, a dataset or record) does not exist.</p>
    ResourceNotFound(String),
    /// <p>Thrown when a request is throttled.</p>
    TooManyRequests(String),
    /// An error occurred dispatching the HTTP request
    HttpDispatch(HttpDispatchError),
    /// An error was encountered with AWS credentials.
    Credentials(CredentialsError),
    /// A validation error occurred.  Details from AWS are provided.
    Validation(String),
    /// An unknown error occurred.  The raw HTTP response is provided.
    Unknown(String),
}

impl From<GetIdError> for Error { fn from(e: GetIdError) -> Error { Error::GetIdError(e) } }

impl GetIdError {
    pub fn from_body(body: &str) -> GetIdError {
        match from_str::<SerdeJsonValue>(body) {
            Ok(json) => {
                let raw_error_type = json.get("__type")
                    .and_then(|e| e.as_str())
                    .unwrap_or("Unknown");
                let error_message = json.get("message").and_then(|m| m.as_str()).unwrap_or(body);

                let pieces: Vec<&str> = raw_error_type.split("#").collect();
                let error_type = pieces.last().expect("Expected error type");

                match *error_type {
                    "ExternalServiceException" => GetIdError::ExternalService(String::from(error_message)),
                    "InternalErrorException" => GetIdError::InternalError(String::from(error_message)),
                    "InvalidParameterException" => GetIdError::InvalidParameter(String::from(error_message)),
                    "LimitExceededException" => GetIdError::LimitExceeded(String::from(error_message)),
                    "NotAuthorizedException" => GetIdError::NotAuthorized(String::from(error_message)),
                    "ResourceConflictException" => GetIdError::ResourceConflict(String::from(error_message)),
                    "ResourceNotFoundException" => GetIdError::ResourceNotFound(String::from(error_message)),
                    "TooManyRequestsException" => GetIdError::TooManyRequests(String::from(error_message)),
                    "ValidationException" => GetIdError::Validation(error_message.to_string()),
                    _ => GetIdError::Unknown(String::from(body)),
                }
            }
            Err(_) => GetIdError::Unknown(String::from(body)),
        }
    }
}

pub fn get_id(dispatcher: &Client, region: &Region, input: &GetIdInput) -> Result<GetIdResponse, Error> {
    let mut request = SignedRequest::new("POST", "cognito-identity", region, "/");

    let payload = serde_json::to_string(&input).unwrap();

    request.set_content_type("application/x-amz-json-1.1".to_owned());
    request.add_header("user-agent", DEFAULT_USER_AGENT);
    request.add_header("x-amz-target", "AWSCognitoIdentityService.GetId");
    request.set_payload(Some(payload.into_bytes()));

    let mut response = dispatcher.dispatch(&request)?;

    match response.status {
        StatusCode::Ok => {
            let mut body: Vec<u8> = Vec::new();
            try!(response.body.read_to_end(&mut body));
            Ok(serde_json::from_str::<GetIdResponse>(String::from_utf8_lossy(&body).as_ref())
               .unwrap())
        }
        _ => {
            let mut body: Vec<u8> = Vec::new();
            try!(response.body.read_to_end(&mut body));
            Err(Error::from(GetIdError::from_body(String::from_utf8_lossy(&body).as_ref())))
        }
    }
}


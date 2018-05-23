use rusoto_core::{AwsCredentials, DispatchSignedRequest, CredentialsError, ProvideAwsCredentials, SignedRequest, Region};
use rusoto_core::request::HttpDispatchError;
use hyper::status::StatusCode;
use serde_json::{from_str};
use serde_json::value::Value as SerdeJsonValue;
use serde_json;
use std::io::Error as IoError;
use ::error::Error;

#[allow(non_snake_case)]
#[doc="<p>Input to the GetUser action.</p>"]
#[derive(Default,Debug,Clone,Serialize)]
pub struct GetUserInput {
    pub AccessToken: String,
}

#[allow(non_snake_case)]
#[derive(Default,Debug,Clone,Deserialize)]
pub struct UserAttributes {
    pub Name: String,
    pub Value: String,
}

#[allow(non_snake_case)]
#[doc="<p>Returned in response to a GetUser request.</p>"]
#[derive(Default,Debug,Clone,Deserialize)]
pub struct GetUserResponse {
    pub UserAttributes: Vec<UserAttributes>,
    pub Username: String,
}

/// Errors returned by GetId
#[derive(Debug, PartialEq)]
pub enum GetUserError {
    ///<p>An exception thrown when a dependent service such as Facebook or Twitter is not responding</p>
    ExternalService(String),
    ///<p>Thrown when the service encounters an error during processing the request.</p>
    InternalError(String),
    ///<p>Thrown for missing or bad input parameter(s).</p>
    InvalidParameter(String),
    ///<p>Thrown when the total number of user pools has exceeded a preset limit.</p>
    LimitExceeded(String),
    ///<p>Thrown when a user is not authorized to access the requested resource.</p>
    NotAuthorized(String),
    ///<p>Thrown when a user tries to use a login which is already linked to another account.</p>
    ResourceConflict(String),
    ///<p>Thrown when the requested resource (for example, a dataset or record) does not exist.</p>
    ResourceNotFound(String),
    ///<p>Thrown when a request is throttled.</p>
    TooManyRequests(String),
    /// An error occurred dispatching the HTTP request
    HttpDispatch(HttpDispatchError),
    /// An error was encountered with AWS credentials.
    Credentials(CredentialsError),
    /// A validation error occurred.  Details from AWS are provided.
    Validation(String),
    /// An unknown error occurred.  The raw HTTP response is provided.
    Unknown(String),
    IoError(String),
}
impl From<CredentialsError> for GetUserError { fn from(x: CredentialsError) -> GetUserError { GetUserError::Credentials(x) } }
impl From<HttpDispatchError> for GetUserError { fn from(x: HttpDispatchError) -> GetUserError { GetUserError::HttpDispatch(x) } }
impl From<IoError> for GetUserError { fn from(x: IoError) -> GetUserError { GetUserError::IoError(x.to_string()) } }
impl From<GetUserError> for Error { fn from(x: GetUserError) -> Error { Error::GetUserError(x) } }

impl GetUserError {
    pub fn from_body(body: &str) -> GetUserError {
        match from_str::<SerdeJsonValue>(body) {
            Ok(json) => {
                let raw_error_type = json.get("__type")
                    .and_then(|e| e.as_str())
                    .unwrap_or("Unknown");
                let error_message = json.get("message").and_then(|m| m.as_str()).unwrap_or(body);

                let pieces: Vec<&str> = raw_error_type.split("#").collect();
                let error_type = pieces.last().expect("Expected error type");

                match *error_type {
                    "ExternalServiceException" => { GetUserError::ExternalService(String::from(error_message)) }
                    "InternalErrorException" => { GetUserError::InternalError(String::from(error_message)) }
                    "InvalidParameterException" => { GetUserError::InvalidParameter(String::from(error_message)) }
                    "LimitExceededException" => { GetUserError::LimitExceeded(String::from(error_message)) }
                    "NotAuthorizedException" => { GetUserError::NotAuthorized(String::from(error_message)) }
                    "ResourceConflictException" => { GetUserError::ResourceConflict(String::from(error_message)) }
                    "ResourceNotFoundException" => { GetUserError::ResourceNotFound(String::from(error_message)) }
                    "TooManyRequestsException" => { GetUserError::TooManyRequests(String::from(error_message)) }
                    "ValidationException" => GetUserError::Validation(error_message.to_string()), _ => GetUserError::Unknown(String::from(body)),
                }
            }
            Err(_) => GetUserError::Unknown(String::from(body)),
        }
    }
}

pub fn get_user<D: DispatchSignedRequest>(input: &GetUserInput, region: Region, dispatcher: &D, credentials: &AwsCredentials) -> Result<GetUserResponse, GetUserError> {
    let mut request = SignedRequest::new("POST", "cognito-idp", &region, "/");

    request.set_content_type("application/x-amz-json-1.1".to_owned());
    request.add_header("x-amz-target", "AWSCognitoIdentityProviderService.GetUser");
    let encoded = serde_json::to_string(input).unwrap();
    request.set_payload(Some(encoded.into_bytes()));

    request.sign(credentials);

    let mut response = dispatcher.dispatch(&request)?;

    match response.status {
        StatusCode::Ok => {
            let mut body: Vec<u8> = Vec::new();
            try!(response.body.read_to_end(&mut body));
            Ok(serde_json::from_str::<GetUserResponse>(String::from_utf8_lossy(&body).as_ref())
               .unwrap())
        }
        _ => {
            let mut body: Vec<u8> = Vec::new();
            try!(response.body.read_to_end(&mut body));
            Err(GetUserError::from_body(String::from_utf8_lossy(&body).as_ref()))
        }
    }
}

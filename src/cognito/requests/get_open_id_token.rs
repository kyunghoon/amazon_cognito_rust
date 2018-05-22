use rusoto_core::{DispatchSignedRequest, CredentialsError, SignedRequest, Region};
use rusoto_core::request::HttpDispatchError;
use hyper::status::StatusCode;
use hyper::Client;
use serde_json::{from_str};
use serde_json::value::Value as SerdeJsonValue;
use serde_json;
use ::tools::DEFAULT_USER_AGENT;
use ::error::Error;

/// <p>Input to the GetOpenIdToken action.</p>
#[derive(Default, Debug, Clone, Serialize)]
pub struct GetOpenIdTokenInput {
    /// <p>A unique identifier in the format REGION:GUID.</p>
    #[serde(rename = "IdentityId")]
    pub identity_id: String,
    /// <p>A set of optional name-value pairs that map provider names to provider tokens. When using graph.facebook.com and www.amazon.com, supply the access_token returned from the provider's authflow. For accounts.google.com, an Amazon Cognito Identity Provider, or any other OpenId Connect provider, always include the <code>id_token</code>.</p>
    #[serde(rename = "Logins")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logins: Option<::std::collections::HashMap<String, String>>,
}

/// <p>Returned in response to a successful GetOpenIdToken request.</p>
#[derive(Default, Debug, Clone, Deserialize)]
pub struct GetOpenIdTokenResponse {
    /// <p>A unique identifier in the format REGION:GUID. Note that the IdentityId returned may not match the one passed on input.</p>
    #[serde(rename = "IdentityId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_id: Option<String>,
    /// <p>An OpenID token, valid for 15 minutes.</p>
    #[serde(rename = "Token")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

/// Errors returned by GetOpenIdToken
#[derive(Debug, PartialEq)]
pub enum GetOpenIdTokenError {
    /// <p>An exception thrown when a dependent service such as Facebook or Twitter is not responding</p>
    ExternalService(String),
    /// <p>Thrown when the service encounters an error during processing the request.</p>
    InternalError(String),
    /// <p>Thrown for missing or bad input parameter(s).</p>
    InvalidParameter(String),
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

impl GetOpenIdTokenError {
    pub fn from_body(body: &str) -> GetOpenIdTokenError {
        match from_str::<SerdeJsonValue>(body) {
            Ok(json) => {
                let raw_error_type = json.get("__type")
                    .and_then(|e| e.as_str())
                    .unwrap_or("Unknown");
                let error_message = json.get("message").and_then(|m| m.as_str()).unwrap_or(body);

                let pieces: Vec<&str> = raw_error_type.split("#").collect();
                let error_type = pieces.last().expect("Expected error type");

                match *error_type {
                    "ExternalServiceException" => GetOpenIdTokenError::ExternalService(String::from(error_message)),
                    "InternalErrorException" => GetOpenIdTokenError::InternalError(String::from(error_message)),
                    "InvalidParameterException" => GetOpenIdTokenError::InvalidParameter(String::from(error_message)),
                    "NotAuthorizedException" => GetOpenIdTokenError::NotAuthorized(String::from(error_message)),
                    "ResourceConflictException" => GetOpenIdTokenError::ResourceConflict(String::from(error_message)),
                    "ResourceNotFoundException" => GetOpenIdTokenError::ResourceNotFound(String::from(error_message)),
                    "TooManyRequestsException" => GetOpenIdTokenError::TooManyRequests(String::from(error_message)),
                    "ValidationException" => GetOpenIdTokenError::Validation(error_message.to_string()),
                    _ => GetOpenIdTokenError::Unknown(String::from(body)),
                }
            }
            Err(_) => GetOpenIdTokenError::Unknown(String::from(body)),
        }
    }
}

impl From<GetOpenIdTokenError> for Error { fn from(e: GetOpenIdTokenError) -> Error { Error::GetOpenIdTokenError(e) } }

pub fn get_open_id_token(dispatcher: &Client, region: &Region, input: GetOpenIdTokenInput) -> Result<GetOpenIdTokenResponse, Error> {
    let mut request = SignedRequest::new("POST", "cognito-identity", region, "/");

    request.set_content_type("application/x-amz-json-1.1".to_owned());
    request.add_header("user-agent", DEFAULT_USER_AGENT);
    request.add_header("x-amz-target", "AWSCognitoIdentityService.GetOpenIdToken");
    let encoded = serde_json::to_string(&input)?;
    request.set_payload(Some(encoded.into_bytes()));

    let mut response = dispatcher.dispatch(&request)?;

    match response.status {
        StatusCode::Ok => {
            let mut body: Vec<u8> = Vec::new();
            try!(response.body.read_to_end(&mut body));
            Ok(serde_json::from_str::<GetOpenIdTokenResponse>(String::from_utf8_lossy(&body).as_ref())?)
        }
        _ => {
            let mut body: Vec<u8> = Vec::new();
            try!(response.body.read_to_end(&mut body));
            Err(Error::from(GetOpenIdTokenError::from_body(String::from_utf8_lossy(&body).as_ref())))
        }
    }
}
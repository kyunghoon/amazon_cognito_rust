use rusoto_core::{DispatchSignedRequest, CredentialsError, SignedRequest, Region};
use rusoto_core::request::HttpDispatchError;
use hyper::status::StatusCode;
use hyper::Client;
use serde_json::{from_str};
use serde_json::value::Value as SerdeJsonValue;
use serde_json;
use ::tools::DEFAULT_USER_AGENT;
use ::error::Error;

/// <p>Credentials for the provided identity ID.</p>
#[derive(Default, Debug, Clone, Deserialize)]
pub struct Credentials {
    /// <p>The Access Key portion of the credentials.</p>
    #[serde(rename = "AccessKeyId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_key_id: Option<String>,
    /// <p>The date at which these credentials will expire.</p>
    #[serde(rename = "Expiration")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration: Option<f64>,
    /// <p>The Secret Access Key portion of the credentials</p>
    #[serde(rename = "SecretKey")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_key: Option<String>,
    /// <p>The Session Token portion of the credentials</p>
    #[serde(rename = "SessionToken")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
}

/// Errors returned by GetCredentialsForIdentity
#[derive(Debug, PartialEq)]
pub enum GetCredentialsForIdentityError {
    /// <p>An exception thrown when a dependent service such as Facebook or Twitter is not responding</p>
    ExternalService(String),
    /// <p>Thrown when the service encounters an error during processing the request.</p>
    InternalError(String),
    /// <p>Thrown if the identity pool has no role associated for the given auth type (auth/unauth) or if the AssumeRole fails.</p>
    InvalidIdentityPoolConfiguration(String),
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

impl GetCredentialsForIdentityError {
    pub fn from_body(body: &str) -> GetCredentialsForIdentityError {
        match from_str::<SerdeJsonValue>(body) {
            Ok(json) => {
                let raw_error_type = json.get("__type")
                    .and_then(|e| e.as_str())
                    .unwrap_or("Unknown");
                let error_message = json.get("message").and_then(|m| m.as_str()).unwrap_or(body);

                let pieces: Vec<&str> = raw_error_type.split("#").collect();
                let error_type = pieces.last().expect("Expected error type");

                match *error_type {
                    "ExternalServiceException" => {
                        GetCredentialsForIdentityError::ExternalService(String::from(error_message))
                    }
                    "InternalErrorException" => {
                        GetCredentialsForIdentityError::InternalError(String::from(error_message))
                    }
                    "InvalidIdentityPoolConfigurationException" => {
                        GetCredentialsForIdentityError::InvalidIdentityPoolConfiguration(
                            String::from(error_message),
                        )
                    }
                    "InvalidParameterException" => {
                        GetCredentialsForIdentityError::InvalidParameter(String::from(
                            error_message,
                        ))
                    }
                    "NotAuthorizedException" => {
                        GetCredentialsForIdentityError::NotAuthorized(String::from(error_message))
                    }
                    "ResourceConflictException" => {
                        GetCredentialsForIdentityError::ResourceConflict(String::from(
                            error_message,
                        ))
                    }
                    "ResourceNotFoundException" => {
                        GetCredentialsForIdentityError::ResourceNotFound(String::from(
                            error_message,
                        ))
                    }
                    "TooManyRequestsException" => {
                        GetCredentialsForIdentityError::TooManyRequests(String::from(error_message))
                    }
                    "ValidationException" => {
                        GetCredentialsForIdentityError::Validation(error_message.to_string())
                    }
                    _ => GetCredentialsForIdentityError::Unknown(String::from(body)),
                }
            }
            Err(_) => GetCredentialsForIdentityError::Unknown(String::from(body)),
        }
    }
}

/// <p>Input to the <code>GetCredentialsForIdentity</code> action.</p>
#[derive(Default, Debug, Clone, Serialize)]
pub struct GetCredentialsForIdentityInput {
    /// <p>The Amazon Resource Name (ARN) of the role to be assumed when multiple roles were received in the token from the identity provider. For example, a SAML-based identity provider. This parameter is optional for identity providers that do not support role customization.</p>
    #[serde(rename = "CustomRoleArn")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_role_arn: Option<String>,
    /// <p>A unique identifier in the format REGION:GUID.</p>
    #[serde(rename = "IdentityId")]
    pub identity_id: String,
    /// <p>A set of optional name-value pairs that map provider names to provider tokens.</p>
    #[serde(rename = "Logins")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logins: Option<::std::collections::HashMap<String, String>>,
}

#[doc="<p>Returned in response to a GetId request.</p>"]
#[derive(Default,Debug,Clone,Deserialize)]
pub struct GetCredentialsForIdentityResponse {
    /// <p>Credentials for the provided identity ID.</p>
    #[serde(rename = "Credentials")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials: Option<Credentials>,
    /// <p>A unique identifier in the format REGION:GUID.</p>
    #[serde(rename = "IdentityId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_id: Option<String>,
}

impl From<GetCredentialsForIdentityError> for Error { fn from(e: GetCredentialsForIdentityError) -> Error { Error::GetCredentialsForIdentityError(e) } }

pub fn get_credentials_for_identity(dispatcher: &Client, region: &Region, input: &GetCredentialsForIdentityInput) -> Result<GetCredentialsForIdentityResponse, Error> {
    let mut request = SignedRequest::new("POST", "cognito-identity", region, "/");

    request.set_content_type("application/x-amz-json-1.1".to_owned());
    request.add_header("user-agent", DEFAULT_USER_AGENT);
    request.add_header("x-amz-target", "AWSCognitoIdentityService.GetCredentialsForIdentity");
    let encoded = serde_json::to_string(&input)?;
    request.set_payload(Some(encoded.into_bytes()));
    let mut response = dispatcher.dispatch(&request)?;

    match response.status {
        StatusCode::Ok => {
            let mut body: Vec<u8> = Vec::new();
            try!(response.body.read_to_end(&mut body));
            Ok(serde_json::from_str::<GetCredentialsForIdentityResponse>(String::from_utf8_lossy(&body).as_ref())
               .unwrap())
        }
        _ => {
            let mut body: Vec<u8> = Vec::new();
            try!(response.body.read_to_end(&mut body));
            Err(Error::from(GetCredentialsForIdentityError::from_body(String::from_utf8_lossy(&body).as_ref())))
        }
    }
}

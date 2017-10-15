use hyper::Client;
use hyper::status::StatusCode;
use rusoto_core::SignedRequest;
use rusoto_core::{DispatchSignedRequest, Region};
use std::collections::BTreeMap;
use super::respond_to_auth_challenge::AuthenticationResult;

use ::error::Error;
use tools::DEFAULT_USER_AGENT;
use serde_json;

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize)]
#[derive(Debug)]
struct ErrorResponse {
    __type: String,
    message: String,
}

#[allow(non_snake_case)]
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthParameters {
    pub REFRESH_TOKEN: Option<String>,
    pub DEVICE_KEY: Option<String>,
    pub USERNAME: Option<String>,
    pub SRP_A: Option<String>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize)]
pub struct InitiateAuthParams {
    pub AuthFlow: String,
    pub ClientId: String,
    pub AuthParameters: AuthParameters,
    pub ClientMetadata: Option<BTreeMap<String, String>>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize)]
pub struct InitiateAuthChallengeParameters {
    pub SECRET_BLOCK: Option<String>,
    pub USER_ID_FOR_SRP: Option<String>,
    pub SRP_B: Option<String>,
    pub SALT: Option<String>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize)]
pub struct InitiateAuthResponse {
    ChallengeName: Option<String>,
    pub ChallengeParameters: InitiateAuthChallengeParameters,
    pub AuthenticationResult: Option<AuthenticationResult>,
}

pub fn initiate_auth(dispatcher: &Client, region: &Region, params: InitiateAuthParams) -> Result<InitiateAuthResponse, Error> {
    let mut request = SignedRequest::new("POST", "cognito-idp", region, "/");

    let payload = serde_json::to_string(&params)?.to_string();

    request.set_content_type("application/x-amz-json-1.1".to_owned());
    request.add_header("user-agent", DEFAULT_USER_AGENT);
    request.add_header("x-amz-target", &format!("AWSCognitoIdentityProviderService.InitiateAuth"));
    request.set_payload(Some(payload.into_bytes()));

    let mut response = try!(dispatcher.dispatch(&request));
    let mut body: Vec<u8> = Vec::new();
    response.body.read_to_end(&mut body)?;
    let body_str = String::from_utf8_lossy(&body);
    debug!("InitiateAuthResponse {}", body_str);

    match response.status {
        StatusCode::Ok => {
            Ok(serde_json::from_str::<InitiateAuthResponse>(body_str.as_ref())?)
        }
        _ => {
            let err_response = serde_json::from_str::<ErrorResponse>(body_str.as_ref())?;
            match &err_response.__type[..] {
                "UserNotFoundException" => Err(Error::UserNotFoundError(err_response.message.to_owned())),
                "NotAuthorizedException" => Err(Error::NotAuthorizedError(err_response.message.to_owned())), // clear cached tokens
                "ResourceNotFoundException" => Err(Error::ResourceNotFoundError(err_response.message.to_owned())),
                _ => Err(Error::BadResponseError(body_str.as_ref().to_string())),
            }
        }
    }
}



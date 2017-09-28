use hyper::Client;
use hyper::status::StatusCode;
use rusoto_core::SignedRequest;
use rusoto_core::{DispatchSignedRequest, Region};
use std::collections::BTreeMap;

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
#[derive(Serialize, Deserialize)]
#[derive(Debug)]
pub struct NewDeviceMetadata {
    pub DeviceGroupKey: String,
    pub DeviceKey: String,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize)]
#[derive(Debug)]
pub struct AuthenticationResult {
    pub AccessToken: String,
    pub ExpiresIn: usize,
    pub IdToken: String,
    pub NewDeviceMetadata: Option<NewDeviceMetadata>,
    pub RefreshToken: String,
    pub TokenType: String,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize)]
pub struct ChallengeResponses {
    pub USERNAME: String,
    pub PASSWORD_CLAIM_SECRET_BLOCK: String,
    pub TIMESTAMP: String,
    pub PASSWORD_CLAIM_SIGNATURE: String,
    //DEVICE_KEY: String,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize)]
pub struct RespondToAuthChallengeParams {
    pub ChallengeName: String,
    pub ClientId: String,
    pub ChallengeResponses: ChallengeResponses,
    //Session: String,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize)]
#[derive(Debug)]
pub struct RespondToAuthChallengeResponse {
    pub AuthenticationResult: AuthenticationResult,
    pub ChallengeParameters: BTreeMap<String, String>,
    pub ChallengeName: Option<String>,
    pub Session: Option<String>,
}

pub fn respond_to_auth_challenge(dispatcher: &Client, region: &Region, params: RespondToAuthChallengeParams) -> Result<RespondToAuthChallengeResponse, Error> {
    let mut request = SignedRequest::new("POST", "cognito-idp", region, "/");

    let payload = serde_json::to_string(&params)?.to_string();

    request.set_content_type("application/x-amz-json-1.1".to_owned());
    request.add_header("user-agent", DEFAULT_USER_AGENT);
    request.add_header("x-amz-target", &format!("AWSCognitoIdentityProviderService.RespondToAuthChallenge"));
    request.set_payload(Some(payload.into_bytes()));

    let mut response = try!(dispatcher.dispatch(&request));
    let mut body: Vec<u8> = Vec::new();
    response.body.read_to_end(&mut body)?;
    let body_str = String::from_utf8_lossy(&body);
    debug!("RespondToAuthChallengeResponse {}", body_str);

    match response.status {
        StatusCode::Ok => {
            Ok(serde_json::from_str::<RespondToAuthChallengeResponse>(body_str.as_ref())?)
        }
        _ => {
            let err_response = serde_json::from_str::<ErrorResponse>(body_str.as_ref())?;
            match &err_response.__type[..] {
                "NotAuthorizedException" => Err(Error::NotAuthorizedError(err_response.message.to_owned())),
                "ResourceNotFoundException" => {
                    if err_response.message.contains("device") {
                        // sign out here
                    }
                    Err(Error::ResourceNotFoundError(err_response.message.to_owned()))
                },
                _ => Err(Error::BadResponseError(body_str.as_ref().to_string())),
            }
        }
    }
}

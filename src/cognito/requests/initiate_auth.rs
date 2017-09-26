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
pub struct AuthParameters {
    pub USERNAME: String,
    pub SRP_A: String,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize)]
pub struct InitiateAuthParams {
    pub AuthFlow: String,
    pub ClientId: String,
    pub AuthParameters: AuthParameters,
    pub ClientMetadata: BTreeMap<String, String>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize)]
pub struct InitiateAuthChallengeParameters {
    pub SECRET_BLOCK: String,
    pub USER_ID_FOR_SRP: String,
    pub SRP_B: String,
    pub SALT: String,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize)]
pub struct InitiateAuthResponse {
    ChallengeName: String,
    pub ChallengeParameters: InitiateAuthChallengeParameters,
}

pub fn initiate_auth(dispatcher: &Client, region: &Region, params: InitiateAuthParams) -> Result<InitiateAuthResponse, Error> {
    let mut request = SignedRequest::new("POST", "cognito-idp", region, "/");

    let payload = serde_json::to_string(&params)?.to_string();

    request.set_content_type("application/x-amz-json-1.1".to_owned());
    request.add_header("user-agent", DEFAULT_USER_AGENT);
    request.add_header("x-amz-target", &format!("AWSCognitoIdentityProviderService.InitiateAuth"));
    request.set_payload(Some(payload.into_bytes()));

    let mut response = try!(dispatcher.dispatch(&request));
    match response.status {
        StatusCode::Ok => {
            let mut body: Vec<u8> = Vec::new();
            response.body.read_to_end(&mut body)?;
            let body_str = String::from_utf8_lossy(&body);
            Ok(serde_json::from_str::<InitiateAuthResponse>(body_str.as_ref())?)
        }
        _ => {
            let mut body: Vec<u8> = Vec::new();
            response.body.read_to_end(&mut body)?;
            Err(Error::BadResponseError(String::from_utf8_lossy(&body).as_ref().to_string()))
        }
    }
}



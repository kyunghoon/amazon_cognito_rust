use hyper::Client;
use hyper::status::StatusCode;
use rusoto_core::SignedRequest;
use rusoto_core::{DispatchSignedRequest, Region};

use ::error::Error;
use tools::DEFAULT_USER_AGENT;
use serde_json;

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize)]
pub struct DeviceSecretVerifierConfig {
    pub Salt: String,
    pub PasswordVerifier: String,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize)]
pub struct ConfirmDeviceParameters {
    pub DeviceKey: String,
    pub AccessToken: String,
    pub DeviceSecretVerifierConfig: DeviceSecretVerifierConfig,
    pub DeviceName: String,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize)]
pub struct ConfirmDeviceResponse {
    pub UserConfirmationNecessary: bool,
}

pub fn confirm_device(dispatcher: &Client, region: &Region, params: ConfirmDeviceParameters) -> Result<ConfirmDeviceResponse, Error> {
    let mut request = SignedRequest::new("POST", "cognito-idp", region, "/");

    let payload = serde_json::to_string(&params)?.to_string();

    request.set_content_type("application/x-amz-json-1.1".to_owned());
    request.add_header("user-agent", DEFAULT_USER_AGENT);
    request.add_header("x-amz-target", &format!("AWSCognitoIdentityProviderService.ConfirmDevice"));
    request.set_payload(Some(payload.into_bytes()));

    let mut response = try!(dispatcher.dispatch(&request));

    match response.status {
        StatusCode::Ok => {
            let mut body: Vec<u8> = Vec::new();
            response.body.read_to_end(&mut body)?;
            let body_str = String::from_utf8_lossy(&body);
            Ok(serde_json::from_str::<ConfirmDeviceResponse>(body_str.as_ref())?)
        }
        _ => {
            let mut body: Vec<u8> = Vec::new();
            response.body.read_to_end(&mut body)?;
            Err(Error::BadResponseError(String::from_utf8_lossy(&body).as_ref().to_string()))
        }
    }
}

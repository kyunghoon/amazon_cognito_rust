use rusoto_core::Region;
use base64::{encode, decode};
use chrono::prelude::{DateTime, Utc};
use hyper::Client;
use num::bigint::{BigUint};
use ring::digest;
use ring::hmac::{SigningKey, SigningContext};
use std::collections::BTreeMap;
use std::rc::Rc;
use std::cell::RefCell;

use ::error::Error;
use super::helpers::AuthHelper;
use super::requests::*;
use super::tools::{FromHex, ToBase64, DEFAULT_USER_AGENT};
use super::session::CognitoUserSession;

pub struct AuthDetails {
    username: String,
    password: String,
    validation_data: BTreeMap<String, String>,
}
impl AuthDetails {
    pub fn new(username: &str, password: &str, validation_data: BTreeMap<String, String>) -> AuthDetails {
        AuthDetails {
            username: username.to_string(),
            password: password.to_string(),
            validation_data: validation_data,
        }
    }
    pub fn get_validation_data(&self) -> &BTreeMap<String, String> {
        &self.validation_data
    }
    fn get_password(&self) -> &str {
        &self.password
    }
    fn get_username(&self) -> &str {
        &self.username
    }
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize)]
struct RespondToAuthChallengeParameters {
    requiredAttributes: String,
    userAttributes: String,
}

pub struct CognitoUserPool {
    client_id: String,
}

impl CognitoUserPool {
    fn new(_user_pool_id: &str, client_id: &str) -> CognitoUserPool {
        CognitoUserPool {
            client_id: client_id.to_string(),
        }
    }

    fn get_client_id(&self) -> &str {
        &self.client_id
    }
}

pub trait Storage {
    fn get_item(&self, _key: &str) -> Option<String>;
    fn set_item(&self, _key: &str, _val: &str);
}

pub trait AuthDelegate {
    fn on_failure(self: &Self, err: &Error);
    fn on_success(&self, session: &CognitoUserSession, confirmation_necessary: bool);
}

/**
 * @returns {string} The current time in "ddd MMM D HH:mm:ss UTC YYYY" format.
 */
fn get_now_string() -> String {
    let utc: DateTime<Utc> = Utc::now();
    utc.format("%a %b %-d %H:%M:%S UTC %Y").to_string()
}

pub struct CognitoUser<S: Storage> {
    region: Region,
    dispatcher: Client,
    user_pool_id: String,
    authentication_flow_type: String,
    username: RefCell<Option<String>>,
    pool: CognitoUserPool,
    storage: Rc<RefCell<S>>,
    device_key: RefCell<Option<String>>,
    random_password: RefCell<Option<String>>,
    device_group_key: RefCell<Option<String>>,
    verifier_devices: RefCell<Option<String>>,
    sign_in_user_session: RefCell<Option<CognitoUserSession>>,
}

impl<S: Storage> CognitoUser<S> {
    pub fn new(dispatcher: Client, storage: Rc<RefCell<S>>, user_pool_id: &str, client_id: &str, region: Region) -> CognitoUser<S> {
        CognitoUser {
            region: region,
            dispatcher: dispatcher,
            user_pool_id: user_pool_id.to_string(),
            authentication_flow_type: "USER_SRP_AUTH".to_string(),
            username: RefCell::new(None),
            pool: CognitoUserPool::new(user_pool_id, client_id),
            storage: storage,
            device_key: RefCell::new(None),
            random_password: RefCell::new(None),
            device_group_key: RefCell::new(None),
            verifier_devices: RefCell::new(None),
            sign_in_user_session: RefCell::new(None),
        }
    }

    /**
     * This is used to save the session tokens to local storage
     * @returns {void}
     */
    fn cache_tokens(&self) {
        let username = self.username.borrow().clone().unwrap();
        let key_prefix = format!("CognitoIdentityServiceProvider.{}", self.pool.get_client_id());
        let id_token_key = format!("{}.{}.idToken", key_prefix, username);
        let access_token_key = format!("{}.{}.accessToken", key_prefix, username);
        let refresh_token_key = format!("{}.{}.refreshToken", key_prefix, username);
        let last_user_key = format!("{}.LastAuthUser", key_prefix);

        let ref storage = *(*self.storage).borrow_mut();
        let ref session = *self.sign_in_user_session.borrow();
        storage.set_item(&id_token_key, session.as_ref().unwrap().id_token.get_jwt_token());
        storage.set_item(&access_token_key, session.as_ref().unwrap().access_token.get_jwt_token());
        storage.set_item(&refresh_token_key, session.as_ref().unwrap().refresh_token.get_token());
        storage.set_item(&last_user_key, &username);
    }

    pub fn access_token(&self) -> Result<String, Error> {
        if let Some(username) = self.username.borrow().clone() {
            let key_prefix = format!("CognitoIdentityServiceProvider.{}", self.pool.get_client_id());
            let token_key = format!("{}.{}.accessToken", key_prefix, username);
            if let Some(item) = self.storage.borrow().get_item(&token_key) {
                return Ok(item);
            }
        }
        Err(Error::RuntimeError("failed to get access token".to_string()))
    }

    pub fn id_token(&self) -> Result<String, Error> {
        if let Some(username) = self.username.borrow().clone() {
            let key_prefix = format!("CognitoIdentityServiceProvider.{}", self.pool.get_client_id());
            let token_key = format!("{}.{}.idToken", key_prefix, username);
            if let Some(item) = self.storage.borrow().get_item(&token_key) {
                return Ok(item);
            }
        }
        Err(Error::RuntimeError("failed to get id token".to_string()))
    }

    pub fn refresh_token(&self) -> Result<String, Error> {
        if let Some(username) = self.username.borrow().clone() {
            let key_prefix = format!("CognitoIdentityServiceProvider.{}", self.pool.get_client_id());
            let token_key = format!("{}.{}.refreshToken", key_prefix, username);
            if let Some(item) = self.storage.borrow().get_item(&token_key) {
                return Ok(item);
            }
        }
        Err(Error::RuntimeError("failed to get refresh token".to_string()))
    }

    /**
     * This is used to cache the device key and device group and device password
     * @returns {void}
     */
    fn cache_device_key_and_password(&self) {
        let ref username = *self.username.borrow();
        let key_prefix = format!("CognitoIdentityServiceProvider.{}.{}", self.pool.get_client_id(), username.as_ref().unwrap());

        let device_key_key = format!("{}.deviceKey", key_prefix);
        let random_password_key = format!("{}.randomPasswordKey", key_prefix);
        let device_group_key_key = format!("{}.deviceGroupKey", key_prefix);

        let ref storage = *(*self.storage).borrow_mut();
        let ref device_key = *self.device_key.borrow();
        storage.set_item(&device_key_key, &device_key.as_ref().unwrap());
        let ref random_password = *self.random_password.borrow();
        storage.set_item(&random_password_key, &random_password.as_ref().unwrap());
        let ref device_group_key = *self.device_group_key.borrow();
        storage.set_item(&device_group_key_key, &device_group_key.as_ref().unwrap());
    }

    /**
     * This is used to get current device key and device group and device password
     * @returns {void}
     */
    fn get_cached_device_key_and_password(&self) {
        let key_prefix = format!("CognitoIdentityServiceProvider.{}.{}", self.pool.get_client_id(), self.username.borrow_mut().clone().unwrap());
        let device_key_key = format!("{}.deviceKey", key_prefix);
        let random_password_key = format!("{}.randomPasswordKey", key_prefix);
        let device_group_key_key = format!("{}.deviceGroupKey", key_prefix);

        let ref storage = *(*self.storage).borrow_mut();
        if storage.get_item(&device_key_key).is_none() {
            *self.device_key.borrow_mut() = storage.get_item(&device_key_key).map(|s| s.to_string());
            *self.random_password.borrow_mut() = storage.get_item(&random_password_key).map(|s| s.to_string());
            *self.device_group_key.borrow_mut() = storage.get_item(&device_group_key_key).map(|s| s.to_string());
        }
    }

    /**
     * This is used for authenticating the user. it calls the AuthenticationHelper for SRP related
     * stuff
     * @param {AuthenticationDetails} authDetails Contains the authentication data
     * @param {object} callback Result callback map.
     * @param {onFailure} callback.onFailure Called on any error.
     * @param {newPasswordRequired} callback.newPasswordRequired new
     *        password and any required attributes are required to continue
     * @param {mfaRequired} callback.mfaRequired MFA code
     *        required to continue.
     * @param {customChallenge} callback.customChallenge Custom challenge
     *        response required to continue.
     * @param {authSuccess} callback.onSuccess Called on success with the new session.
     * @returns {void}
     */
    pub fn authenticate_user<D: AuthDelegate>(&self, auth_details: &AuthDetails, delegate: &D) -> Result<(), Error> {
        let split = &self.user_pool_id.split("_").collect::<Vec<_>>();
        if split.len() != 2 {
            return Err(Error::IllegalParameterError(format!("invalid user pool id format '{}'", self.user_pool_id).to_string()))
        }

        let pool_name = split[1];

        let helper = AuthHelper::new(&pool_name);

        let large_a_result = helper.get_large_a_value()?;

        let initiate_auth: InitiateAuthResponse = initiate_auth(&self.dispatcher, &self.region, InitiateAuthParams {
            AuthFlow: self.authentication_flow_type.to_string(),
            AuthParameters: AuthParameters {
                SRP_A: large_a_result.to_str_radix(16),
                USERNAME: auth_details.get_username().to_string(),
            },
            ClientId: self.pool.get_client_id().to_string(),
            ClientMetadata: auth_details.get_validation_data().clone(),
        })?;

        let challenge_parameters = initiate_auth.ChallengeParameters;

        let username = challenge_parameters.USER_ID_FOR_SRP;
        *self.username.borrow_mut() = Some(username.clone());

        let server_b_value = BigUint::parse_bytes(&challenge_parameters.SRP_B.as_bytes(), 16).unwrap();

        let salt = BigUint::parse_bytes(&challenge_parameters.SALT.as_bytes(), 16).unwrap();
        self.get_cached_device_key_and_password();

        let auth_key_result = helper.get_password_authentication_key(&username, &auth_details.get_password(), &server_b_value, &salt);

        let hkdf = auth_key_result;

        let date_now = get_now_string();

        let secret_block = challenge_parameters.SECRET_BLOCK;

        let s_key = SigningKey::new(&digest::SHA256, &hkdf?);
        let mut s_ctx = SigningContext::with_key(&s_key);
        let md5_encoded_secret_block = decode(&secret_block)?;
        let update_data = vec!(pool_name.as_bytes(), username.as_bytes(), md5_encoded_secret_block.as_ref(), date_now.as_bytes());
        let flattened = (update_data.as_ref() as &Vec<&[_]>).into_iter().flat_map(|k| k.to_vec()).collect::<Vec<_>>();
        s_ctx.update(&flattened);
        let signature_string = encode(s_ctx.sign().as_ref());

        let data_authenticate = respond_to_auth_challenge(&self.dispatcher, &self.region, RespondToAuthChallengeParams {
            ChallengeName: "PASSWORD_VERIFIER".to_string(),
            ChallengeResponses: ChallengeResponses {
                PASSWORD_CLAIM_SECRET_BLOCK: secret_block.to_string(),
                PASSWORD_CLAIM_SIGNATURE: signature_string,
                TIMESTAMP: date_now.clone(),
                USERNAME: username.clone(),
            },
            ClientId: self.pool.get_client_id().to_string(),
        })?;

        if let &Some(ref challenge_name) = &data_authenticate.ChallengeName {
            if challenge_name == "NEW_PASSWORD_REQUIRED" {
                panic!("NEW_PASSWORD_REQUIRED NYI");
                /*
                let mut user_attributes = Value::Null;
                let mut required_attributes: Vec<String> = vec!();
                let user_attributes_prefix = AuthHelper::get_new_password_required_challenge_user_attribute_prefix();

                if let &Some(ref challenge_parameters) = &data_authenticate.ChallengeParameters {
                    user_attributes = serde_json::from_str(&challenge_parameters.userAttributes)?;
                    if let Ok(raw_required_attributes) = serde_json::from_str::<Vec<String>>(&challenge_parameters.requiredAttributes) {
                        required_attributes = raw_required_attributes.iter().map(|a| a[0..user_attributes_prefix.len()].to_string()).collect::<Vec<_>>();
                    }
                }

                delegate.new_password_required(&user_attributes, required_attributes);
                */
            }
        }

        self.authenticate_user_internal(&data_authenticate, &helper, delegate)
    }

    /**
     * This is used to build a user session from tokens retrieved in the authentication result
     * @param {object} authResult Successful auth response from server.
     * @returns {CognitoUserSession} The new user session.
     * @private
     */
    fn get_cognito_user_session(&self, auth_result: &AuthenticationResult) -> CognitoUserSession {
        CognitoUserSession::new(auth_result)
    }

    /**
     * PRIVATE ONLY: This is an internal only method and should not
     * be directly called by the consumers.
     * @param {object} dataAuthenticate authentication data
     * @param {object} authenticationHelper helper created
     * @param {callback} callback passed on from caller
     * @returns {void}
     */
    fn authenticate_user_internal<D: AuthDelegate>(&self, data_authenticate: &RespondToAuthChallengeResponse, helper: &AuthHelper, delegate: &D) -> Result<(), Error> {
        let challenge_name = &data_authenticate.ChallengeName;

        match challenge_name {
            &Some(ref name) if name == "SMS_MFS" => {
                panic!("SMS_MFS NYI");
                //*self.session.borrow_mut() = Some(data_authenticate.Session.unwrap());
                //delegate.mfa_required(challenge_name, challenge_parameters);
            }
            &Some(ref name) if name == "CUSTOM_CHALLENGE" => {
                panic!("CUSTOM_CHALLENGE NYI");
                //*self.session.borrow_mut() = Some(data_authenticate.Session.unwrap());
                //delegate.custom_challenge(challenge_parameters);
            }
            &Some(ref name) if name == "DEVICE_SRP_AUTH" => {
                panic!("DEVICE_SRP_AUTH NYI");
                //self.get_device_response(&delegate);
            }
            _ => {
                *self.sign_in_user_session.borrow_mut() = Some(self.get_cognito_user_session(&data_authenticate.AuthenticationResult));
                self.cache_tokens();

                match &data_authenticate.AuthenticationResult.NewDeviceMetadata {
                    &None => {
                        let ref sign_in_user_session = *self.sign_in_user_session.borrow();
                        delegate.on_success(&sign_in_user_session.as_ref().unwrap(), false);
                        Ok(())
                    }
                    &Some(ref new_device_metadata) => {
                        helper.generate_hash_device(
                            &new_device_metadata.DeviceGroupKey,
                            &new_device_metadata.DeviceKey);

                        let password_verifier = helper.get_verifier_devices().from_hex().unwrap().to_base64();

                        *self.verifier_devices.borrow_mut() = Some(password_verifier.to_string());
                        *self.device_group_key.borrow_mut() = Some(new_device_metadata.DeviceGroupKey.clone());
                        *self.random_password.borrow_mut() = Some(helper.get_random_password());

                        let data_confirm = confirm_device(&self.dispatcher, &self.region, ConfirmDeviceParameters {
                            DeviceKey: new_device_metadata.DeviceKey.clone(),
                            AccessToken: self.sign_in_user_session.borrow().as_ref().unwrap().access_token.get_jwt_token().to_string(),
                            DeviceSecretVerifierConfig: DeviceSecretVerifierConfig {
                                Salt: helper.get_salt_devices().from_hex().unwrap().to_base64(),
                                PasswordVerifier: password_verifier,
                            },
                            DeviceName: DEFAULT_USER_AGENT.to_string(),
                        })?;

                        *self.device_key.borrow_mut() = Some(new_device_metadata.DeviceKey.clone());
                        self.cache_device_key_and_password();

                        delegate.on_success(self.sign_in_user_session.borrow().as_ref().unwrap(), data_confirm.UserConfirmationNecessary);

                        Ok(())
                    }
                }
            }
        }
    }
}

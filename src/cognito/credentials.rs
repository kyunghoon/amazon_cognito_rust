use hyper;
use std::cell::{RefCell};
use rusoto_core::{default_tls_client, ProvideAwsCredentials, Region, AwsCredentials, CredentialsError};
use super::requests::{GetIdInput, get_id, GetIdError};
use super::requests::{GetCredentialsForIdentityInput, get_credentials_for_identity, GetCredentialsForIdentityError};
use super::requests::{GetOpenIdTokenInput, get_open_id_token, GetOpenIdTokenError};
use rusoto_sts::{Sts, StsClient, AssumeRoleWithWebIdentityRequest, Credentials as StsCredentials};
use chrono::{Utc, Duration, DateTime, NaiveDateTime};
use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;
use ::error::Error;
use std::rc::Rc;
use super::Storage;

static LOCAL_STORAGE_KEY_ID: &str = "aws.cognito.identity-id.";
static LOCAL_STORAGE_KEY_PROVIDERS: &str = "aws.cognito.identity-providers.";

/**
 * A credentials object can be ated using positional arguments or an options
 * hash.
 *
 * @overload AWS.Credentials(accessKeyId, secretAccessKey, sessionToken=null)
 *   Creates a Credentials object with a given set of credential information
 *   as positional arguments.
 *   @param accessKeyId [String] the AWS access key ID
 *   @param secretAccessKey [String] the AWS secret access key
 *   @param sessionToken [String] the optional AWS session token
 *   @example Create a credentials object with AWS credentials
 *     var creds = new AWS.Credentials('akid', 'secret', 'session');
 * @overload AWS.Credentials(options)
 *   Creates a Credentials object with a given set of credential information
 *   as an options hash.
 *   @option options accessKeyId [String] the AWS access key ID
 *   @option options secretAccessKey [String] the AWS secret access key
 *   @option options sessionToken [String] the optional AWS session token
 *   @example Create a credentials object with AWS credentials
 *     var creds = new AWS.Credentials({
 *       accessKeyId: 'akid', secretAccessKey: 'secret', sessionToken: 'session'
 *     });
 */

pub trait Refreshable {
  fn refresh(&self) -> Result<Option<StsCredentials>, Error>;
}

pub struct Credentials<T: Refreshable> {
    expired: RefCell<bool>,
    expire_time: RefCell<Option<DateTime<Utc>>>,
    access_key_id: RefCell<Option<String>>,
    secret_access_key: RefCell<Option<String>>,
    session_token: RefCell<Option<String>>,
    expiry_window: i64, // the window size in seconds to attempt refreshing of credentials before the expireTime occurs.
    refreshable: T,
}

impl<T> Credentials<T> where T: Refreshable {
  pub fn new(refreshable: T) -> Credentials<T> {
      Credentials {
          expired: RefCell::new(true),
          expire_time: RefCell::new(None),
          access_key_id: RefCell::new(None),
          secret_access_key: RefCell::new(None),
          session_token: RefCell::new(None),
          expiry_window: 15,
          refreshable,
      }
  }

  fn credentials_from(&self, data: Option<StsCredentials>) -> () {
    if let Some(credentials) = data {
      if let Some(exp) = credentials.expiration.parse::<f64>().ok() {
        *self.expired.borrow_mut() = false;
        *self.access_key_id.borrow_mut() = Some(credentials.access_key_id);
        *self.secret_access_key.borrow_mut() = Some(credentials.secret_access_key);
        *self.session_token.borrow_mut() = Some(credentials.session_token);
        *self.expire_time.borrow_mut() = Some(DateTime::from_utc(NaiveDateTime::from_timestamp(exp as i64, 0), Utc));
      }
    }
  }

  /**
   * @return [Boolean] whether the credentials object should call {refresh}
   * @note Subclasses should override this method to provide custom refresh
   *   logic.
   */
  pub fn needs_refresh(&self) -> bool {
      let adjusted_time = Utc::now() + Duration::seconds(self.expiry_window);
      match *self.expire_time.borrow() {
        Some(time) => adjusted_time > time,
        None => *self.expired.borrow() || self.access_key_id.borrow().is_none() || self.secret_access_key.borrow().is_none()
      }
  }

  fn refresh(&self) -> Result<Option<StsCredentials>, Error> {
    self.refreshable.refresh()
  }

  /**
   * Gets the existing credentials, refreshing them if they are not yet loaded
   * or have expired. Users should call this method before using {refresh},
   * as this will not attempt to reload credentials when they are already
   * loaded into the object.
   *
   * @callback callback function(err)
   *   When this callback is called with no error, it means either credentials
   *   do not need to be refreshed or refreshed credentials information has
   *   been loaded into the object (as the `accessKeyId`, `secretAccessKey`,
   *   and `sessionToken` properties).
   *   @param err [Error] if an error occurred, this value will be filled
   */
  fn get(&self) -> Result<(), Error> {
    if self.needs_refresh() {
      self.credentials_from(self.refreshable.refresh()?);
      *self.expired.borrow_mut() = false; // reset expired flag
    }
    Ok(())
  }

  fn get_credentials(&self) -> Result<Option<AwsCredentials>, Error> {
    self.get()?;
    if let Some(access_key_id) = self.access_key_id.borrow().to_owned() {
      if let Some(secret_key) = self.secret_access_key.borrow().to_owned() {
        if let Some(session_token) = self.session_token.borrow().to_owned() {
          if let Some(expiration) = self.expire_time.borrow().to_owned() {
            return Ok(Some(AwsCredentials::new(
              access_key_id,
              secret_key,
              Some(session_token),
              expiration,
            )));
          }
        }
      }
    }
    Ok(None)
  }

}

//////////////////////////////////

struct CredentialsProvider { credentials: Option<AwsCredentials> }
impl ProvideAwsCredentials for CredentialsProvider {
    fn credentials(&self) -> Result<AwsCredentials, CredentialsError> {
        self.credentials.clone().ok_or(CredentialsError::new("failed to get aws credentials".to_owned()))
    }
}

struct WebIdentityParams {
  role_session_name: Option<String>,
  web_identity_token: RefCell<Option<String>>,
}

struct WebIdentity<'a, P: 'a + ProvideAwsCredentials> {
  provider: &'a P,
  region: &'a Region,
  role_session_name: String,
  role_arn: RefCell<Option<String>>,
  web_identity_token: RefCell<Option<String>>,
  service: RefCell<Option<StsClient<CredentialsProvider, hyper::Client>>>,
}

impl<'a, P> WebIdentity<'a, P> where P: ProvideAwsCredentials {
  /**
   * Creates a new credentials object.
   * @param (see AWS.STS.assumeRoleWithWebIdentity)
   * @example Creating a new credentials object
   *   AWS.config.credentials = new AWS.WebIdentityCredentials({
   *     RoleArn: 'arn:aws:iam::1234567890:role/WebIdentity',
   *     WebIdentityToken: 'ABCDEFGHIJKLMNOP', // token from identity service
   *     RoleSessionName: 'web' // optional name, defaults to web-identity
   *   }, {
   *     // optionally provide configuration to apply to the underlying AWS.STS service client
   *     // if configuration is not provided, then configuration will be pulled from AWS.config
   *
   *     // specify timeout options
   *     httpOptions: {
   *       timeout: 100
   *     }
   *   });
   * @see AWS.STS.assumeRoleWithWebIdentity
   * @see AWS.Config
   */
  fn new(provider: &'a P, params: WebIdentityParams, region: &'a Region) -> WebIdentity<'a, P> {
    WebIdentity {
      provider,
      region,
      role_session_name: params.role_session_name.unwrap_or("web-identity".to_owned()),
      role_arn: RefCell::new(None),
      web_identity_token: params.web_identity_token,
      service: RefCell::new(None),
      //this.data = null;
      //this._clientConfig = AWS.util.copy(clientConfig || {});
    }
  }

  fn create_clients(&self) -> Result<(), Error> {
    if self.service.borrow().is_none() {
      let provider = CredentialsProvider { credentials: Some(self.provider.credentials()?) };
      *self.service.borrow_mut() = Some(StsClient::new(default_tls_client()?, provider, self.region.to_owned()));
    }
    Ok(())
  }
}

impl<'a, P> Refreshable for WebIdentity<'a, P> where P: ProvideAwsCredentials {
  /**
   * Refreshes credentials using {AWS.STS.assumeRoleWithWebIdentity}
   *
   * @callback callback function(err)
   *   Called when the STS service responds (or fails). When
   *   this callback is called with no error, it means that the credentials
   *   information has been loaded into the object (as the `accessKeyId`,
   *   `secretAccessKey`, and `sessionToken` properties).
   *   @param err [Error] if an error occurred, this value will be filled
   * @see get
   */
  fn refresh(&self) -> Result<Option<StsCredentials>, Error> {
    self.create_clients()?;

    if let Some(service) = &*self.service.borrow_mut() {
      let request = AssumeRoleWithWebIdentityRequest {
        duration_seconds: None,
        policy: None,
        provider_id: None,
        role_arn: self.role_arn.borrow().to_owned().unwrap(),
        role_session_name: self.role_session_name.to_owned(),
        web_identity_token: self.web_identity_token.borrow().to_owned().unwrap(),
      };
      let data = service.assume_role_with_web_identity(&request)?;
      Ok(data.credentials)
    } else {
      Ok(None)
    }
  }
}

pub struct WebIdentityCredentials<'a, P: 'a + ProvideAwsCredentials> {
  identity: Credentials<WebIdentity<'a, P>>,
}
  
impl<'a, P> WebIdentityCredentials<'a, P> where P: ProvideAwsCredentials {
  fn new(provider: &'a P, params: WebIdentityParams, region: &'a Region) -> WebIdentityCredentials<'a, P> {
    WebIdentityCredentials {
      identity: Credentials::new(WebIdentity::new(provider, params, region)),
    }
  }
  fn refresh(&self) -> Result<Option<StsCredentials>, Error> {
    self.identity.refresh()
  }
}

//////////////////////////////////
      
pub struct CognitoIdentityParams {
  pub identity_pool_id: String,
  pub logins: Option<HashMap<String, String>>,
  pub login_id: Option<String>,
  pub identity_id: RefCell<Option<String>>,
  pub role_session_name: Option<String>,
  pub role_arn: RefCell<Option<String>>,
}

pub struct RefreshableCognitoIdentity<'a, P: 'a + ProvideAwsCredentials, S: Storage> {
  provider: &'a P,
  storage: Rc<RefCell<S>>,
  region: &'a Region,
  params: CognitoIdentityParams,
  web_identity_credentials: RefCell<Option<WebIdentityCredentials<'a, P>>>,
  //sts: RefCell<Option<StsClient<CredentialsProvider, hyper::Client>>>,
  identity_id: RefCell<Option<String>>,
}

impl<'a, P, S> RefreshableCognitoIdentity<'a, P, S> where P: ProvideAwsCredentials, S: Storage {
  fn new(provider: &'a P, storage: Rc<RefCell<S>>, params: CognitoIdentityParams, region: &'a Region) -> RefreshableCognitoIdentity<'a, P, S> {
    let ret = RefreshableCognitoIdentity {
      provider,
      storage,
      region,
      params,
      web_identity_credentials: RefCell::new(None),
      //sts: RefCell::new(None),
      identity_id: RefCell::new(None),
    };
    ret.load_cached_id();
    ret
  }

  fn load_cached_id(&self) -> () {
    if self.params.identity_id.borrow().is_none() {
      if let Some(id) = self.get_storage_id() {
        if let Some(actual_providers) = self.params.logins.to_owned().map(|p| p.iter().map(|(_, l)| l.clone()).collect::<Vec<_>>()) {
          if actual_providers.len() > 0 {
            if let Some(cached_providers) = self.get_storage_providers() {
              // only load ID if at least one provider used this ID before
              let a: HashSet<String> = HashSet::from_iter(cached_providers.iter().cloned());
              let b: HashSet<String> = HashSet::from_iter(actual_providers.iter().cloned());
              let intersect = a.intersection(&b).collect::<Vec<_>>();
              if intersect.len() > 0 {
                  *self.params.identity_id.borrow_mut() = Some(id);
              }
            }
          }
        } else {
          *self.params.identity_id.borrow_mut() = Some(id);
        }
      }
    }
  }

  fn get_storage_providers(&self) -> Option<Vec<String>> {
    let pool_id = &self.params.identity_pool_id;
    let login_id = &self.params.login_id.to_owned().unwrap_or("".to_owned());
    (*self.storage.borrow_mut()).get_item(&format!("{}{}{}", LOCAL_STORAGE_KEY_PROVIDERS, pool_id, login_id))
        .map(|s| s.split(",").map(String::from).collect::<Vec<_>>())
  }

  fn set_storage_providers(&self, providers: Option<&Vec<String>>) -> () {
    let pool_id = &self.params.identity_pool_id;
    let login_id = &self.params.login_id.to_owned().unwrap_or("".to_owned());
    let value = providers.map(|ps| ps.join(","));
    (*self.storage.borrow_mut()).set_item(&format!("{}{}{}", LOCAL_STORAGE_KEY_PROVIDERS, pool_id, login_id), value.as_ref().map(|r| &**r));
  }

  fn get_storage_id(&self) -> Option<String> {
    let pool_id = &self.params.identity_pool_id;
    let login_id = &self.params.login_id.to_owned().unwrap_or("".to_owned());
    (*self.storage.borrow_mut()).get_item(&format!("{}{}{}", LOCAL_STORAGE_KEY_ID, pool_id, login_id))
  }

  fn set_storage_id(&self, id: Option<&str>) -> () {
    let pool_id = &self.params.identity_pool_id;
    let login_id = &self.params.login_id.to_owned().unwrap_or("".to_owned());
    (*self.storage.borrow_mut()).set_item(&format!("{}{}{}", LOCAL_STORAGE_KEY_ID, pool_id, login_id), id);
  }

  /**
   * Clears the cached Cognito ID associated with the currently configured
   * identity pool ID. Use this to manually invalidate your cache if
   * the identity pool ID was deleted.
   */
  fn clear_cached_id(&self) -> () {
    *self.identity_id.borrow_mut() = None;
    *self.params.identity_id.borrow_mut() = None;

    self.set_storage_id(None);
    self.set_storage_providers(None);
  }

  fn cache_id(&self, identity_id: &Option<String>) -> () {
    if let Some(id) = identity_id {
      *self.identity_id.borrow_mut() = Some(id.to_owned());
      *self.params.identity_id.borrow_mut() = Some(id.to_owned());

      self.set_storage_id(Some(&id));

      if let Some(ref logins) = self.params.logins.as_ref() {
        if logins.len() > 0 {
          self.set_storage_providers(Some(&logins.iter().map(|(_, login)| login.clone()).collect::<Vec<_>>()));
        }
      }
    }
  }

  fn get_identity_id(&self) -> Option<String> {
    self.identity_id.borrow_mut().to_owned()
  }

  /**
   * Retrieves a Cognito ID, loading from cache if it was already retrieved
   * on this device.
   *
   * @callback callback function(err, identityId)
   *   @param err [Error, null] an error object if the call failed or null if
   *     it succeeded.
   *   @param identityId [String, null] if successful, the callback will return
   *     the Cognito ID.
   * @note If not loaded explicitly, the Cognito ID is loaded and stored in
   *   localStorage in the browser environment of a device.
   * @api private
   */
  fn get_id(&self) -> Result<String, Error> {
    if let Some(identity_id) = self.params.identity_id.borrow().to_owned() {
      Ok(identity_id)
    } else {
      let input = GetIdInput {
        IdentityPoolId: self.params.identity_pool_id.to_owned(),
        Logins: self.params.logins.to_owned(),
      };
      let data = get_id(&default_tls_client()?, &self.region, &input)?;
      Ok(data.IdentityId)
    }
  }

  fn get_credentials_for_identity(&self, identity_id: &str) -> Result<Option<StsCredentials>, Error> {
    let input = GetCredentialsForIdentityInput {
      custom_role_arn: None,
      identity_id: identity_id.to_owned(),
      logins: self.params.logins.to_owned(),
    };
    match get_credentials_for_identity(&default_tls_client()?, &self.region, &input) {
      Err(Error::GetCredentialsForIdentityError(GetCredentialsForIdentityError::NotAuthorized(msg))) => {
        self.clear_cached_id();
        Err(Error::GetCredentialsForIdentityError(GetCredentialsForIdentityError::NotAuthorized(msg)))
      },
      Err(err) => Err(err),
      Ok(data) => {
        self.cache_id(&data.identity_id);
        match data.credentials {
          None => Ok(None),
          Some(credentials) => {
            if credentials.access_key_id.is_none() ||
              credentials.expiration.is_none() ||
              credentials.secret_key.is_none() ||
              credentials.session_token.is_none() {
              Ok(None)
            } else {
              Ok(Some(StsCredentials {
                  access_key_id: credentials.access_key_id.unwrap(),
                  expiration: credentials.expiration.unwrap().to_string(),
                  secret_access_key: credentials.secret_key.unwrap(),
                  session_token: credentials.session_token.unwrap(),
              }))
            }
          }
        }
      }
    }
  }

  fn get_credentials_from_sts(&self) -> Result<Option<StsCredentials>, Error> {
    let input = GetOpenIdTokenInput {
      identity_id: self.params.identity_id.borrow().to_owned().unwrap(),
      logins: self.params.logins.to_owned(),
    };
    match get_open_id_token(&default_tls_client()?, &self.region, input) {
      Err(Error::GetOpenIdTokenError(GetOpenIdTokenError::NotAuthorized(msg))) => {
        self.clear_cached_id();
        Err(Error::GetOpenIdTokenError(GetOpenIdTokenError::NotAuthorized(msg)))
      },
      Err(err) => Err(err),
      Ok(data) => {
        match self.web_identity_credentials.borrow().as_ref() {
          None => Ok(None),
          Some(ref web_identity_credentials) => {
            self.cache_id(&data.identity_id);
            web_identity_credentials.refresh()
          }
        }
      }
    }
  }

  fn create_clients(&self) -> Result<(), Error> {
    if self.web_identity_credentials.borrow().is_none() {
      *self.web_identity_credentials.borrow_mut() = Some(WebIdentityCredentials::new(
        self.provider,
        WebIdentityParams {
          role_session_name: self.params.role_session_name.to_owned(),
          web_identity_token: RefCell::new(None),
        },
        self.region));
    }
    Ok(())
  }
}

impl<'a, P, S> Refreshable for RefreshableCognitoIdentity<'a, P, S> where P: ProvideAwsCredentials, S: Storage {
  /**
   * Refreshes credentials using {AWS.CognitoIdentity.getCredentialsForIdentity},
   * or {AWS.STS.assumeRoleWithWebIdentity}.
   *
   * @callback callback function(err)
   *   Called when the STS service responds (or fails). When
   *   this callback is called with no error, it means that the credentials
   *   information has been loaded into the object (as the `accessKeyId`,
   *   `secretAccessKey`, and `sessionToken` properties).
   *   @param err [Error] if an error occurred, this value will be filled
   * @see get
   */
  fn refresh(&self) -> Result<Option<StsCredentials>, Error> {
    self.create_clients()?;

    *self.identity_id.borrow_mut() = None;

    match self.get_id() {
      Err(Error::GetIdError(GetIdError::NotAuthorized(msg))) => {
        self.clear_cached_id();
        Err(Error::GetIdError(GetIdError::NotAuthorized(msg)))
      },
      Err(err) => Err(err),
      Ok(identity_id) => {
        if self.params.role_arn.borrow().is_none() {
          self.get_credentials_for_identity(&identity_id)
        } else {
          self.get_credentials_from_sts()
        }
      }
    }
  }
}

pub struct CognitoIdentityCredentials<'a, P: 'a + ProvideAwsCredentials, S: Storage> {
  credentials: Credentials<RefreshableCognitoIdentity<'a, P, S>>,
}
  
impl<'a, P, S> CognitoIdentityCredentials<'a, P, S> where P: ProvideAwsCredentials, S: Storage {
  pub fn new(provider: &'a P, storage: Rc<RefCell<S>>, params: CognitoIdentityParams, region: &'a Region) -> CognitoIdentityCredentials<'a, P, S> {
    CognitoIdentityCredentials {
      credentials: Credentials::new(RefreshableCognitoIdentity::new(provider, storage, params, region)),
    }
  }

  pub fn get_credentials(&self) -> Result<Option<AwsCredentials>, Error> {
    self.credentials.get_credentials()
  }
}

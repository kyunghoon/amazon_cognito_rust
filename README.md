# Amazon Cognito Client for Rust

Work in progress...

---

## Usage

    extern crate rusoto_core;
    extern crate amazon_cognito_rust;

    use rusoto_core::{DefaultCredentialsProvider, default_tls_client, Region};
    use amazon_cognito_rust::{CognitoUserSession, CognitoUser, AuthDetails, AuthDelegate, Storage};

    struct MyStorage {}
    impl Storage for MyStorage {
        fn get_item(&self, key: &str) -> Option<String> {
            // read from somewhere
            None
        }
        fn set_item(&self, key: &str, val: &str) {
            // write to somewhere
        }
    }

    fn main() -> Result<(), Error> {
      let storage = MyStorage {};
      let user = CognitoUser::new(default_tls_client().unwrap(), &storage, USER_POOL_ID, CLIENT_ID, Region::UsEast1);
      match user.authenticate_user(&AuthDetails::new(username, password, BTreeMap::new()))? {
        AuthResult::SmsMfs => Err(Error::NotYetImplemented),
        AuthResult::CustomChallenge => Err(Error::NotYetImplemented),
        AuthResult::DeviceSrpAuth => Err(Error::NotYetImplemented),
        AuthResult::Success { session, confirmation_necessary } => {
          if confirmation_necessary {
              Err(Error::NotYetImplemented)
          } else {
            let access_token = session.access_token.get_jwt_token();
            let id_token = session.id_token.get_jwt_token();
            let refresh_token = session.refresh_token.get_token().to_owned();

            // refresh session
            //let new_session = user.refresh_session(refresh_token)?;

            // get aws credentials
            let params = CognitoIdentityParams {
              identity_pool_id: IDENTITY_POOL_ID,
              logins: Some([
                (format!("cognito-idp.{}.amazonaws.com/{}", Region::UsEast1, USER_POOL_ID).to_string(), self.user.id_token()?)
              ].iter().cloned().collect::<HashMap<_, _>>()),
              login_id: None,
              identity_id: RefCell::new(None),
              role_session_name: None,
              role_arn: RefCell::new(None),
            };
            let aws_credentials = CognitoIdentityCredentials::new(self, self.storage.clone(), Region::UsEast1, params).get_credentials()?;

            // get sub
            let sub = user.get_sub(&access_token, &aws_credentials)?;

            Ok(());
          }
        },
      }
    }


## Status

- [x] SRP
- [x] Initiate auth
- [x] Receives device-key, access-token
- [x] User authentication
- [x] Refresh session
- [ ] New Password required
- [ ] SMS MFS
- [ ] Custom Challenge
- [ ] Device SRP Auth


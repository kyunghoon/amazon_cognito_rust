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

    struct MyAuthDelegate {}
    impl AuthDelegate for MyAuthDelegate {
        fn on_failure(&self, err: &CognitoError) {
            println!("failed to authenticate user - {:?}", err);
        }
        fn on_success(&self, session: &CognitoUserSession, confirmation_necessary: bool) {
            println!("ACCESS_TOKEN {}", session.access_token.get_jwt_token());
            println!("ID_TOKEN {}", session.id_token.get_jwt_token());
            println!("REFRESH_TOKEN {}", session.refresh_token.get_token().to_string());
        }
    }

    fn main() {
      let storage = MyStorage {};
      let user = CognitoUser::new(default_tls_client().unwrap(), &storage, USER_POOL_ID, CLIENT_ID, Region::UsEast1);
      user.authenticate_user(&AuthDetails::new(username, password, BTreeMap::new()), &MyAuthDelegate {}).unwrap();

      // to refresh session
      // user.refresh_session(refresh_token);
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


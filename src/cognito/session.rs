use super::requests::{AuthenticationResult};

#[derive(Debug, Clone)]
pub struct CognitoIdToken {
    jwt_token: String,
}

impl CognitoIdToken {
    fn new(jwt_token: &str) -> CognitoIdToken {
        CognitoIdToken {
            jwt_token: jwt_token.to_string()
        }
    }
    pub fn get_jwt_token(&self) -> &str {
        &self.jwt_token
    }
    fn _get_expiration(&self) -> usize {
        panic!("NYI");
        /*
        let payload = self.jwt_token.split('.')[1];
        let expiration = JSON.parse(util.base64.decode(payload).toString('utf8'));
        return expiration.exp;
        */
  }
}

#[derive(Debug, Clone)]
pub struct CognitoAccessToken {
    jwt_token: String,
}

impl CognitoAccessToken {
    fn new(jwt_token: &str) -> CognitoAccessToken {
        CognitoAccessToken {
            jwt_token: jwt_token.to_string()
        }
    }
    pub fn get_jwt_token(&self) -> &str {
        &self.jwt_token
    }
    fn _get_expiration(&self) -> usize {
        panic!("NYI");
        /*
        let payload = self.jwt_token.split('.')[1];
        let expiration = JSON.parse(util.base64.decode(payload).toString('utf8'));
        return expiration.exp;
        */
  }
}

#[derive(Debug, Clone)]
pub struct CognitoRefreshToken {
    jwt_token: Option<String>,
}

impl CognitoRefreshToken {
    fn new(jwt_token: &Option<String>) -> CognitoRefreshToken {
        CognitoRefreshToken {
            jwt_token: jwt_token.to_owned()
        }
    }
    pub fn get_token(&self) -> Option<String> {
        self.jwt_token.to_owned()
    }
}

#[derive(Debug, Clone)]
pub struct CognitoUserSession {
    pub id_token: CognitoIdToken,
    pub access_token: CognitoAccessToken,
    pub refresh_token: CognitoRefreshToken,
}

impl CognitoUserSession {
    pub fn new(auth_result: &AuthenticationResult) -> CognitoUserSession {
        let id_token = CognitoIdToken::new(&auth_result.IdToken);
        let access_token = CognitoAccessToken::new(&auth_result.AccessToken);
        let refresh_token = CognitoRefreshToken::new(&auth_result.RefreshToken);
        CognitoUserSession { id_token, access_token, refresh_token }
    }
}

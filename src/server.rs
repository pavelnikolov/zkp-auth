use num_bigint::BigUint;
use rand::Rng;
use std::{collections::HashMap, env, sync::Mutex};
use tonic::{transport::Server, Code, Request, Response, Status};
use uuid::Uuid;
use ::zkp_auth::{gen_random_number_below, ZKP};

use zkp_auth::{
    auth_server::{Auth, AuthServer},
    AuthenticationAnswerRequest, AuthenticationAnswerResponse, AuthenticationChallengeRequest,
    AuthenticationChallengeResponse, RegisterRequest, RegisterResponse,
};

/// Import the generated proto file.
pub mod zkp_auth {
    tonic::include_proto!("zkp_auth");
}

/// AuthSvc implements the Auth trait from the zkp_auth proto file.
#[derive(Debug, Default)]
pub struct AuthSvc {
    // users is a map of user_id to (y1, y2)
    pub users: Mutex<HashMap<String, (BigUint, BigUint)>>,
    // challenges is a map of auth_id to (r1, r2, c)
    pub challenges: Mutex<HashMap<String, (BigUint, BigUint, BigUint)>>,
    // user_atuh maps auth_id to user_id
    pub user_atuh: Mutex<HashMap<String, String>>
}

/// random_string is used to generate a random string of a given size.
fn random_string(size: usize) -> String {
    rand::thread_rng()
        .sample_iter(rand::distributions::Alphanumeric)
        .take(size)
        .map(char::from)
        .collect()
}

/// Implement the Auth trait from the zkp_auth proto file for the AuthSvc struct.
#[tonic::async_trait]
impl Auth for AuthSvc {
    /// register is used to register a user with the server.
    async fn register(&self, request: Request<RegisterRequest>) -> Result<Response<RegisterResponse>, Status> {
        let RegisterRequest { user, y1, y2 } = request.into_inner();

        let y1 = BigUint::from_bytes_be(&y1);
        let y2 = BigUint::from_bytes_be(&y2);

        self.users.lock().unwrap().insert(user, (y1, y2));

        Ok(Response::new(RegisterResponse {}))
    }

    /// authentication_challenge is used to generate a challenge for a user to solve.
    async fn authentication_challenge(&self, request: Request<AuthenticationChallengeRequest>) -> Result<Response<AuthenticationChallengeResponse>, Status> {
        let AuthenticationChallengeRequest { user, r1, r2 } = request.into_inner();

        let users = self.users.lock().unwrap();
        if users.get(&user).is_some() {
            let (_, _, _, q) = ::zkp_auth::default_cfg();
            let c = gen_random_number_below(&q);
            let auth_id = Uuid::new_v4().to_string();

            let r1 = BigUint::from_bytes_be(&r1);
            let r2 = BigUint::from_bytes_be(&r2);

            self.challenges
                .lock()
                .unwrap()
                .insert(auth_id.clone(), (r1, r2, c.clone()));
            self.user_atuh
                .lock()
                .unwrap()
                .insert(auth_id.clone(), user);

            Ok(Response::new(AuthenticationChallengeResponse {auth_id, c: c.to_bytes_be()}))
        } else {
            Err(Status::new(Code::NotFound, format!("User: {} not found", user)))
        }
    }

    /// verify_authentication is used to verify the solution to a challenge and return a session_id.
    async fn verify_authentication(&self, request: Request<AuthenticationAnswerRequest>) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        let AuthenticationAnswerRequest { auth_id, s } = request.into_inner();

        let user_id = self
            .user_atuh
            .lock()
            .unwrap()
            .get(&auth_id)
            .ok_or_else(|| Status::new(Code::NotFound, format!("Auth ID: {} not found", auth_id)))?
            .clone();

        let users = self.users.lock().unwrap();
        let (y1, y2) = users.get(&user_id).ok_or_else(|| {
            Status::new(Code::NotFound, format!("User ID: {} not found", user_id))
        })?;

        let challenges = self.challenges.lock().unwrap();
        let (r1, r2, c) = challenges.get(&auth_id).ok_or_else(|| {
            Status::new(
                Code::NotFound,
                format!("Auth ID: {} not found in database", auth_id),
            )
        })?;

        let (g, h, p, q) = ::zkp_auth::default_cfg();
        let zkp = ZKP { g, h, p, q };
        let s = BigUint::from_bytes_be(&s);
        let verification = zkp.verify(r1, r2, y1, y2, c, &s);

        if verification {
            let session_id = random_string(32); // For simplicity, we generate a random string as session_id. Use JWT or similar in production.
            Ok(Response::new(AuthenticationAnswerResponse { session_id }))
        } else {
            Err(Status::new(Code::PermissionDenied, format!("Auth ID: {} wrong solution", auth_id)))
        }
    }
}

#[tokio::main]
async fn main() {
    let addr = env::var("LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:50051".to_string());

    println!("Listening for connections on {}", addr);

    let auth_svc = AuthSvc::default();

    Server::builder()
        .add_service(AuthServer::new(auth_svc))
        .serve(addr.parse().expect("invalid address"))
        .await
        .unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use num_bigint::BigUint;
    use tonic::Request;
    use self::zkp_auth::{RegisterRequest, AuthenticationChallengeRequest, AuthenticationAnswerRequest};

    fn setup_auth_svc() -> AuthSvc {
        AuthSvc {
            users: Mutex::new(HashMap::new()),
            challenges: Mutex::new(HashMap::new()),
            user_atuh: Mutex::new(HashMap::new()),
        }
    }

    #[tokio::test]
    async fn test_register() {
        let auth_svc = setup_auth_svc();

        let user = "test_user".to_string();
        let y1 = BigUint::from(123u32).to_bytes_be();
        let y2 = BigUint::from(456u32).to_bytes_be();

        let request = Request::new(RegisterRequest {
            user: user.clone(),
            y1: y1.clone(),
            y2: y2.clone(),
        });

        let response = auth_svc.register(request).await;

        assert!(response.is_ok());

        let users = auth_svc.users.lock().unwrap();
        let stored_user = users.get(&user);
        assert!(stored_user.is_some());
        let (stored_y1, stored_y2) = stored_user.unwrap();
        assert_eq!(&y1, &stored_y1.to_bytes_be());
        assert_eq!(&y2, &stored_y2.to_bytes_be());
    }

    #[tokio::test]
    async fn test_authentication_challenge() {
        let auth_svc = setup_auth_svc();

        let user = "test_user".to_string();
        let y1 = BigUint::from(123u32).to_bytes_be();
        let y2 = BigUint::from(456u32).to_bytes_be();
        let register_request = Request::new(RegisterRequest {
            user: user.clone(),
            y1: y1.clone(),
            y2: y2.clone(),
        });
        auth_svc.register(register_request).await.unwrap();

        let r1 = BigUint::from(789u32).to_bytes_be();
        let r2 = BigUint::from(101112u32).to_bytes_be();

        let challenge_request = Request::new(AuthenticationChallengeRequest {
            user: user.clone(),
            r1: r1.clone(),
            r2: r2.clone(),
        });

        let response = auth_svc.authentication_challenge(challenge_request).await;

        assert!(response.is_ok());
        let response = response.unwrap().into_inner();
        assert!(!response.auth_id.is_empty());
        assert!(!response.c.is_empty());

        let challenges = auth_svc.challenges.lock().unwrap();
        let stored_challenge = challenges.get(&response.auth_id);
        assert!(stored_challenge.is_some());
        let (stored_r1, stored_r2, stored_c) = stored_challenge.unwrap();
        assert_eq!(&r1, &stored_r1.to_bytes_be());
        assert_eq!(&r2, &stored_r2.to_bytes_be());
        assert_eq!(&BigUint::from_bytes_be(&response.c), stored_c);
    }

    #[tokio::test]
    async fn test_verify_authentication() {
        let auth_svc = setup_auth_svc();

        let (g, h, p, q) = ::zkp_auth::default_cfg();

        let user = "test_user".to_string();

        let x = gen_random_number_below(&BigUint::from(1_000_000u32));

        let y1 = g.modpow(&x, &p).to_bytes_be(); // g^x mod p
        let y2 = h.modpow(&x, &p).to_bytes_be(); // h^x mod p
        let register_request = Request::new(RegisterRequest {
            user: user.clone(),
            y1: y1.clone(),
            y2: y2.clone(),
        });
        auth_svc.register(register_request).await.unwrap();

        let k = gen_random_number_below(&BigUint::from(1_000_000u32));

        let r1 = g.modpow(&k, &p).to_bytes_be(); // g^k mod p
        let r2 = h.modpow(&k, &p).to_bytes_be(); // h^k mod p

        let challenge_request = Request::new(AuthenticationChallengeRequest {
            user: user,
            r1: r1.clone(),
            r2: r2.clone(),
        });
        let challenge_response = auth_svc.authentication_challenge(challenge_request).await.unwrap().into_inner();
        let auth_id = challenge_response.auth_id;
        let c = BigUint::from_bytes_be(&challenge_response.c);

        let zkp = ZKP { g, h, p, q };
        let s = zkp.solve(&k, &c, &x);

        let verify_request = Request::new(AuthenticationAnswerRequest {
            auth_id: auth_id.clone(),
            s: s.to_bytes_be(),
        });

        let response = auth_svc.verify_authentication(verify_request).await;

        assert!(response.is_ok());
        let response = response.unwrap().into_inner();
        assert!(!response.session_id.is_empty());

        let user_auth = auth_svc.user_atuh.lock().unwrap();
        assert!(user_auth.contains_key(&auth_id));
    }
}

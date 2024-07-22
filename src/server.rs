use num_bigint::BigInt;
use num_traits::ToPrimitive;
use rand::Rng;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tonic::{transport::Server, Request, Response, Status};
use zkp_auth::{RegisterRequest, RegisterResponse, AuthenticationChallengeRequest, AuthenticationChallengeResponse, AuthenticationAnswerRequest, AuthenticationAnswerResponse};
use zkp_auth::auth_server::{Auth, AuthServer};

pub mod zkp_auth {
    tonic::include_proto!("zkp_auth");
}

#[derive(Debug, Default)]
pub struct MyAuth {
    users: Arc<Mutex<HashMap<String, (BigInt, BigInt)>>>,
    challenges: Arc<Mutex<HashMap<String, (BigInt, BigInt)>>>,
}

impl MyAuth {
    fn new() -> Self {
        MyAuth {
            users: Arc::new(Mutex::new(HashMap::new())),
            challenges: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[tonic::async_trait]
impl Auth for MyAuth {
    async fn register(&self, request: Request<RegisterRequest>) -> Result<Response<RegisterResponse>, Status> {
        let req = request.into_inner();
        let y1 = BigInt::from(req.y1);
        let y2 = BigInt::from(req.y2);

        {
            let mut users = self.users.lock().unwrap();
            users.insert(req.user, (y1, y2));
        }

        Ok(Response::new(RegisterResponse {}))
    }

    async fn create_authentication_challenge(&self, request: Request<AuthenticationChallengeRequest>) -> Result<Response<AuthenticationChallengeResponse>, Status> {
        let req = request.into_inner();
        let r1 = BigInt::from(req.r1);
        let _r2 = BigInt::from(req.r2);

        // Generate a random challenge
        let mut rng = rand::thread_rng();
        let c = BigInt::from(rng.gen_range(1..256));

        {
            let mut challenges = self.challenges.lock().unwrap();
            challenges.insert(req.user.clone(), (c.clone(), r1));
        }

        Ok(Response::new(AuthenticationChallengeResponse {
            auth_id: req.user,
            c: c.to_i64().unwrap(), // Convert BigInt to byte vector
        }))
    }

    async fn verify_authentication(&self, request: Request<AuthenticationAnswerRequest>) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        let req = request.into_inner();
        let s = BigInt::from(req.s);

        let (c, r1);
        {
            let challenges = self.challenges.lock().unwrap();
            if let Some(challenge) = challenges.get(&req.auth_id) {
                c = challenge.0.clone();
                r1 = challenge.1.clone();
            } else {
                return Err(Status::unauthenticated("Invalid auth_id"));
            }
        }

        let (y1, y2);
        {
            let users = self.users.lock().unwrap();
            if let Some(user_data) = users.get(&req.auth_id) {
                y1 = user_data.0.clone();
                y2 = user_data.1.clone();
            } else {
                return Err(Status::unauthenticated("Invalid user"));
            }
        }

        // Verification logic
        let p = BigInt::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16).unwrap();
        let g = BigInt::from(2);
        let h = BigInt::from(3);

        // Calculate g^s and h^s
        let gs = g.modpow(&s, &p);
        let hs = h.modpow(&s, &p);

        // Calculate g^r * y1^c and h^r * y2^c
        let gr_y1c = (g.modpow(&r1, &p) * y1.modpow(&c, &p)) % &p;
        let hr_y2c = (h.modpow(&r1, &p) * y2.modpow(&c, &p)) % &p;

        let valid = gs == gr_y1c && hs == hr_y2c;

        if valid {
            return Ok(Response::new(AuthenticationAnswerResponse {
                session_id: "session_12345".to_string(),
            }));
        }
        Err(Status::unauthenticated("Invalid proof"))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let auth = MyAuth::new();

    Server::builder()
        .add_service(AuthServer::new(auth))
        .serve(addr)
        .await?;

    Ok(())
}

use num_bigint::BigInt;
use num_traits::{One, ToPrimitive};
use rand::Rng;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::MutexGuard;
use tonic::{transport::Server, Request, Response, Status};
use zkp_auth::{RegisterRequest, RegisterResponse, AuthenticationChallengeRequest, AuthenticationChallengeResponse, AuthenticationAnswerRequest, AuthenticationAnswerResponse};
use zkp_auth::auth_server::{Auth, AuthServer};

mod zkp_auth {
    tonic::include_proto!("zkp_auth");
}

#[derive(Default)]
pub struct AuthSvc {
    users: Arc<Mutex<HashMap<String, (BigInt, BigInt)>>>,
    challenges: Arc<Mutex<HashMap<String, (BigInt, BigInt, BigInt)>>>,
}

#[tonic::async_trait]
impl Auth for AuthSvc {
    async fn register(&self, request: Request<RegisterRequest>) -> Result<Response<RegisterResponse>, Status> {
        let req = request.into_inner();
        let y1 = BigInt::from(req.y1);
        let y2 = BigInt::from(req.y2);

        let mut users = self.users.lock().unwrap();
        users.insert(req.user, (y1, y2));

        Ok(Response::new(RegisterResponse {}))
    }

    async fn create_authentication_challenge(&self, request: Request<AuthenticationChallengeRequest>) -> Result<Response<AuthenticationChallengeResponse>, Status> {
        let req = request.into_inner();
        let user = req.user.clone();

        let n = rand::thread_rng().gen_range(0..128);
        let c: BigInt = BigInt::from(n);

        let mut challenges = self.challenges.lock().unwrap();
        challenges.insert(user.clone(), (c.clone(), req.r1.into(), req.r2.into()));

        Ok(Response::new(AuthenticationChallengeResponse {
            auth_id: user,
            c: c.to_i64().unwrap(), // Simplification, in real application handle BigInt properly
        }))
    }

    async fn verify_authentication(&self, request: Request<AuthenticationAnswerRequest>) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        let req = request.into_inner();
        let auth_id = req.auth_id;

        let challenges: MutexGuard<HashMap<String, (BigInt, BigInt, BigInt)>> = self.challenges.lock().unwrap();
        if let Some((c, r1, r2)) = challenges.get(&auth_id) {
            let s: BigInt = req.s.into();

            let users = self.users.lock().unwrap();
            if let Some((y1, y2)) = users.get(&auth_id) {
                let g: BigInt = BigInt::one(); // Simplification, should be a proper generator
                let h: BigInt = BigInt::one(); // Simplification, should be a proper generator

                let left1 = &g * &s;
                let right1 = r1 + &(y1 * c);
                let left2 = &h * &s;
                let right2 = r2 + &(y2 * c);

                if left1 == right1 && left2 == right2 {
                    return Ok(Response::new(AuthenticationAnswerResponse {
                        session_id: "authenticated".to_string(),
                    }));
                }
            }
        }

        Err(Status::unauthenticated("Authentication failed"))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse().unwrap();
    let auth_svc = AuthSvc::default();

    println!("Server listening on {}", addr);

    Server::builder()
        .add_service(AuthServer::new(auth_svc))
        .serve(addr)
        .await?;

    Ok(())
}

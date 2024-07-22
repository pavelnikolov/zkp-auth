use num_bigint::BigInt;
use num_traits::{One, ToPrimitive};
use rand::Rng;
use tonic::{Response, Request,transport::Channel};

use zkp_auth::{RegisterRequest, AuthenticationChallengeRequest, AuthenticationAnswerRequest, AuthenticationAnswerResponse};
use zkp_auth::auth_client::AuthClient;

mod zkp_auth {
    tonic::include_proto!("zkp_auth");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client: AuthClient<Channel> = AuthClient::connect("http://[::1]:50051").await?;

    let mut rng = rand::thread_rng();
    // Registration
    let n = rng.gen_range(0..128);
    let x: BigInt = BigInt::from(n);
    let g: BigInt = BigInt::one(); // Simplification, should be a proper generator
    let h: BigInt = BigInt::one(); // Simplification, should be a proper generator

    let y1 = &g * &x;
    let y2 = &h * &x;

    let request = tonic::Request::new(RegisterRequest {
        user: "user1".to_string(),
        y1: y1.to_i64().unwrap(), // Simplification, in real application handle BigInt properly
        y2: y2.to_i64().unwrap(), // Simplification, in real application handle BigInt properly
    });

    let response: Response<zkp_auth::RegisterResponse> = client.register(request).await?;
    println!("RESPONSE={:?}", response);

    // Authentication Challenge
    let n = rng.gen_range(0..128);
    let r: BigInt = BigInt::from(n);
    let r1 = &g * &r;
    let r2 = &h * &r;

    let request: Request<AuthenticationChallengeRequest> = Request::new(AuthenticationChallengeRequest {
        user: "user1".to_string(),
        r1: r1.to_i64().unwrap(), // Simplification, in real application handle BigInt properly
        r2: r2.to_i64().unwrap(), // Simplification, in real application handle BigInt properly
    });

    let response = client.create_authentication_challenge(request).await?;
    let challenge_res = response.into_inner();
    let auth_id = challenge_res.auth_id;
    let c = challenge_res.c;

    // Authentication Answer
    let s = &r + &(BigInt::from(c) * &x);

    let request = Request::new(AuthenticationAnswerRequest {
        auth_id: auth_id,
        s: s.to_i64().unwrap(), // Simplification, in real application handle BigInt properly
    });

    let response: Response<AuthenticationAnswerResponse> = client.verify_authentication(request).await?;
    println!("RESPONSE={:?}", response);

    Ok(())
}

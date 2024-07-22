use zkp_auth::auth_client::AuthClient;
use zkp_auth::{RegisterRequest, AuthenticationChallengeRequest, AuthenticationAnswerRequest};
use num_bigint::BigInt;
use rand::{thread_rng, Rng};
use num_traits::ToPrimitive;

pub mod zkp_auth {
    tonic::include_proto!("zkp_auth");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = AuthClient::connect("http://[::1]:50051").await?;

    // Registration
    let mut rng = thread_rng();
    let x = BigInt::from(rng.gen_range(1..256)); // Secret password
    let p = BigInt::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16).unwrap();
    let g = BigInt::from(2);
    let h = BigInt::from(3);

    let y1 = g.modpow(&x, &p);
    let y2 = h.modpow(&x, &p);

    let register_request = tonic::Request::new(RegisterRequest {
        user: "user1".into(),
        y1: y1.to_i64().unwrap(), // assume that the number is small enough to fit in i64
        y2: y2.to_i64().unwrap(), // assume that the number is small enough to fit in i64
    });

    client.register(register_request).await?;

    // Authentication
    let mut rng = thread_rng();
    let r1 = BigInt::from(rng.gen_range(1..256));
    let r2 = BigInt::from(rng.gen_range(1..256));

    let challenge_request = tonic::Request::new(AuthenticationChallengeRequest {
        user: "user1".into(),
        r1: r1.to_i64().unwrap(), // assume that the number is small enough to fit in i64
        r2: r2.to_i64().unwrap(), // assume that the number is small enough to fit in i64
    });

    let response = client.create_authentication_challenge(challenge_request).await?;
    let auth_id = response.get_ref().auth_id.clone();
    let c = BigInt::from(response.get_ref().c);

    // Prover calculates s = r1 + c * x
    let s = &r1 + &c * &x;

    let answer_request = tonic::Request::new(AuthenticationAnswerRequest {
        auth_id,
        s: s.to_i64().unwrap(), // assume that the number is small enough to fit in i64
    });

    let response = client.verify_authentication(answer_request).await?;

    println!("Session ID: {}", response.get_ref().session_id);

    Ok(())
}

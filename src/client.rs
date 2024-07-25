use num_bigint::BigUint;
use std::env;
use zkp_auth::{auth_client::AuthClient, RegisterRequest, AuthenticationAnswerRequest, AuthenticationChallengeRequest};
use ::zkp_auth::{gen_random_number_below, ZKP};

pub mod zkp_auth {
    tonic::include_proto!("zkp_auth");
}

#[tokio::main]
async fn main() {
    let (g, h, p, q) = ::zkp_auth::default_cfg();
    let zkp = ZKP { g: g.clone(), h: h.clone(), p: p.clone(), q: q.clone() };

    let addr = env::var("SERVER_ADDR").unwrap_or_else(|_| "http://127.0.0.1:50051".to_string());

    let mut client = AuthClient::connect(addr).await.expect("Failed to connect to the server");

    let user_id: String = "Pavel".to_string();
    let secret = BigUint::from(123456u32); // Hard-coded for simplicity, could use a random number too

    let y1 = g.modpow(&secret, &p); // g^secret mod p
    let y2 = h.modpow(&secret, &p);  // h^secret mod p

    let register_request = RegisterRequest {
        user: user_id.clone(),
        y1: y1.to_bytes_be(),
        y2: y2.to_bytes_be(),
    };

    client.register(register_request).await.expect("Failed to register user");
    println!("Registration successful.");

    let k = gen_random_number_below(&BigUint::from(1_000_000u32));
    let r1 = g.modpow(&k, &p);
    let r2 = h.modpow(&k, &p);

    let challenge_request = AuthenticationChallengeRequest {
        user: user_id.clone(),
        r1: r1.to_bytes_be(),
        r2: r2.to_bytes_be(),
    };

    let res = client.authentication_challenge(challenge_request).await.expect("Could not request challenge from server").into_inner();
    println!("Received challenge from server.");

    let s = zkp.solve(&k, &BigUint::from_bytes_be(&res.c), &secret);

    let answer_request = AuthenticationAnswerRequest {
        auth_id: res.auth_id,
        s: s.to_bytes_be(),
    };

    let res = client.verify_authentication(answer_request).await.expect("Could not verify authentication on server").into_inner();

    println!("Successfully logged in! Session ID: {}", res.session_id);
}

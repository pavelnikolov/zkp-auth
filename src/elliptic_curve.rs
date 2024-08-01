use k256::elliptic_curve::{sec1::ToEncodedPoint, Field};
use k256::{ProjectivePoint, Scalar};
use rand::rngs::OsRng;

fn main() {
    // Generate a random private key for the prover
    let mut rng = OsRng;
    let sk = Scalar::random(&mut rng);
    let pk = ProjectivePoint::GENERATOR * sk;

    // Prover generates a random nonce
    let nonce = Scalar::random(&mut rng);
    let r = ProjectivePoint::GENERATOR * nonce;

    // Prover sends the commitment (r) to the verifier
    println!("Prover sends r: {:?}", r.to_encoded_point(false));

    // Verifier generates a random challenge
    let challenge = Scalar::random(&mut rng);
    println!("Verifier sends challenge: {:?}", challenge);

    // Prover computes the response
    let response = nonce + challenge * sk;
    println!("Prover sends response: {:?}", response);

    // Verifier computes r' = response * G - challenge * pk
    let computed_r = ProjectivePoint::GENERATOR * response - pk * challenge;
    println!("Verifier computes r': {:?}", computed_r.to_encoded_point(false));

    // Verifier checks if r' == r
    let valid = computed_r.to_affine().eq(&r.to_affine());
    println!("Verification result: {:?}", valid);
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_zkp_authentication() {
        // Generate a random private key for the prover
        let mut rng = OsRng;
        let sk = Scalar::random(&mut rng);
        let pk = ProjectivePoint::GENERATOR * sk;

        // Prover generates a random nonce
        let nonce = Scalar::random(&mut rng);
        let r = ProjectivePoint::GENERATOR * nonce;

        // Verifier generates a random challenge
        let challenge = Scalar::random(&mut rng);

        // Prover computes the response
        let response = nonce + challenge * sk;

        // Verifier computes r' = response * G - challenge * pk
        let computed_r = ProjectivePoint::GENERATOR * response - pk * challenge;

        // Verifier checks if r' == r
        let valid = computed_r.to_affine().eq(&r.to_affine());

        // Assert that the verification is successful
        assert!(valid);
    }

    #[test]
    fn test_invalid_proof() {
        // Generate a random private key for the prover
        let mut rng = OsRng;
        let sk = Scalar::random(&mut rng);
        let pk = ProjectivePoint::GENERATOR * sk;

        // Prover generates a random nonce
        let nonce = Scalar::random(&mut rng);
        let r = ProjectivePoint::GENERATOR * nonce;

        // Verifier generates a random challenge
        let challenge = Scalar::random(&mut rng);

        // Prover computes an incorrect response
        let response = nonce + challenge * (sk + Scalar::ONE); // Intentionally incorrect

        // Verifier computes r' = response * G - challenge * pk
        let computed_r = ProjectivePoint::GENERATOR * response - pk * challenge;

        // Verifier checks if r' == r
        let valid = computed_r.to_affine().eq(&r.to_affine());

        // Assert that the verification fails
        assert!(!valid);
    }
}

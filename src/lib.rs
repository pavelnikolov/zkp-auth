use num_bigint::{BigUint, RandBigInt};

// P is a big prime number forming a cyclic modulus group, data taken from https://www.rfc-editor.org/rfc/rfc5114#page-15 
const P: &[u8] = b"B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371";
// Q us the prime order of the above group
const Q: &[u8] = b"F518AA8781A8DF278ABA4E7D64B7CB9D49462353";
// G is a generator of the group
const G: &[u8] = b"A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5";

/// Returns the default configuration for the ZKP protocol.
pub fn default_cfg() -> (BigUint, BigUint, BigUint, BigUint) {
    let p = BigUint::from_bytes_be(hex::decode(P).unwrap().as_slice());
    let q = BigUint::from_bytes_be(hex::decode(Q).unwrap().as_slice());
    let g = BigUint::from_bytes_be(hex::decode(G).unwrap().as_slice());
    let exp = BigUint::from(85u32); // randomly chosen, any number would work
    let h = g.modpow(&exp, &p); // h = g^exp mod p is also a generator of the group because the group is cyclic and of prime order

    (g, h, p, q)
}

/// Returns a random number below the given bound.
pub fn gen_random_number_below(bound: &BigUint) -> BigUint {
    let mut rng = rand::thread_rng();
    rng.gen_biguint_below(bound)
}

/// Zero Knowledge Proof (ZKP) struct implementing the Chaum-Pedersen protocol using a cyclic group of prime order and discrete logarithm problem.
pub struct ZKP {
    pub g: BigUint, // generator of the group
    pub h: BigUint, // generator of the group
    pub p: BigUint, // (big) prime number used as modulus
    pub q: BigUint  // prime order of the group
}

impl ZKP {
    /// solve is used by a prover to solve the discrete logarithm problem using the Chaum-Pedersen protocol.
    pub fn solve(&self, k: &BigUint, c: &BigUint, x: &BigUint) -> BigUint {   // s = k-cx mod q
        if *k >= c * x {
            return (k - c * x).modpow(&BigUint::from(1u32), &self.q);
        }
        (&self.q - (c * x - k).modpow(&BigUint::from(1u32), &self.q)).modpow(&BigUint::from(1u32), &self.q)
    }

    /// verify is used by a verifier to check if the given solution s is correct according to the Chaum-Pedersen protocol.
    pub fn verify(&self, r1: &BigUint, r2: &BigUint, y1: &BigUint, y2: &BigUint, c: &BigUint, s: &BigUint) -> bool {
        let cond1 = *r1 == (&self.g.modpow(s, &self.p) * y1.modpow(c, &self.p)).modpow(&BigUint::from(1u32), &self.p);
        let cond2 = *r2 == (&self.h.modpow(s, &self.p) * y2.modpow(c, &self.p)).modpow(&BigUint::from(1u32), &self.p);
        cond1 && cond2
    }
}

#[cfg(test)]

mod test {
    use super::*;

    #[test]
    fn test_simple_example() {
        // data taken from https://crypto.stackexchange.com/questions/99262/chaum-pedersen-protocol 
        let g = BigUint::from(4u32);
        let h = BigUint::from(9u32);
        let p = BigUint::from(23u32);
        let q = BigUint::from(11u32);
        let zkp = ZKP { g: g.clone(), h: h.clone(), p: p.clone(), q: q.clone() };

        let x = BigUint::from(6u32);
        let k = BigUint::from(7u32);
        
        let c = BigUint::from(4u32);

        let y1 = g.modpow(&x, &p); // g^x mod p
        let y2 = h.modpow(&x, &p); // h^x mod p

        assert_eq!(y1, BigUint::from(2u32));
        assert_eq!(y2, BigUint::from(3u32));

        let r1 = g.modpow(&k, &p); // g^k mod p
        let r2 = h.modpow(&k, &p); // h^k mod p

        assert_eq!(r1, BigUint::from(8u32));
        assert_eq!(r2, BigUint::from(4u32));

        let s = zkp.solve(&k, &c, &x); // s = k-cx mod q
        assert_eq!(s, BigUint::from(5u32));

        let result = zkp.verify(&r1, &r2, &y1, &y2, &c, &s); 
        assert!(result);

        // wrong secret
        let wrong_x = BigUint::from(15u32);
        let wrong_s = zkp.solve(&k, &c, &wrong_x);

        let result_wrong = zkp.verify(&r1, &r2, &y1, &y2, &c, &wrong_s);
        assert!(!result_wrong);
    }

    #[test]
    fn test_2048_bits_prime() {
        // the group was copied from https://www.rfc-editor.org/rfc/rfc5114#page-16
        let p = hex::decode("AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1B54B1597B61D0A75E6FA141DF95A56DBAF9A3C407BA1DF15EB3D688A309C180E1DE6B85A1274A0A66D3F8152AD6AC2129037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708B3BF8A317091883681286130BC8985DB1602E714415D9330278273C7DE31EFDC7310F7121FD5A07415987D9ADC0A486DCDF93ACC44328387315D75E198C641A480CD86A1B9E587E8BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763C9B53DCF4BA80A29E3FB73C16B8E75B97EF363E2FFA31F71CF9DE5384E71B81C0AC4DFFE0C10E64F").unwrap();
        let p = BigUint::from_bytes_be(&p);
        let q = hex::decode("801C0D34C58D93FE997177101F80535A4738CEBCBF389A99B36371EB").unwrap();
        let q = BigUint::from_bytes_be(&q);
        let g = hex::decode("AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF74866A08CFE4FFE3A6824A4E10B9A6F0DD921F01A70C4AFAAB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7C17669101999024AF4D027275AC1348BB8A762D0521BC98AE247150422EA1ED409939D54DA7460CDB5F6C6B250717CBEF180EB34118E98D119529A45D6F834566E3025E316A330EFBB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC017981BC087F2A7065B384B890D3191F2BFA").unwrap();
        let g = BigUint::from_bytes_be(&g);

        let h = g.modpow(&gen_random_number_below(&q), &p);
        
        let zkp = ZKP { g: g.clone(), h: h.clone(), p: p.clone(), q: q.clone() };

        let x = gen_random_number_below(&q);
        let k = gen_random_number_below(&q);
        
        let c = gen_random_number_below(&q);

        let y1 = g.modpow(&x, &p);
        let y2 = h.modpow(&x, &p);

        let r1 = g.modpow(&k, &p);
        let r2 = h.modpow(&k, &p);

        let s = zkp.solve(&k, &c, &x);
        assert!(s < q);

        let result = zkp.verify(&r1, &r2, &y1, &y2, &c, &s);
        assert!(result);

        // wrong secret
        let wrong_x = (x + BigUint::from(1u32)) %p;
        let wrong_s = zkp.solve(&k, &c, &wrong_x);
        let wrong_result = zkp.verify(&r1, &r2, &y1, &y2, &c, &wrong_s);
        assert!(!wrong_result);
    }
}


#![allow(non_snake_case)]
use std::convert::TryFrom;
use std::ops::Neg;

#[allow(unused_doc_comments)]
/*
    Multisig Schnorr

    Copyright 2018 by Kzen Networks

    This file is part of Multisig Schnorr library
    (https://github.com/KZen-networks/multisig-schnorr)

    Multisig Schnorr is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/multisig-schnorr/blob/master/LICENSE>
*/
/// following the variant used in bip-schnorr: https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki
use Error::{self, InvalidKey, InvalidSS, InvalidSig};

use curv::arithmetic::traits::*;

use curv::elliptic::curves::secp256_k1::{Secp256k1Scalar, PK};
use curv::elliptic::curves::traits::*;

use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::BigInt;

type GE = curv::elliptic::curves::secp256_k1::GE;
type FE = curv::elliptic::curves::secp256_k1::FE;

const SECURITY: usize = 256;

pub struct Keys {
    pub u_i: FE,
    pub y_i: GE,
    pub party_index: usize,
}

pub struct KeyGenBroadcastMessage1 {
    com: BigInt,
}

#[derive(Debug)]
pub struct Parameters {
    pub threshold: usize,   //t
    pub share_count: usize, //n
}
#[derive(Clone, Serialize, Deserialize)]
pub struct SharedKeys {
    pub y: GE,
    pub x_i: FE,
}

impl Keys {
    pub fn phase1_create(index: usize) -> Keys {
        let u: FE = ECScalar::new_random();
        let y = &ECPoint::generator() * &u;

        Keys {
            u_i: u,
            y_i: y,
            party_index: index.clone(),
        }
    }

    pub fn phase1_broadcast(&self) -> (KeyGenBroadcastMessage1, BigInt) {
        let blind_factor = BigInt::sample(SECURITY);
        let com = HashCommitment::create_commitment_with_user_defined_randomness(
            &self.y_i.bytes_compressed_to_big_int(),
            &blind_factor,
        );
        let bcm1 = KeyGenBroadcastMessage1 { com };
        (bcm1, blind_factor)
    }

    pub fn phase1_verify_com_phase2_distribute(
        &self,
        params: &Parameters,
        blind_vec: &Vec<BigInt>,
        y_vec: &Vec<GE>,
        bc1_vec: &Vec<KeyGenBroadcastMessage1>,
        parties: &[usize],
    ) -> Result<(VerifiableSS<GE>, Vec<FE>, usize), Error> {
        // test length:
        assert_eq!(blind_vec.len(), params.share_count);
        assert_eq!(bc1_vec.len(), params.share_count);
        assert_eq!(y_vec.len(), params.share_count);
        // test decommitments
        let correct_key_correct_decom_all = (0..bc1_vec.len())
            .map(|i| {
                HashCommitment::create_commitment_with_user_defined_randomness(
                    &y_vec[i].bytes_compressed_to_big_int(),
                    &blind_vec[i],
                ) == bc1_vec[i].com
            })
            .all(|x| x == true);
        /*
        let (vss_scheme, secret_shares) = VerifiableSS::share_at_indices(
            params.threshold,
            params.share_count,
            &self.u_i,
            parties,
        );
        */
        let (vss_scheme, secret_shares) = VerifiableSS::share_at_indices(
            params.threshold,
            params.share_count,
            &self.u_i,
            &parties,
        );

        match correct_key_correct_decom_all {
            true => Ok((vss_scheme, secret_shares, self.party_index.clone())),
            false => Err(InvalidKey),
        }
    }

    pub fn phase2_verify_vss_construct_keypair(
        &self,
        params: &Parameters,
        y_vec: &Vec<GE>,
        secret_shares_vec: &Vec<FE>,
        vss_scheme_vec: &Vec<VerifiableSS<GE>>,
        index: &usize,
    ) -> Result<SharedKeys, Error> {
        assert_eq!(y_vec.len(), params.share_count);
        assert_eq!(secret_shares_vec.len(), params.share_count);
        assert_eq!(vss_scheme_vec.len(), params.share_count);

        let correct_ss_verify = (0..y_vec.len())
            .map(|i| {
                vss_scheme_vec[i]
                    .validate_share(&secret_shares_vec[i], *index)
                    .is_ok()
                    && vss_scheme_vec[i].commitments[0] == y_vec[i]
            })
            .all(|x| x == true);

        match correct_ss_verify {
            true => {
                let mut y_vec_iter = y_vec.iter();
                let y0 = y_vec_iter.next().unwrap();
                let y = y_vec_iter.fold(y0.clone(), |acc, x| acc + x);
                let x_i = secret_shares_vec.iter().fold(FE::zero(), |acc, x| acc + x);
                Ok(SharedKeys { y, x_i })
            }
            false => Err(InvalidSS),
        }
    }

    // remove secret shares from x_i for parties that are not participating in signing
    pub fn update_shared_key(
        shared_key: &SharedKeys,
        parties_in: &[usize],
        secret_shares_vec: &Vec<FE>,
    ) -> SharedKeys {
        let mut new_xi: FE = FE::zero();
        for i in 0..secret_shares_vec.len() {
            if parties_in.iter().find(|&&x| x == i).is_some() {
                new_xi = new_xi + &secret_shares_vec[i]
            }
        }
        SharedKeys {
            y: shared_key.y.clone(),
            x_i: new_xi,
        }
    }
}

pub struct LocalSig {
    gamma_i: FE,
    e: FE,
}

impl LocalSig {
    pub fn compute(
        message: &[u8],
        local_ephemeral_key: &SharedKeys,
        local_private_key: &SharedKeys,
    ) -> LocalSig {
        let beta_i = local_ephemeral_key.x_i.clone();
        let alpha_i = local_private_key.x_i.clone();

        let message_len_bits = message.len() * 8;
        let R = local_ephemeral_key.y.bytes_compressed_to_big_int();
        let X = local_private_key.y.bytes_compressed_to_big_int();
        let X_vec = BigInt::to_bytes(&X);
        let X_vec_len_bits = X_vec.len() * 8;
        let e_bn = HSha256::create_hash_from_slice(
            &BigInt::to_bytes(
                &((((R << X_vec_len_bits) + X) << message_len_bits) + BigInt::from_bytes(message)),
            )[..],
        );

        let e: FE = ECScalar::from(&e_bn);
        let gamma_i = beta_i + e.clone() * alpha_i;

        LocalSig { gamma_i, e }
    }

    // section 4.2 step 3
    #[allow(unused_doc_comments)]
    pub fn verify_local_sigs(
        gamma_vec: &Vec<LocalSig>,
        parties_index_vec: &[usize],
        vss_private_keys: &Vec<VerifiableSS<GE>>,
        vss_ephemeral_keys: &Vec<VerifiableSS<GE>>,
    ) -> Result<VerifiableSS<GE>, Error> {
        //parties_index_vec is a vector with indices of the parties that are participating and provided gamma_i for this step
        // test that enough parties are in this round
        assert!(parties_index_vec.len() > vss_private_keys[0].parameters.threshold);

        // Vec of joint commitments:
        // n' = num of signers, n - num of parties in keygen
        // [com0_eph_0,... ,com0_eph_n', e*com0_kg_0, ..., e*com0_kg_n ;
        // ...  ;
        // comt_eph_0,... ,comt_eph_n', e*comt_kg_0, ..., e*comt_kg_n ]
        let comm_vec = (0..vss_private_keys[0].parameters.threshold + 1)
            .map(|i| {
                let mut key_gen_comm_i_vec = (0..vss_private_keys.len())
                    .map(|j| vss_private_keys[j].commitments[i].clone() * &gamma_vec[i].e)
                    .collect::<Vec<GE>>();
                let mut eph_comm_i_vec = (0..vss_ephemeral_keys.len())
                    .map(|j| vss_ephemeral_keys[j].commitments[i].clone())
                    .collect::<Vec<GE>>();
                key_gen_comm_i_vec.append(&mut eph_comm_i_vec);
                let mut comm_i_vec_iter = key_gen_comm_i_vec.iter();
                let comm_i_0 = comm_i_vec_iter.next().unwrap();
                comm_i_vec_iter.fold(comm_i_0.clone(), |acc, x| acc + x)
            })
            .collect::<Vec<GE>>();

        let vss_sum = VerifiableSS {
            parameters: vss_ephemeral_keys[0].parameters.clone(),
            commitments: comm_vec,
        };

        let g: GE = GE::generator();
        let correct_ss_verify = (0..parties_index_vec.len())
            .map(|i| {
                let gamma_i_g = &g * &gamma_vec[i].gamma_i;
                vss_sum
                    .validate_share_public(&gamma_i_g, parties_index_vec[i] + 1)
                    .is_ok()
            })
            .collect::<Vec<bool>>();

        match correct_ss_verify.iter().all(|x| x.clone() == true) {
            true => Ok(vss_sum),
            false => Err(InvalidSS),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Signature {
    pub sigma: FE,
    pub v: GE,
}

impl Signature {
    pub fn generate(
        vss_sum_local_sigs: &VerifiableSS<GE>,
        local_sig_vec: &Vec<LocalSig>,
        parties_index_vec: &[usize],
        v: GE,
    ) -> Signature {
        let gamma_vec = (0..parties_index_vec.len())
            .map(|i| local_sig_vec[i].gamma_i.clone())
            .collect::<Vec<FE>>();
        let reconstruct_limit = vss_sum_local_sigs.parameters.threshold.clone() + 1;
        let sigma = vss_sum_local_sigs.reconstruct(
            &parties_index_vec[0..reconstruct_limit.clone()],
            &gamma_vec[0..reconstruct_limit.clone()],
        );
        Signature { sigma, v }
    }

    pub fn verify(&self, message: &[u8], pubkey_y: &GE) -> Result<(), Error> {
        let v = self.v.bytes_compressed_to_big_int().to_bytes();
        let y = pubkey_y.bytes_compressed_to_big_int().to_bytes();
        println!("v_len: {}, y_len: {}, v: {:?}, y: {:?}",v.len(), y.len(), v, y);
        let e_bn = HSha256::create_hash(&[
            &self.v.bytes_compressed_to_big_int(),
            &pubkey_y.bytes_compressed_to_big_int(),
            &BigInt::from_bytes(message),
        ]);
        let e: FE = ECScalar::from(&e_bn);
        let e_y = pubkey_y * &e;
        let e_y_plus_v = e_y + &self.v;

        let g: GE = GE::generator();
        let sigma_g = g * &self.sigma;

        // R + H(R,X,m) * X = s * G
        if e_y_plus_v == sigma_g {
            Ok(())
        } else {
            Err(InvalidSig)
        }
    }

    pub fn hash_message(&self, message: &[u8], pubkey_y: &GE) -> Result<BigInt, Error> {
        let v = self.v.bytes_compressed_to_big_int().to_bytes();
        let y = pubkey_y.bytes_compressed_to_big_int().to_bytes();
        println!("v_len: {}, y_len: {}, v: {:?}, y: {:?}",v.len(), y.len(), v, y);
        let e_bn = HSha256::create_hash(&[
            &self.v.bytes_compressed_to_big_int(),
            &pubkey_y.bytes_compressed_to_big_int(),
            &BigInt::from_bytes(message),
        ]);
        Ok(e_bn)
    }
}

#[derive(Clone, Serialize, Deserialize, )]
pub struct SigEx {
    pub signature: Signature,
}

impl From<Signature> for SigEx {
    fn from(value: Signature) -> Self {
        SigEx { signature: value }
    }
}

impl SigEx {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = [0u8; 65];
        let s = self.signature.sigma.to_big_int().to_bytes();
        let v = self.signature.v.bytes_compressed_to_big_int().to_bytes();
        bytes[..32].copy_from_slice(&s);
        bytes[32..].copy_from_slice(&v);
        bytes.to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 65 {
            return Err("invalid signature length".into());
        }
        let bigint = BigInt::from_bytes(&bytes[..32]);
        let sigma: FE = ECScalar::from(&bigint);
        let pk = PK::from_slice(&bytes[32..]).unwrap().serialize_uncompressed();
        let x = BigInt::from_bytes(&pk[1..33]);
        let y = BigInt::from_bytes(&pk[33..]);
        let v = GE::from_coor(&x, &y);
        let signature = Signature { sigma, v };
        Ok(SigEx { signature })
    }
}

use libsecp256k1::curve::{Scalar, Affine, Jacobian, Field};
use libsecp256k1::{PublicKey as ECPK, SecretKey as ECSK, Signature as ECSig, PublicKeyFormat, Error as ECError};
use libsecp256k1::{ECMULT_GEN_CONTEXT,ECMULT_CONTEXT};
use sha2::{Sha256, Digest};

// H(R, X, m)
fn hash(R: &[u8], X: &[u8], m: &[u8]) -> Scalar {
    let mut hasher = Sha256::new();

    hasher.update(R);
    hasher.update(X);
    hasher.update(m);

    let result_hex = hasher.finalize();
    
    let mut bin = [0u8; 32];
    bin.copy_from_slice(&result_hex[..]);
    let mut h = Scalar::default();
    h.set_b32(&bin);
    h
}

// SHA256 (SHA256("BIP0340/challenge")||SHA256("BIP0340/challenge")||R.x||P.x||M)
fn sha256_tagged(r_x: &[u8], p_x: &[u8], m: &[u8]) -> Scalar {
    // SHA256("BIP0340/challenge")
    const CHALLENGE_PREFIX: [u8; 32] = [123u8, 181, 45, 122, 159, 239, 88, 50, 62, 177, 191, 122, 64, 125, 179, 130, 210, 243, 242, 216, 27, 177, 34, 79, 73, 254, 81, 143, 109, 72, 211, 124];

    let mut hasher = Sha256::new();

    // add prefix
    hasher.update(CHALLENGE_PREFIX);
    hasher.update(CHALLENGE_PREFIX);

    hasher.update(r_x);
    hasher.update(p_x);
    hasher.update(m);

    let result_hex = hasher.finalize();
    
    let mut bin = [0u8; 32];
    bin.copy_from_slice(&result_hex[..]);
    let mut h = Scalar::default();
    h.set_b32(&bin);
    h
}

// https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv


pub fn load_xonly_pubkey(pubkey: &[u8]) -> Result<ECPK, ECError> {
    if pubkey.len() != 32 {
        return Err(ECError::InvalidPublicKey);
    }
    let mut x = Field::default();
    if !x.set_b32(array_ref!(pubkey, 0, 32)) {
        return Err(ECError::InvalidPublicKey);
    }
    let mut elem = Affine::default();
    elem.set_xo_var(&x, false);
    if elem.is_infinity() {
        return Err(ECError::InvalidPublicKey);
    }
    if elem.is_valid_var() {
        return ECPK::try_from(elem);
    } else {
        Err(ECError::InvalidPublicKey)
    }
}

// https://github.com/joschisan/schnorr_secp256k1/blob/main/src/schnorr.rs#LL90C1-L90C1
pub fn verify_schnorr(message: &[u8], pubkey: &[u8], signature: &[u8]) -> bool {
    if signature.len() != 64 || message.len() != 32 || pubkey.len() != 32 {
        return false;
    }

    let p: ECPK = load_xonly_pubkey(pubkey).unwrap();
    let r:ECPK = load_xonly_pubkey(&signature[..32]).unwrap();
    let s:ECSK = ECSK::parse_slice(&signature[32..]).unwrap();
    
    // compute e
    let e = sha256_tagged(&signature[..32], &pubkey, message);

    // Compute rj =  s*G + (-e)*pkj
    let mut e_p_j = Jacobian::default();
    let e = e.neg();
    ECMULT_CONTEXT.ecmult_const(&mut e_p_j, &p.into(), &e);

    let mut g_j_s = Jacobian::default();
    ECMULT_GEN_CONTEXT.ecmult_gen(&mut g_j_s, &s.into());

    let rj = e_p_j.add_var(&g_j_s, None);

    let mut rx = Affine::from_gej(&rj);
    if rx.is_infinity() {
        return false;
    }
    rx.y.normalize_var();
    let r: Affine = r.into();
    return !rx.y.is_odd() && rx.x == r.x
}



pub fn verify(message: &[u8], pubkey: &[u8], signature: &[u8]) -> bool {
    if signature.len() != 65 {
        return false;
    }
    let R:ECSK = ECSK::parse_slice(&signature[..32]).unwrap();
    let V:ECPK = ECPK::parse_slice(&signature[32..], Some(PublicKeyFormat::Compressed)).unwrap();
    let Pk: ECPK = ECPK::parse_slice(pubkey, Some(PublicKeyFormat::Compressed)).unwrap();

    let e = hash(&V.serialize_compressed(), &Pk.serialize_compressed(), message);
    let mut e_y_j = Jacobian::default();
    ECMULT_CONTEXT.ecmult_const(&mut e_y_j, &Pk.into(), &e);

    let e_y_plus_v_j = e_y_j.add_ge(&V.into());

    let mut g_j_s = Jacobian::default();
    ECMULT_GEN_CONTEXT.ecmult_gen(&mut g_j_s, &R.into());

    let g_s = Affine::from_gej(&g_j_s);
    let e_y_plus_v: Affine = Affine::from_gej(&e_y_plus_v_j);

    return e_y_plus_v == g_s
}
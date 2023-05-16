#![allow(non_snake_case)]
use curv::BigInt;
use curv::arithmetic::Converter;
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
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;

use curv::elliptic::curves::secp256_k1::FE;
use curv::elliptic::curves::secp256_k1::GE;
use curv::elliptic::curves::secp256_k1::PK;
use curv::elliptic::curves::traits::ECPoint;
use curv::elliptic::curves::traits::ECScalar;
use protocols::thresholdsig::bitcoin_schnorr::*;
use libsecp256k1::{PublicKey as ECPK, SecretKey as ECSK, Signature as ECSig};
use secp::Message;
use secp::Secp256k1;
use secp::XOnlyPublicKey;
use secp::schnorr::Signature as SCSig;

#[test]
#[allow(unused_doc_comments)]
fn test_t2_n4() {
    /// this test assumes that in keygen we have n=4 parties and in signing we have 4 parties as well.
    let t = 2;
    let n = 4;
    let key_gen_parties_index_vec: [usize; 4] = [0, 1, 2, 3];
    let key_gen_parties_points_vec = (0..key_gen_parties_index_vec.len())
        .map(|i| key_gen_parties_index_vec[i].clone() + 1)
        .collect::<Vec<usize>>();

    let (_priv_keys_vec, priv_shared_keys_vec, Y, key_gen_vss_vec) =
        keygen_t_n_parties(t.clone(), n.clone(), &key_gen_parties_points_vec);
    let parties_index_vec: [usize; 4] = [0, 1, 2, 3];
    let parties_points_vec = (0..parties_index_vec.len())
        .map(|i| parties_index_vec[i].clone() + 1)
        .collect::<Vec<usize>>();

    let (_eph_keys_vec, eph_shared_keys_vec, V, eph_vss_vec) =
        keygen_t_n_parties(t.clone(), n.clone(), &parties_points_vec);
    let message: [u8; 46] = [79; 46];
    let local_sig_vec = (0..n.clone())
        .map(|i| LocalSig::compute(&message, &eph_shared_keys_vec[i], &priv_shared_keys_vec[i]))
        .collect::<Vec<LocalSig>>();
    let verify_local_sig = LocalSig::verify_local_sigs(
        &local_sig_vec,
        &parties_index_vec,
        &key_gen_vss_vec,
        &eph_vss_vec,
    );

    assert!(verify_local_sig.is_ok());
    let vss_sum_local_sigs = verify_local_sig.unwrap();
    let signature = Signature::generate(&vss_sum_local_sigs, &local_sig_vec, &parties_index_vec, V);




    // convert to SCSig
    let vv = signature.v.clone();
    println!("vv uncompressed : {:?} \nvv compressed: {:?} \nx coor: {:?}", vv.get_element().serialize_uncompressed(), vv.get_element().serialize(), vv.x_coor().unwrap().to_bytes());
    
    let mut sc_sig = [0u8; 64];
    sc_sig[..32].copy_from_slice(&signature.sigma.to_big_int().to_bytes());
    sc_sig[32..].copy_from_slice(&signature.v.x_coor().unwrap().to_bytes());

    let sc_sig = SCSig::from_slice(&sc_sig).unwrap();
    let verifyer = Secp256k1::new();
    
    println!("x len: {}", Y.x_coor().unwrap().to_bytes().len());
    let msg = signature.hash_message(&message, &Y).unwrap();
    verifyer.verify_schnorr(&sc_sig,
        &Message::from_slice(&msg.to_bytes()).unwrap(), 
        &XOnlyPublicKey::from_slice(&Y.x_coor().unwrap().to_bytes()).unwrap()).unwrap();





    let verify_sig = signature.verify(&message, &Y);
    assert!(verify_sig.is_ok());

    let vb = signature.v.get_element().serialize();
    let pk = PK::from_slice(&vb).unwrap().serialize_uncompressed();
    
    let x = BigInt::from_bytes(&pk[1..33]);
    let y = BigInt::from_bytes(&pk[33..]);
    let v = GE::from_coor(&x, &y);
    println!("v: {:?}", v);
    let s_bytes = SigEx::from(signature).to_bytes();
    println!("signature bytes len: {}, data: {:?}", s_bytes.len(), s_bytes);
    let sig = SigEx::from_bytes(&s_bytes).unwrap();

    let verify_sig = sig.signature.verify(&message, &Y);
    assert!(verify_sig.is_ok());

    let unknown_pk = [12u8, 132, 2, 236, 10, 1, 152, 124, 229, 44, 252, 203, 196, 4, 53, 103, 150, 32, 82, 206, 123, 143, 219, 20, 140, 205, 160, 29, 82, 45, 209, 163, 253, 196, 49, 132, 2, 161, 45, 115, 186, 102, 8, 88, 206, 192, 105, 180, 212, 92, 38, 234, 215, 203, 137, 26, 50, 204, 228, 100, 122, 33, 130, 185, 51, 148, 225, 14, 97, 132, 3, 235, 160, 219, 0, 4, 178, 182, 167, 35, 198, 97, 150, 36, 65, 7, 245, 187, 142, 20, 196, 249, 220, 117, 18, 182, 215, 162, 184, 254, 20, 176, 214];

    // use secp256k1 crate to verify the schnorr signature.
    let ec_pk = ECPK::parse_compressed(&vb).unwrap();
    let ec_sig = ECSig::parse_standard_slice(&s_bytes[..64]).unwrap();

    // use invalid message should 
    let invalid_message:[u8; 46] = [22; 46];
    let vr = verify(&invalid_message, &Y.bytes_compressed_to_big_int().to_bytes(), &s_bytes);
    assert!(!vr);

    // use invalid public should failed.
    let vr = verify(&message, &V.bytes_compressed_to_big_int().to_bytes(), &s_bytes);
    assert!(!vr);

    // use invalid signature should failed.
    let mut invalid_sig = s_bytes.clone();
    invalid_sig[0] = 44;
    let vr = verify(&message, &Y.bytes_compressed_to_big_int().to_bytes(), &invalid_sig);
    assert!(!vr);

    // should success
    // let vr = verify(&message, &Y.bytes_compressed_to_big_int().to_bytes(), &s_bytes);
    // assert!(vr);
}

#[test]
#[allow(unused_doc_comments)]
fn test_t2_n5_sign_with_4() {
    /// this test assumes that in keygen we have n=4 parties and in signing we have 4 parties, indices 0,1,3,4.
    let t = 2;
    let n = 5;
    /// keygen:
    let key_gen_parties_index_vec: [usize; 5] = [0, 1, 2, 3, 4];
    let key_gen_parties_points_vec = (0..key_gen_parties_index_vec.len())
        .map(|i| key_gen_parties_index_vec[i].clone() + 1)
        .collect::<Vec<usize>>();
    let (_priv_keys_vec, priv_shared_keys_vec, Y, key_gen_vss_vec) =
        keygen_t_n_parties(t.clone(), n.clone(), &key_gen_parties_points_vec);
    /// signing:
    let parties_index_vec: [usize; 4] = [0, 1, 3, 4];
    let parties_points_vec = (0..parties_index_vec.len())
        .map(|i| parties_index_vec[i].clone() + 1)
        .collect::<Vec<usize>>();
    let num_parties = parties_index_vec.len();
    let (_eph_keys_vec, eph_shared_keys_vec, V, eph_vss_vec) =
        keygen_t_n_parties(t.clone(), num_parties.clone(), &parties_points_vec);
    let message: [u8; 678] = [79u8 ; 678];

    // each party computes and share a local sig, we collected them here to a vector as each party should do AFTER receiving all local sigs
    let local_sig_vec = (0..num_parties.clone())
        .map(|i| {
            LocalSig::compute(
                &message,
                &eph_shared_keys_vec[i],
                &priv_shared_keys_vec[parties_index_vec[i]],
            )
        })
        .collect::<Vec<LocalSig>>();

    let verify_local_sig = LocalSig::verify_local_sigs(
        &local_sig_vec,
        &parties_index_vec,
        &key_gen_vss_vec,
        &eph_vss_vec,
    );

    assert!(verify_local_sig.is_ok());
    let vss_sum_local_sigs = verify_local_sig.unwrap();

    /// each party / dealer can generate the signature
    let signature = Signature::generate(&vss_sum_local_sigs, &local_sig_vec, &parties_index_vec, V);
    let verify_sig = signature.verify(&message, &Y);
    assert!(verify_sig.is_ok());

    // use schnorrkel to verify
    // let signature = schnorrkel::Signature::from_bytes(signature).unwrap();
}

#[allow(dead_code)]
pub fn keygen_t_n_parties(
    t: usize,
    n: usize,
    parties: &[usize],
) -> (Vec<Keys>, Vec<SharedKeys>, GE, Vec<VerifiableSS<GE>>) {
    let parames = Parameters {
        threshold: t,
        share_count: n.clone(),
    };
    assert_eq!(parties.len(), n.clone());
    let party_keys_vec = (0..n.clone())
        .map(|i| Keys::phase1_create(parties[i]))
        .collect::<Vec<Keys>>();

    let mut bc1_vec = Vec::new();
    let mut blind_vec = Vec::new();
    for i in 0..n.clone() {
        let (bc1, blind) = party_keys_vec[i].phase1_broadcast();
        bc1_vec.push(bc1);
        blind_vec.push(blind);
    }

    let y_vec = (0..n.clone())
        .map(|i| party_keys_vec[i].y_i.clone())
        .collect::<Vec<GE>>();
    let mut y_vec_iter = y_vec.iter();
    let head = y_vec_iter.next().unwrap();
    let tail = y_vec_iter;
    let y_sum = tail.fold(head.clone(), |acc, x| acc + x);
    let mut vss_scheme_vec = Vec::new();
    let mut secret_shares_vec = Vec::new();
    let mut index_vec = Vec::new();
    for i in 0..n.clone() {
        let (vss_scheme, secret_shares, index) = party_keys_vec[i]
            .phase1_verify_com_phase2_distribute(&parames, &blind_vec, &y_vec, &bc1_vec, parties)
            .expect("invalid key");
        vss_scheme_vec.push(vss_scheme);
        secret_shares_vec.push(secret_shares);
        index_vec.push(index);
    }

    let party_shares = (0..n.clone())
        .map(|i| {
            (0..n.clone())
                .map(|j| {
                    let vec_j = &secret_shares_vec[j];
                    vec_j[i].clone()
                })
                .collect::<Vec<FE>>()
        })
        .collect::<Vec<Vec<FE>>>();

    let mut shared_keys_vec = Vec::new();
    for i in 0..n.clone() {
        let shared_keys = party_keys_vec[i]
            .phase2_verify_vss_construct_keypair(
                &parames,
                &y_vec,
                &party_shares[i],
                &vss_scheme_vec,
                &index_vec[i],
            )
            .expect("invalid vss");
        shared_keys_vec.push(shared_keys);
    }

    (party_keys_vec, shared_keys_vec, y_sum, vss_scheme_vec)
}

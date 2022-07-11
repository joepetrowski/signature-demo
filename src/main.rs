use sp_core::*;
use std::fmt::Debug;

fn main() {
	signatures();
	hashes();
}

fn signatures() {
	println!("\n\nStarting Signature Demo.\n\n");
	/* Key generation */

	// Generate a secret key.
	let (pair, mnemonic, raw_seed) = sr25519::Pair::generate_with_phrase(None);
	println!("Secret Phrase: {}", mnemonic);
	println!("Secret Key: {:?}", raw_seed);

	// Derive the public key.
	let pk = pair.public();
	println!("Public Key: {:?}\n", &pk.0);

	// Recreate the secret from the mnemonic.
	let (same_pair, same_raw_seed) = sr25519::Pair::from_phrase(&mnemonic, None).unwrap();
	let same_pk = same_pair.public();
	println!("Same Secret Key: {:?}", &same_raw_seed);
	println!("Same Public Key: {:?}\n", &same_pk.0);

	/* Signatures */

	// Sign a message.
	let message = b"Welcome to Polkadot Blockchain Academy 2022";
	let signature = pair.sign(&message[..]);
	println!("Message: {:?}", std::str::from_utf8(&message[..]).unwrap());
	println!("Signature: {:?}", &signature);

	// Verify the signature.
	assert!(sr25519::Pair::verify(&signature, &message[..], &pk));
	println!("Signature verified!\n");

	// Alter the message.
	let tampered = b"Welcome to Polkadot Blockchain Academy 2021";
	assert!(!sr25519::Pair::verify(&signature, &tampered[..], &pk));
	println!("Tampered Message: {:?}", std::str::from_utf8(&tampered[..]).unwrap());
	println!("Signature rejected!\n");

	/* Message Hash */

	let long_message =
		b"Welcome to Polkadot Blockchain Academy 2022. We are staying in Cambridge, which I was told is far superior to Oxford, but I should probably leave that to others to hash out.";
	let message_hash = blake2_256(&long_message[..]);
	let signature_on_hash = pair.sign(&message_hash[..]);
	println!("Longer Message: {:?}", std::str::from_utf8(&long_message[..]).unwrap());
	println!("Long Message Hash: {:?}", message_hash);

	// Verify the signature.
	assert!(sr25519::Pair::verify(&signature_on_hash, blake2_256(&long_message[..]), &pk));
	println!("Signature verified!\n");

	/* Hard Derivation */

	// Derive new key pairs using //polkadot and //kusama.
	let pair_polkadot = sr25519::Pair::from_string(&format!("{}//polkadot", &mnemonic), None);
	let pk_polkadot = pair_polkadot.unwrap().public();
	let pair_kusama = sr25519::Pair::from_string(&format!("{}//kusama", &mnemonic), None);
	let pk_kusama = pair_kusama.unwrap().public();
	println!("Polkadot Public Key: {:?}", &pk_polkadot.0);
	println!("Kusama Public Key: {:?}\n", pk_kusama.0);

	/* Soft Derivation */

	// Derive a soft path on the Polkadot key.
	let pair_polkadot_zero = sr25519::Pair::from_string(&format!("{}//polkadot/0", &mnemonic), None);
	let pubkey_soft_derived_with_secret = pair_polkadot_zero.unwrap().public();
	println!(
		"Polkadot Soft-Derived Public Key (from secret): {:?}",
		&pubkey_soft_derived_with_secret.0
	);

	// Derive a soft path on the Polkadot key, but only use the _public_ material.
	let pk_polkadot: sr25519::Public = sr25519::Public(pk_polkadot.0);
	let path = vec![DeriveJunction::soft(0u8)];
	use sp_core::crypto::Derive;
	let pubkey_soft_derived_without_secret = pk_polkadot.derive(path.into_iter());
	println!(
		"Polkadot Soft-Derived Public Key (from pubkey): {:?}",
		&pubkey_soft_derived_without_secret.unwrap().0
	);

	assert_eq!(pubkey_soft_derived_with_secret, pubkey_soft_derived_without_secret.unwrap());
	println!("They are equal!");
}

fn hashes() {
	println!("\n\nStarting Hash Function Demo.\n\n");
	/* Variable input, fixed output. */

	let short_input_hash = blake2_256(&b"abcd"[..]);
	let long_input_hash = blake2_256(&[0; 1024][..]);
	assert_eq!(short_input_hash.len(), long_input_hash.len());
	println!("{:?}", short_input_hash);
	println!("{:?}", long_input_hash);

	/* Computation Speed */

	use std::time::{Instant};
	let value_to_hash = [0; 1024]; // 1 kb

	let blake2_start = Instant::now();
	for _ in 0..1000 {
		let _ = blake2_256(&value_to_hash[..]);
	}
	let blake2_elapsed_time = blake2_start.elapsed().as_micros();

	let twox_start = Instant::now();
	for _ in 0..1000 {
		let _ = twox_256(&value_to_hash[..]);
	}
	let twox_elapsed_time = twox_start.elapsed().as_micros();

	println!("\nTime (us) for 1k rounds of Blake2: {:?}", blake2_elapsed_time);
	println!("Time (us) for 1k rounds of TwoX:   {:?}", twox_elapsed_time); // expected about 10x faster

	/* Pre-Image Attacks */

	use rand::prelude::*;
	let attack_target = blake2_256(b"cambridge");

	let mut count = 0u32;
	let difficulty = 2; // number of bytes to call it a "collision"
	loop {
		count += 1;
		let x: [u8; 16] = random();
		let x_hash = blake2_256(&x[..]);
		if sized_compare(&attack_target[0..difficulty], &x_hash[0..difficulty]) {
			println!("\nSecond pre-image found in {:?} attempts! {:?}", count, x);
			sized_print(&x_hash[0..difficulty]);
			sized_print(&attack_target[0..difficulty]);
			break;
		}

		// some protection
		if count == 500_000 {
			println!("\nGiving up on pre-image attack");
			break;
		}
	}

	/* Collisions */

	//                     hash,     value
	let mut previous: Vec<([u8; 32], [u8; 16])> = Vec::new();

	let mut count = 0u32;
	let mut break_loop = false;
	let difficulty = 2; // number of bytes to call it a "collision"
	loop {
		count += 1;

		let x: [u8; 16] = random();
		let x_hash = blake2_256(&x[..]);

		for hh in &previous {
			if sized_compare(&x_hash[0..difficulty], &hh.0[0..difficulty]) {
				println!("\nCollision found in {:?} attempts!", count);
				println!("pre-image 1: {:?}", &hh.1);
				println!("pre-image 2: {:?}", x);
				sized_print(&x_hash[0..difficulty]);
				sized_print(&hh.0[0..difficulty]);
				break_loop = true;
				break;
			}
		}
		if break_loop {
			break;
		}

		previous.push((x_hash, x));

		// some protection
		if count == 100_000 {
			println!("\nGiving up on collision");
			break;
		}
	}
}

fn sized_print<H:Debug+?Sized>(h: &H) {
    println!("{:?}", h);
}

fn sized_compare<H:std::cmp::PartialEq+?Sized>(a: &H, b: &H) -> bool {
	a == b
}

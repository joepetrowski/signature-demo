use sp_core::*;

fn main() {

	/* Key generation */

	// Generate a secret key.
	let (pair, mnemonic, raw_seed) = sr25519::Pair::generate_with_phrase(None);
	println!("Secret Phrase: {}", mnemonic);
	println!("Secret Key: {:?}", raw_seed);

	// Derive the public key.
	let pk = pair.public();
	println!("Public Key: {:?}\n", &pk.0);

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

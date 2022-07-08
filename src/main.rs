use sp_core::{blake2_256, Pair as _, sr25519::Pair};

fn main() {

	/* Key generation */

	// Generate a secret key.
	let (pair, mnemonic, raw_seed) = Pair::generate_with_phrase(None);
	println!("Secret Phrase: {}", mnemonic);
	println!("Secret Key: {:?}", raw_seed);

	// Derive the public key.
	let pk = pair.public();
	println!("Public Key: {:?}\n", pk.0);

	/* Signatures */

	// Sign a message.
	let message = b"Welcome to Polkadot Blockchain Academy 2022";
	let signature = pair.sign(&message[..]);
	println!("Message: {:?}", std::str::from_utf8(&message[..]).unwrap());
	println!("Signature: {:?}", &signature);

	// Verify the signature.
	assert!(Pair::verify(&signature, &message[..], &pk));
	println!("Signature verified!\n");

	// Alter the message.
	let tampered = b"Welcome to Polkadot Blockchain Academy 2021";
	assert!(!Pair::verify(&signature, &tampered[..], &pk));
	println!("Tampered Message: {:?}", std::str::from_utf8(&tampered[..]).unwrap());
	println!("Signature rejected!\n");

	/* Message Hash */
	let long_message =
		b"Welcome to Polkadot Blockchain Academy 2022. We are staying in Cambridge, which I was told is far superior to Oxford, but I should probably leave that to others to hash out.";
	let message_hash = blake2_256(&long_message[..]);
	let signature_on_hash = pair.sign(&message_hash);
	println!("Longer Message: {:?}", std::str::from_utf8(&long_message[..]).unwrap());
	println!("Long Message Hash: {:?}", message_hash);

	// Verify the signature.
	assert!(Pair::verify(&signature_on_hash, blake2_256(&long_message[..]), &pk));
	println!("Signature verified!\n");

	/* Hard Derivation */

	// Derive new key pairs using //polkadot and //kusama.
	let pair_polkadot = Pair::from_string(&format!("{}//polkadot", &mnemonic), None);
	let pk_polkadot = pair_polkadot.unwrap().public();
	let pair_kusama = Pair::from_string(&format!("{}//kusama", &mnemonic), None);
	let pk_kusama = pair_kusama.unwrap().public();
	println!("Polkadot Public Key: {:?}", pk_polkadot.0);
	println!("Kusama Public Key: {:?}\n", pk_kusama.0);

	/* Soft Derivation */

	// Derive a soft path on the Polkadot key.
	let pair_polkadot_0 = Pair::from_string(&format!("{}//polkadot/0", &mnemonic), None);
	let pk_polkadot_0 = pair_polkadot_0.unwrap().public();
	println!("Polkadot Soft-Derived Public Key: {:?}", pk_polkadot_0.0);
}

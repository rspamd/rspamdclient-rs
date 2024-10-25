use crypto_box::{SecretKey, aead::{OsRng, AeadCore}, ChaChaBox};
use crypto_box::aead::AeadInPlace;
use crate::error::RspamdError;
use rspamd_base32::decode;

/// Encrypt a plaintext with a given peer public key generating an ephemeral keypair.
fn encrypt_inplace(
	plaintext: &[u8],
	recipient_public_key: &[u8],
	local_sk: &SecretKey,
) -> Result<Vec<u8>, RspamdError> {
	let mut dest = Vec::with_capacity(plaintext.len() +
		std::mem::size_of::<<ChaChaBox as AeadCore>::NonceSize>() +
		std::mem::size_of::<<ChaChaBox as AeadCore>::TagSize>());
	let remote_pk = decode(recipient_public_key)
		.map_err(|_| RspamdError::EncryptionError("Base32 decode failed".to_string()))?;
	let remote_pk = crypto_box::PublicKey::from_slice(&remote_pk)
		.map_err(|_| RspamdError::EncryptionError("Public key is invalid".to_string()))?;
	let cbox = ChaChaBox::new(&remote_pk, &local_sk);
	let nonce = ChaChaBox::generate_nonce(&mut OsRng);
	dest.extend_from_slice(nonce.as_slice());
	dest.extend_from_slice(plaintext);
	let mac = cbox.encrypt_in_place_detached(&nonce, &[], &mut dest.as_mut_slice()[nonce.len()..])
		.map_err(|_| RspamdError::EncryptionError("Cannot encrypt".to_string()))?;
	dest.extend_from_slice(mac.as_slice());
	Ok(dest)
}

pub struct HTTPCryptEncrypted {
	pub body: Vec<u8>,
	pub peer_key: String, // Encoded as base32
}

pub fn httpcrypt_encrypt<T, HN, HV>(url: &str, body: &[u8], headers: T, peer_key: &[u8]) -> Result<HTTPCryptEncrypted, RspamdError>
where T: IntoIterator<Item = (HN, HV)>,
	  HN: AsRef<[u8]>,
	  HV: AsRef<[u8]>
{
	let local_sk = SecretKey::generate(&mut OsRng);
	let local_pk = local_sk.public_key();
	let extra_size = std::mem::size_of::<<ChaChaBox as AeadCore>::NonceSize>() + std::mem::size_of::<<ChaChaBox as AeadCore>::TagSize>();
	let mut dest = Vec::with_capacity(body.len() + 128 + extra_size);

	// Fill the inner headers
	dest.extend_from_slice(b"POST ");
	dest.extend_from_slice(url.as_bytes());
	dest.extend_from_slice(b" HTTP/1.1\n");
	for (k, v) in headers {
		dest.extend_from_slice(k.as_ref());
		dest.push(b':');
		dest.extend_from_slice(v.as_ref());
		dest.push(b'\n');
	}
	dest.push(b'\n');
	dest.extend_from_slice(body.as_ref());

	dest = encrypt_inplace(&dest.as_slice(), peer_key, &local_sk)?;

	Ok(HTTPCryptEncrypted {
		body: dest.clone(),
		peer_key: rspamd_base32::encode(local_pk.as_ref()),
	})
}
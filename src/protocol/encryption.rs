use crypto_box::{SecretKey, aead::{OsRng, AeadCore}, ChaChaBox};
use crypto_box::aead::AeadInPlace;
use crate::error::RspamdError;
use rspamd_base32::{decode, encode};
use blake2b_simd::blake2b;
use chacha20::hchacha;
use chacha20::cipher::zeroize::Zeroizing;
use crypto_box::aead::generic_array::arr;
use crypto_secretbox::{XChaCha20Poly1305, KeyInit, Tag};
use crypto_secretbox::consts::U20;
use curve25519_dalek::Scalar;

/// It must be the same as Rspamd one, that is currently 5
const SHORT_KEY_ID_SIZE : usize = 5;

pub fn make_key_header(remote_pk: &str, local_pk: &str) -> Result<String, RspamdError> {
	let remote_pk = decode(remote_pk)
		.map_err(|_| RspamdError::EncryptionError("Base32 decode failed".to_string()))?;
	let hash = blake2b(remote_pk.as_slice());
	let hash_b32 = encode(&hash.as_bytes()[0..SHORT_KEY_ID_SIZE]);
	Ok(format!("{}={}", hash_b32.as_str(), local_pk))
}

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

	// Do manual scalarmult as Rspamd is using it's own way there
	let n0 = arr![u8; 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,];
	let mut nm = Zeroizing::new(local_sk.to_scalar() * Scalar::from_bytes_mod_order(*remote_pk.as_bytes())).to_bytes();
	nm[0] &= 248u8;
	nm[31] &= 127u8;
	nm[31] |= 64u8;
	let nm = Zeroizing::new(hchacha::<U20>(&nm.into(), &n0));
	let cbox = XChaCha20Poly1305::new(nm.as_slice().into());
	let nonce = ChaChaBox::generate_nonce(&mut OsRng);
	dest.extend_from_slice(nonce.as_slice());
	// Make room in the buffer for the tag. It needs to be prepended.
	dest.extend_from_slice(Tag::default().as_slice());
	let offset = dest.len();
	dest.extend_from_slice(plaintext);
	let tag = cbox.encrypt_in_place_detached(&nonce, &[], &mut dest.as_mut_slice()[offset..])
		.map_err(|_| RspamdError::EncryptionError("Cannot encrypt".to_string()))?;
	<Vec<u8> as AsMut<Vec<u8>>>::as_mut(&mut dest)[nonce.len()..XChaCha20Poly1305::TAG_SIZE].copy_from_slice(tag.as_slice());
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

	dest = encrypt_inplace(dest.as_slice(), peer_key, &local_sk)?;

	Ok(HTTPCryptEncrypted {
		body: dest.clone(),
		peer_key: rspamd_base32::encode(local_pk.as_ref()),
	})
}
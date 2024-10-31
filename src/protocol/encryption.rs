use crypto_box::{SecretKey, aead::{OsRng, AeadCore}, ChaChaBox};
use crypto_box::aead::AeadInPlace;
use crate::error::RspamdError;
use rspamd_base32::{decode, encode};
use blake2b_simd::blake2b;
use chacha20::cipher::consts::U10;
use chacha20::hchacha;
use chacha20::cipher::zeroize::Zeroizing;
use crypto_box::aead::generic_array::{arr, GenericArray, typenum::U32};
use crypto_secretbox::{XChaCha20Poly1305, KeyInit, Tag};
use crypto_secretbox::aead::Aead;
use curve25519_dalek::{MontgomeryPoint, Scalar};
use curve25519_dalek::scalar::clamp_integer;

/// It must be the same as Rspamd one, that is currently 5
const SHORT_KEY_ID_SIZE : usize = 5;

pub fn make_key_header(remote_pk: &str, local_pk: &str) -> Result<String, RspamdError> {
	let remote_pk = decode(remote_pk)
		.map_err(|_| RspamdError::EncryptionError("Base32 decode failed".to_string()))?;
	let hash = blake2b(remote_pk.as_slice());
	let hash_b32 = encode(&hash.as_bytes()[0..SHORT_KEY_ID_SIZE]);
	Ok(format!("{}={}", hash_b32.as_str(), local_pk))
}

/// Perform a scalar multiplication with a remote public key and a local secret key.
pub(crate) fn rspamd_x25519_scalarmult(remote_pk: &[u8], local_sk: &SecretKey) -> Result<Zeroizing<MontgomeryPoint>, RspamdError> {
	let remote_pk: [u8; XChaCha20Poly1305::KEY_SIZE] = decode(remote_pk)
		.map_err(|_| RspamdError::EncryptionError("Base32 decode failed".to_string()))?
		.as_slice().try_into().unwrap();
	// Do manual scalarmult as Rspamd is using it's own way there
	let e = Scalar::from_bytes_mod_order(clamp_integer(local_sk.to_bytes()));
	let p = MontgomeryPoint(remote_pk);
	Ok(Zeroizing::new(e * p))
}

/// Unlike IETF version, Rspamd uses an old suggested way to derive a shared secret - it performs
/// hchacha iteration on the point and a zeroed nonce.
pub(crate) fn rspamd_x25519_ecdh(point: Zeroizing<MontgomeryPoint>) -> Zeroizing<GenericArray<u8, U32>> {
	let n0 = arr![u8; 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,];
	Zeroizing::new(hchacha::<U10>(&point.to_bytes().into(), &n0))
}

/// Encrypt a plaintext with a given peer public key generating an ephemeral keypair.
fn encrypt_inplace(
	plaintext: &[u8],
	recipient_public_key: &[u8],
	local_sk: &SecretKey,
) -> Result<(Vec<u8>, XChaCha20Poly1305), RspamdError> {
	let mut dest = Vec::with_capacity(plaintext.len() +
		XChaCha20Poly1305::NONCE_SIZE +
		XChaCha20Poly1305::TAG_SIZE);
	let ec_point = rspamd_x25519_scalarmult(recipient_public_key, local_sk)?;
	let nm = rspamd_x25519_ecdh(ec_point);
	let cbox = XChaCha20Poly1305::new(nm.as_slice().into());
	let nonce = ChaChaBox::generate_nonce(&mut OsRng);
	dest.extend_from_slice(nonce.as_slice());
	// Make room in the buffer for the tag. It needs to be prepended.
	dest.extend_from_slice(Tag::default().as_slice());
	let offset = dest.len();
	dest.extend_from_slice(plaintext);
	let nm_slice = nm.as_slice();
	let tag = cbox.encrypt_in_place_detached(&nonce, &[], &mut dest.as_mut_slice()[offset..])
		.map_err(|_| RspamdError::EncryptionError("Cannot encrypt".to_string()))?;
	let tag_dest = &mut <Vec<u8> as AsMut<Vec<u8>>>::as_mut(&mut dest)[nonce.len()..(nonce.len() + XChaCha20Poly1305::TAG_SIZE)];
	tag_dest.copy_from_slice(tag.as_slice());
	Ok((dest, cbox))
}

pub struct HTTPCryptEncrypted {
	pub body: Vec<u8>,
	pub peer_key: String, // Encoded as base32
	pub secretbox: XChaCha20Poly1305,
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

	let (dest, sbox) = encrypt_inplace(dest.as_slice(), peer_key, &local_sk)?;

	Ok(HTTPCryptEncrypted {
		body: dest,
		peer_key: rspamd_base32::encode(local_pk.as_ref()),
		secretbox: sbox,
	})
}

/// Decrypts body using HTTPCrypt algorithm
pub fn httpcrypt_decrypt(body: &[u8], secret_box: &XChaCha20Poly1305) -> Result<Vec<u8>, RspamdError> {
	let nonce = &body[0..XChaCha20Poly1305::NONCE_SIZE];
	secret_box.decrypt(nonce.into(), &body[XChaCha20Poly1305::NONCE_SIZE..])
		.map_err(|_| RspamdError::EncryptionError("Cannot decrypt".to_string()))
}

#[cfg(test)]
mod tests {
	use crate::protocol::encryption::*;
	const EXPECTED_POINT : [u8; 32] = [95, 76, 225, 188, 0, 26, 146, 94, 70, 249,
		90, 189, 35, 51, 1, 42, 9, 37, 94, 254, 204, 55, 198, 91, 180, 90,
		46, 217, 140, 226, 211, 90];

	#[cfg(test)]
	#[test]
	fn test_scalarmult() {
		use crypto_box::{SecretKey};
		let sk = SecretKey::from_slice(&[0u8; 32]).unwrap();
		let pk = "k4nz984k36xmcynm1hr9kdbn6jhcxf4ggbrb1quay7f88rpm9kay";
		let point = rspamd_x25519_scalarmult(pk.as_bytes(), &sk).unwrap();
		assert_eq!(point.to_bytes().as_slice(), EXPECTED_POINT);
	}

	#[cfg(test)]
	#[test]
	fn test_ecdh() {
		const EXPECTED_NM : [u8; 32] = [61, 109, 220, 195, 100, 174, 127, 237, 148,
			122, 154, 61, 165, 83, 93, 105, 127, 166, 153, 112, 103, 224, 2, 200,
			136, 243, 73, 51, 8, 163, 150, 7];
		let point = Zeroizing::new(MontgomeryPoint(EXPECTED_POINT));
		let nm = rspamd_x25519_ecdh(point);
		assert_eq!(nm.as_slice(), &EXPECTED_NM);
	}
}
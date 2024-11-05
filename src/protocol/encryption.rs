//! This module contains encryption functions used by the HTTPCrypt protocol.
//! This encryption is common to x25519 and chacha20-poly1305 as defined in RFC 8439.
//! However, since HTTPCrypt has been designed before RFC being published, it uses
//! a different way to do KEX and to derive shared keys.
//! In general, it relies on hchacha20 for kdf and x25519 for key exchange.

use crypto_box::{SecretKey, aead::{OsRng, AeadCore}, ChaChaBox};
use crate::error::RspamdError;
use rspamd_base32::{decode, encode};
use blake2b_simd::blake2b;
use chacha20::{cipher::consts::U10, hchacha, cipher::zeroize::Zeroizing, XChaCha20};
use chacha20::cipher::consts::U64;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use poly1305::{Poly1305, Tag};
use crypto_box::aead::generic_array::{arr, GenericArray, typenum::U32};
use curve25519_dalek::{MontgomeryPoint, Scalar};
use curve25519_dalek::scalar::clamp_integer;
use poly1305::universal_hash::{KeyInit};

/// It must be the same as Rspamd one, that is currently 5
const SHORT_KEY_ID_SIZE : usize = 5;

pub(crate) type RspamdNM = Zeroizing<GenericArray<u8, U32>>;

pub struct RspamdSecretbox {
	enc_ctx: XChaCha20,
	mac_ctx: Poly1305,
}

pub struct HTTPCryptEncrypted {
	pub body: Vec<u8>,
	pub peer_key: String, // Encoded as base32
	pub shared_key: RspamdNM,
}

impl RspamdSecretbox {
	/// Construct new secretbox following Rspamd conventions
	pub fn new(key: RspamdNM, nonce: chacha20::XNonce) -> Self {
		// Rspamd does it in a different way, doing full chacha20 round on the extended mac key
		let mut chacha = XChaCha20::new_from_slices(key.as_slice(),
													nonce.as_slice()).unwrap();
		let mut mac_key : GenericArray<u8, U64> = GenericArray::default();
		chacha.apply_keystream(mac_key.as_mut());
		let poly = Poly1305::new_from_slice(mac_key.split_at(32).0).unwrap();
		RspamdSecretbox {
			enc_ctx: chacha,
			mac_ctx: poly,
		}
	}

	/// Encrypts data in place and returns a tag
	pub fn encrypt_in_place(mut self, data: &mut [u8]) -> Tag {
		// Encrypt-then-mac
		self.enc_ctx.apply_keystream(data);
		self.mac_ctx.compute_unpadded(data)
	}

	/// Decrypts in place if auth tag is correct
	pub fn decrypt_in_place(&mut self, data: &mut [u8], tag: &Tag) -> Result<usize, RspamdError> {
		let computed = self.mac_ctx.clone().compute_unpadded(data);
		if computed != *tag {
			return Err(RspamdError::EncryptionError("Authentication failed".to_string()));
		}
		self.enc_ctx.apply_keystream(&mut data[..]);

		Ok(computed.len())
	}
}

pub fn make_key_header(remote_pk: &str, local_pk: &str) -> Result<String, RspamdError> {
	let remote_pk = decode(remote_pk)
		.map_err(|_| RspamdError::EncryptionError("Base32 decode failed".to_string()))?;
	let hash = blake2b(remote_pk.as_slice());
	let hash_b32 = encode(&hash.as_bytes()[0..SHORT_KEY_ID_SIZE]);
	Ok(format!("{}={}", hash_b32.as_str(), local_pk))
}

/// Perform a scalar multiplication with a remote public key and a local secret key.
pub(crate) fn rspamd_x25519_scalarmult(remote_pk: &[u8], local_sk: &SecretKey) -> Result<Zeroizing<MontgomeryPoint>, RspamdError> {
	let remote_pk: [u8; 32] = decode(remote_pk)
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
) -> Result<(Vec<u8>, RspamdNM), RspamdError> {
	let mut dest = Vec::with_capacity(plaintext.len() +
		24 +
		poly1305::BLOCK_SIZE);
	let ec_point = rspamd_x25519_scalarmult(recipient_public_key, local_sk)?;
	let nm = rspamd_x25519_ecdh(ec_point);

	let nonce = ChaChaBox::generate_nonce(&mut OsRng);
	let cbox = RspamdSecretbox::new(nm.clone(), nonce);
	dest.extend_from_slice(nonce.as_slice());
	// Make room in the buffer for the tag. It needs to be prepended.
	dest.extend_from_slice(Tag::default().as_slice());
	let offset = dest.len();
	dest.extend_from_slice(plaintext);
	let tag = cbox.encrypt_in_place(&mut dest.as_mut_slice()[offset..]);
	let tag_dest = &mut <Vec<u8> as AsMut<Vec<u8>>>::as_mut(&mut dest)[nonce.len()..(nonce.len() + poly1305::BLOCK_SIZE)];
	tag_dest.copy_from_slice(tag.as_slice());
	Ok((dest, nm))
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
		dest.extend_from_slice(b": ");
		dest.extend_from_slice(v.as_ref());
		dest.push(b'\n');
	}
	dest.extend_from_slice(format!("Content-Length: {}\n\n", body.len()).as_bytes());
	dest.extend_from_slice(body.as_ref());

	let (encrypted, nm) = encrypt_inplace(dest.as_slice(), peer_key, &local_sk)?;

	Ok(HTTPCryptEncrypted {
		body: encrypted,
		peer_key: rspamd_base32::encode(local_pk.as_ref()),
		shared_key: nm,
	})
}

/// Decrypts body using HTTPCrypt algorithm
pub fn httpcrypt_decrypt(body: &mut [u8], nm: RspamdNM) -> Result<usize, RspamdError> {
	if body.len() < 24 + poly1305::BLOCK_SIZE {
		return Err(RspamdError::EncryptionError("Invalid body size".to_string()));
	}

	let (nonce, remain) = body.split_at_mut(24);
	let (tag, decrypted_dest) = remain.split_at_mut(poly1305::BLOCK_SIZE);
	let tag = Tag::from_slice(tag);
	let mut offset = nonce.len();
	let mut sbox = RspamdSecretbox::new(nm, *chacha20::XNonce::from_slice(nonce));
	offset += sbox.decrypt_in_place(decrypted_dest, tag)?;
	Ok(offset)
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
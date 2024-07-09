use color_eyre::Result;
use thiserror::Error;

use rand::{rngs::OsRng, Rng};
use rsa::{
    pkcs8::{Document, EncodePublicKey},
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
};
use tracing::trace;

use crate::multi_version::{self, Protocol};

use super::Connection;

#[derive(Debug, Error)]
pub(crate) enum EncryptionError {
    #[error("verify tokens don't match: expected = {0:?}, recieved = {1:?}")]
    VerifyTokenMissmatch(Vec<u8>, Vec<u8>),

    // only way for a shared secret to be invalid is if it's the wrong size
    #[error("client send invalid length shared secret: got {0} expected 16")]
    InvalidSharedSecret(usize),
}

#[derive(Debug, Clone)]
pub struct McKeyPair {
    private_key: RsaPrivateKey,
    public_key_der: Document,
}

impl McKeyPair {
    pub fn generate() -> Result<Self> {
        let private_key = RsaPrivateKey::new(&mut OsRng, 1024)?;
        let public_key = RsaPublicKey::from(&private_key);

        let public_key_der = public_key.to_public_key_der()?;

        Ok(McKeyPair {
            private_key,
            public_key_der,
        })
    }

    pub fn public_key_der(&self) -> &Document {
        &self.public_key_der
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        Ok(self.private_key.decrypt(Pkcs1v15Encrypt, ciphertext)?)
    }
}

pub(crate) fn negotiate_encryption<P: Protocol>(
    key_pair: &McKeyPair,
    connection: &mut Connection<P::LoginState>,
) -> Result<Vec<u8>>
where
    P::StatusState: multi_version::StatusState,
    <P::StatusState as mcproto::state::RoleStatePackets<mcproto::role::Server>>::RecvPacket:
        mcproto::packet::PacketFromIdBody,
    P::LoginState: multi_version::LoginState,
    <P::LoginState as mcproto::state::RoleStatePackets<mcproto::role::Server>>::RecvPacket:
        mcproto::packet::PacketFromIdBody,
{
    // generate 4 random bytes
    let mut verify_token = vec![0u8; 4];
    OsRng.fill(&mut verify_token[..]);

    // tell client to begin encryption
    P::write_encryption_request(
        connection,
        multi_version::EncryptionRequest {
            server_id: "".into(),
            public_key: key_pair.public_key_der().clone().into_vec(),
            verify_token: verify_token.clone(),
        },
    )?;
    trace!("Sent encryption request packet");

    // client should authenticate with mojang

    // client is ready to enable encryption and will after this packet
    let encryption_res = P::read_encryption_response(connection)?;
    trace!(?encryption_res, "Recieved encryption response packet");

    // decrypt the verify the tunnel
    let res_verify_token = key_pair.decrypt(&encryption_res.verify_token)?;
    if verify_token != res_verify_token {
        return Err(EncryptionError::VerifyTokenMissmatch(verify_token, res_verify_token).into());
    }

    // decrypt shared secred used for future encryption
    let shared_secret = key_pair.decrypt(&encryption_res.shared_secret)?;
    if shared_secret.len() != 16 {
        return Err(EncryptionError::InvalidSharedSecret(shared_secret.len()).into());
    }

    // enable encryption
    connection.set_encryption_secret(&shared_secret);

    Ok(shared_secret)
}

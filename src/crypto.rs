use crate::error::Error;
use crate::util::env_var;
use hmac::{Hmac, Mac, NewMac};
use sha2::Sha256;
use std::convert::TryInto;

pub struct Crypto {
    secret: [u8; 64],
}

pub struct Signature {
    pub hash: [u8; 32],
}

impl Crypto {
    pub fn from_env() -> Result<Crypto, Error> {
        let secret = hex::decode(env_var("SECRET")?)?.try_into().unwrap();
        Ok(Crypto { secret })
    }

    pub fn sign(&self, data: &[u8]) -> Signature {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret).unwrap();
        mac.update(data);
        Signature {
            hash: mac.finalize().into_bytes().into(),
        }
    }

    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<Signature, Error> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret).unwrap();
        mac.update(data);
        mac.verify(signature)?;
        Ok(Signature {
            hash: signature.try_into().unwrap(),
        })
    }
}

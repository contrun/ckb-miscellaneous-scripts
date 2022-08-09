use rlua::{Lua, Result};

use bitcoin_hashes::{sha256, Hash};
use secp256k1::Error;
use secp256k1::{ecdsa, Message, PublicKey, Secp256k1, SecretKey};

type SecKey = [u8; 32];
type PubKey = [u8; 33];
type Signature = [u8; 64];

const TEST_SECKEY: SecKey = [
    59, 148, 11, 85, 134, 130, 61, 253, 2, 174, 59, 70, 27, 180, 51, 107, 94, 203, 174, 253, 102,
    39, 170, 146, 46, 252, 4, 143, 236, 12, 136, 28,
];

const TEST_PUBKEY: PubKey = [
    2, 29, 21, 35, 7, 198, 183, 43, 14, 208, 65, 139, 14, 112, 205, 128, 231, 245, 41, 91, 141,
    134, 245, 114, 45, 63, 82, 19, 251, 210, 57, 79, 54,
];

const TEST_SIGNATURE: Signature = [
    12, 4, 34, 223, 125, 111, 38, 168, 214, 37, 2, 54, 6, 11, 138, 205, 81, 79, 164, 232, 210, 96,
    255, 60, 50, 195, 170, 212, 182, 180, 112, 55, 110, 15, 90, 39, 225, 78, 71, 173, 50, 141, 1,
    195, 216, 164, 185, 105, 254, 186, 176, 110, 162, 108, 132, 202, 161, 251, 225, 119, 157, 98,
    167, 133,
];

const TEST_WRONG_SIGNATURE: Signature = [
    0, 4, 34, 223, 125, 111, 38, 168, 214, 37, 2, 54, 6, 11, 138, 205, 81, 79, 164, 232, 210, 96,
    255, 60, 50, 195, 170, 212, 182, 180, 112, 55, 110, 15, 90, 39, 225, 78, 71, 173, 50, 141, 1,
    195, 216, 164, 185, 105, 254, 186, 176, 110, 162, 108, 132, 202, 161, 251, 225, 119, 157, 98,
    167, 133,
];

static TEST_MESSAGE: &str = "This is some message";

fn verify(msg: &[u8], sig: Signature, pubkey: PubKey) -> core::result::Result<bool, Error> {
    let secp = Secp256k1::new();
    let msg = sha256::Hash::hash(msg);
    let msg = Message::from_slice(&msg)?;
    let sig = ecdsa::Signature::from_compact(&sig)?;
    let pubkey = PublicKey::from_slice(&pubkey)?;

    Ok(secp.verify_ecdsa(&msg, &sig, &pubkey).is_ok())
}

fn sign(msg: &[u8], seckey: SecKey) -> core::result::Result<Signature, Error> {
    let secp = Secp256k1::new();
    let msg = sha256::Hash::hash(msg);
    let msg = Message::from_slice(&msg)?;
    let seckey = SecretKey::from_slice(&seckey)?;
    Ok(secp.sign_ecdsa(&msg, &seckey).serialize_compact())
}

fn test_rust_sign_and_verify() {
    let signature = sign(TEST_MESSAGE.as_bytes(), TEST_SECKEY).unwrap();
    assert!(verify(TEST_MESSAGE.as_bytes(), signature, TEST_PUBKEY).unwrap());
    assert!(verify(TEST_MESSAGE.as_bytes(), TEST_SIGNATURE, TEST_PUBKEY).unwrap());
    assert!(!verify(TEST_MESSAGE.as_bytes(), TEST_WRONG_SIGNATURE, TEST_PUBKEY).unwrap());
}

fn test_lua_sign_and_verify() -> Result<()> {
    // You can create a new Lua state with `Lua::new()`.  This loads the default Lua std library
    // *without* the debug library.  You can get more control over this with the other
    // `Lua::xxx_new_xxx` functions.
    let lua = Lua::new();

    // In order to interact with Lua values at all, you must do so inside a callback given to the
    // `Lua::context` method.  This provides some extra safety and allows the rlua API to avoid some
    // extra runtime checks.
    lua.context(|lua_ctx| {
        // You can get and set global variables.  Notice that the globals table here is a permanent
        // reference to _G, and it is mutated behind the scenes as Lua code is loaded.  This API is
        // based heavily around sharing and internal mutation (just like Lua itself).

        let globals = lua_ctx.globals();

        globals.set("message", TEST_MESSAGE)?;
        globals.set("seckey", TEST_SECKEY)?;
        globals.set("pubkey", TEST_PUBKEY)?;
        globals.set("signature", TEST_SIGNATURE)?;
        globals.set("wrong_signature", TEST_WRONG_SIGNATURE)?;

        Ok(())
    })?;

    lua.context(|lua_ctx| {
        // The Lua state lives inside the top-level `Lua` value, and all state changes persist
        // between `Lua::context` calls.  This is another table reference in another context call,
        // but it refers to the same table _G.

        let globals = lua_ctx.globals();

        assert_eq!(globals.get::<_, String>("message")?, TEST_MESSAGE);
        assert_eq!(globals.get::<_, SecKey>("seckey")?, TEST_SECKEY);
        assert_eq!(globals.get::<_, PubKey>("pubkey")?, TEST_PUBKEY);
        assert_eq!(globals.get::<_, Signature>("signature")?, TEST_SIGNATURE);
        assert_eq!(
            globals.get::<_, Signature>("wrong_signature")?,
            TEST_WRONG_SIGNATURE
        );

        Ok(())
    })?;

    lua.context(|lua_ctx| {
        let globals = lua_ctx.globals();

        let sign_function = lua_ctx.create_function(|_, (msg, seckey): (String, SecKey)| {
            Ok(sign(msg.as_bytes(), seckey).ok())
        })?;
        globals.set("sign", sign_function)?;

        let verify_function =
            lua_ctx.create_function(|_, (msg, sig, pubkey): (String, Signature, PubKey)| {
                let result = verify(msg.as_bytes(), sig, pubkey);
                Ok(result.ok())
            })?;
        globals.set("verify", verify_function)?;

        dbg!(lua_ctx
            .load(r#"sign(message, seckey)"#)
            .eval::<Option<Signature>>()?,);

        assert_eq!(lua_ctx
            .load(r#"verify(message, signature, pubkey)"#)
            .eval::<Option<bool>>()?, Some(true));

        assert_eq!(lua_ctx
            .load(r#"verify(message, wrong_signature, pubkey)"#)
            .eval::<Option<bool>>()?, Some(false));

        assert_eq!(lua_ctx
            .load(r#"signature = sign(message, seckey); return signature and verify(message, signature, pubkey)"#)
            .eval::<Option<bool>>()?, Some(true));

        Ok(())
    })
}

fn main() {
    test_rust_sign_and_verify();
    assert!(test_lua_sign_and_verify().is_ok());
}

use rand::Rng;
use base32;
use sha1::Sha1;
use hmac::{Hmac, Mac};
use pad::{PadStr, Alignment};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    // let secret = generate_secret();
    let secret = "GYVPZJQQ4VBK7K64AILB2NF3BZAG7CLL"; // NOTE: testing
    // otpauth://totp/Rustapp?secret=GYVPZJQQ4VBK7K64AILB2NF3BZAG7CLL&issuer=berna.dev
    let secbase = base32::decode(base32::Alphabet::RFC4648 {padding: false}, secret).unwrap();

    // Step 1: Create hmac value
    // Get time
    let now = SystemTime::now().duration_since(UNIX_EPOCH)
        .expect("Time went backwards!");
    let mut time = now.as_millis() / 30000;

    let mut buffer: [u8; 8] = [0; 8];
    for i in 0..8 {
        buffer[7 - i] = (time & 0xff) as u8;
        time = time >> 8;
    }

    type HmacSha1 = Hmac<Sha1>;
    let mut mac = HmacSha1::new_varkey(&secbase)
        .expect("HMAC can take key of any size");

    mac.input(&buffer);
    
    let result = mac.result();
    let hmac_value = result.code();

    // Step 2: Dynamic truncation
    let offset = (hmac_value[19] & 0xf) as usize;
    let truncated_hash = ((hmac_value[offset] & 0x7f) as u32) << 24
        | ((hmac_value[offset + 1] & 0xff) as u32) << 16
        | ((hmac_value[offset + 2] & 0xff) as u32) << 8
        | ((hmac_value[offset + 3] & 0xff) as u32);
    
    // Step 3: Compute hotp value
    let hotp_value = truncated_hash % 10_u32.pow(6);
    let code = hotp_value.to_string().pad(6, '0', Alignment::Right, true);
    println!("Code: {}", code);
}

fn generate_secret() -> String {
    let alphabet = base32::Alphabet::RFC4648{padding: false};
    let random_buffer = rand::thread_rng().gen::<[u8; 20]>();
    
    base32::encode(alphabet, &random_buffer)
}
use wasm_bindgen::prelude::*;

/// Return only the score; feedback and match serialization are not part of the ABI.
#[wasm_bindgen]
pub fn password_score(password: &str, context: Vec<String>) -> u8 {
    let inputs: Vec<&str> = context.iter().map(String::as_str).collect();
    zxcvbn::zxcvbn(password, &inputs).score().into()
}

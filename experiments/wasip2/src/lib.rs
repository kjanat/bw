wit_bindgen::generate!({ world: "scorer" });

struct Scorer;

impl Guest for Scorer {
    fn score(password: String, context: Vec<String>) -> u8 {
        let inputs: Vec<&str> = context.iter().map(String::as_str).collect();
        zxcvbn::zxcvbn(&password, &inputs).score().into()
    }
}

export!(Scorer);

use serde_derive::{Deserialize, Serialize};
use std::fs::{File};
use std::io::Read;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub admil_login: String,
    pub admil_password: String,
}

impl Config {
    // Фабрика
    pub fn new(file_path: &str) -> Config {
        let mut file = match File::open(file_path) {
            Ok(f) => f,
            Err(e) => panic!("no such file {} exception:{}", file_path, e)
        };
        let mut str_val = std::string::String::new();
        match file.read_to_string(&mut str_val) {
            Ok(s) => s,
            Err(e) => panic!("Error Reading file: {}", e)
        };
        toml::from_str(&str_val).unwrap()
    }
}

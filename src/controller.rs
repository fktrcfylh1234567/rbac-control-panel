use anyhow::anyhow;
use crate::Config;
use lazy_static::lazy_static;
use rusqlite::{Connection, params};
use uuid::Uuid;
use serde_derive::{Serialize, Deserialize};
use serde_rusqlite::from_rows;

lazy_static! {
    pub static ref CONTROLLER: Controller = Controller::new();
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Role {
    ADMIN,
    USER,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Fingerprint {
    pub device_id: String,
    pub webdriver: bool,
    pub dev_tools: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthRequest {
    pub login: String,
    pub password: String,
    pub fingerprint: Fingerprint,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthResponse {
    pub token: String,
    pub role: Role,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RegistrationRequest {
    pub login: String,
    pub password: String,
    pub admin: bool,
    pub fingerprint: Fingerprint,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SystemInfo {
    pub cpu: String,
    pub temp: String,
    pub device: String,
    pub distro: String,
    pub environment: String,
    pub gpu: String,
    pub hostname: String,
    pub kernel: String,
    pub memory: String,
}

#[derive(Debug)]
pub struct Controller {
    config: Config,
    db: parking_lot::Mutex<Connection>,
}

impl Controller {
    pub fn new() -> Controller {
        let config = Config::new("Config.toml");
        let db: parking_lot::Mutex<Connection> = parking_lot::Mutex::new(open_db().expect("Cannot open DB"));
        Controller {
            config,
            db,
        }
    }

    pub fn start(&self) {
        // в БД заносим админа из конфига (если его еще нет в БД)
        let conn = self.db.lock();
        let q = "SELECT login FROM users WHERE login = ?1";
        let mut stmt = conn.prepare(q).unwrap();
        stmt.raw_bind_parameter(1, self.config.admil_login.clone()).unwrap();
        let rows = stmt.raw_query();
        let res = from_rows::<String>(rows).flatten().collect::<Vec<String>>();
        if res.len() == 0 {
            conn.execute(
                "INSERT INTO users (login, password, admin) VALUES (?1, ?2, true)",
                params![self.config.admil_login, self.config.admil_password],
            ).expect("Не удалось создать учетную запись для администратора");
        }
    }

    pub fn check_auth(&self, token: &str, fp: Fingerprint) -> Option<Role> {
        if Self::calculate_risk(&fp) > 10 {
            return None;
        }

        let conn = self.db.lock();
        let q = "select users.admin as admin from tokens, users \
                       where tokens.token = ?1 and tokens.device_id = ?2 \
                       and users.login = tokens.login";
        let mut stmt = conn.prepare(q).unwrap();
        stmt.raw_bind_parameter(1, token).unwrap();
        stmt.raw_bind_parameter(2, fp.device_id).unwrap();
        let rows = stmt.raw_query();
        let role = match from_rows::<bool>(rows).flatten().next() {
            Some(true) => Role::ADMIN,
            Some(false) => Role::USER,
            None => return None,
        };
        Some(role)
    }

    pub fn log_in_with_password(&self, auth: AuthRequest) -> anyhow::Result<Option<AuthResponse>> {
        if Self::calculate_risk(&auth.fingerprint) > 10 {
            return Ok(None);
        }

        let role = {
            let conn = self.db.lock();
            let q = "SELECT login, admin FROM users WHERE login = ?1 and password = ?2";
            let mut stmt = conn.prepare(q)?;
            stmt.raw_bind_parameter(1, auth.login.clone())?;
            stmt.raw_bind_parameter(2, auth.password)?;
            let rows = stmt.raw_query();
            let r = match from_rows::<(String, bool)>(rows).flatten().next() {
                Some((_login, true)) => Role::ADMIN,
                Some((_login, false)) => Role::USER,
                None => return Ok(None),
            };
            r
        };
        let res = AuthResponse {
            token: self.generate_token(auth.login, auth.fingerprint.device_id),
            role,
        };
        println!("{:?}", res);
        Ok(Some(res))
    }

    pub fn create_user(&self, login: String, password: String, admin: bool) -> anyhow::Result<()> {
        let conn = self.db.lock();
        let q = "SELECT login FROM users WHERE login = ?1";
        let mut stmt = conn.prepare(q).unwrap();
        stmt.raw_bind_parameter(1, login.clone()).unwrap();
        let rows = stmt.raw_query();
        let res = from_rows::<String>(rows).flatten().collect::<Vec<String>>();
        if res.len() > 0 {
            return Err(anyhow!("Пользователь с таким логином уже существует"));
        }
        conn.execute(
            "INSERT INTO users (login, password, admin) VALUES (?1, ?2, ?3)",
            params![login, password, admin],
        )?;
        Ok(())
    }

    pub fn get_system_data(&self) -> SystemInfo {
        SystemInfo {
            cpu: nixinfo::cpu().unwrap_or("-".to_string()),
            temp: nixinfo::temp().unwrap_or("-".to_string()),
            device: nixinfo::device().unwrap_or("-".to_string()),
            distro: nixinfo::distro().unwrap_or("-".to_string()),
            environment: nixinfo::environment().unwrap_or("-".to_string()),
            gpu: nixinfo::gpu().unwrap_or("-".to_string()),
            hostname: nixinfo::hostname().unwrap_or("-".to_string()),
            kernel: nixinfo::kernel().unwrap_or("-".to_string()),
            memory: nixinfo::memory().unwrap_or("-".to_string()),
        }
    }

    fn generate_token(&self, login: String, device_id: String) -> String {
        let token = Uuid::new_v4().to_string();
        let conn = self.db.lock();
        let q = "SELECT login FROM tokens WHERE login = ?1 and device_id = ?2";
        let mut stmt = conn.prepare(q).unwrap();
        stmt.raw_bind_parameter(1, login.clone()).unwrap();
        stmt.raw_bind_parameter(2, device_id.clone()).unwrap();
        let rows = stmt.raw_query();
        let res = from_rows::<String>(rows).flatten().collect::<Vec<String>>();
        if res.len() == 1 {
            // обновляем запись
            conn.execute(
                "UPDATE tokens SET token = ?1 WHERE login = ?2 and device_id = ?3",
                params![token, login, device_id],
            ).unwrap();
        } else {
            // добавляем запись
            conn.execute(
                "INSERT INTO tokens (login, token, device_id) VALUES (?1, ?2, ?3)",
                params![login, token, device_id],
            ).unwrap();
        }
        token
    }

    fn calculate_risk(fp: &Fingerprint) -> u8 {
        let mut risk = 0;

        if fp.webdriver {
            risk += 50;
        }

        if fp.dev_tools {
            risk += 50;
        }

        risk
    }
}

pub fn open_db() -> anyhow::Result<Connection> {
    let connection_db = Connection::open("os.db")?;
    connection_db.execute_batch(
        "BEGIN;
                 CREATE TABLE IF NOT EXISTS users (
                     login TEXT PRIMARY KEY,
                     password TEXT,
                     admin Bool
                     );
                 CREATE TABLE IF NOT EXISTS tokens (
                     token TEXT PRIMARY KEY,
                     login TEXT,
                     device_id TEXT);
                 COMMIT;",
    )?;
    Ok(connection_db)
}

pub mod crypt;
pub mod queries;

use dirs_next::data_dir;
use rusqlite::{Connection, Result};
use std::fs::create_dir_all;

pub fn init_db() -> Result<Connection> {
    let mut db_path =
        data_dir().unwrap_or_else(|| std::env::current_dir().expect("Cannot get current dir"));

    db_path.push("passman");

    create_dir_all(&db_path).expect("Failed to create config directory");

    db_path.push("database.db");

    let conn = Connection::open(&db_path).expect("Failed to open database");

    conn.execute(
        "CREATE TABLE IF NOT EXISTS passwords (
            id          TEXT PRIMARY KEY,
            service     TEXT NOT NULL,
            secret      TEXT NOT NULL,
            description TEXT
        )",
        [],
    )?;

    Ok(conn)
}

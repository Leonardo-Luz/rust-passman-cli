use crate::database::crypt::{decrypt, encrypt};
use rusqlite::{Connection, Error, Result, params};
use uuid::Uuid;

#[derive(Debug)]
pub struct Password {
    pub id: String,
    pub service: String,
    pub encrypted_secret: String,
    pub description: Option<String>,
}

impl Password {
    pub fn decrypted_secret(&self, master_pass: &str) -> Result<String, String> {
        decrypt(master_pass, &self.encrypted_secret)
    }
}

pub fn insert_password(
    conn: &Connection,
    master_pass: &str,
    service: &str,
    secret: &str,
    description: Option<&str>,
) -> Result<()> {
    let id = Uuid::new_v4().to_string();
    let encrypted = encrypt(master_pass, secret).map_err(|e| {
        Error::ToSqlConversionFailure(Box::new(std::io::Error::new(std::io::ErrorKind::Other, e)))
    })?;

    conn.execute(
        "INSERT INTO passwords (id, service, secret, description) VALUES (?1, ?2, ?3, ?4)",
        params![id, service, encrypted, description],
    )?;

    Ok(())
}

pub fn get_all_passwords(conn: &Connection) -> Result<Vec<Password>> {
    let mut stmt = conn.prepare("SELECT id, service, secret, description FROM passwords")?;
    let rows = stmt.query_map([], |row| {
        Ok(Password {
            id: row.get(0)?,
            service: row.get(1)?,
            encrypted_secret: row.get(2)?,
            description: row.get(3)?,
        })
    })?;

    rows.collect()
}

pub fn get_password_by_id(conn: &Connection, id: &str) -> Result<Vec<Password>> {
    let mut stmt =
        conn.prepare("SELECT id, service, secret, description FROM passwords WHERE id = ?1")?;
    let rows = stmt.query_map(params![id], |row| {
        Ok(Password {
            id: row.get(0)?,
            service: row.get(1)?,
            encrypted_secret: row.get(2)?,
            description: row.get(3)?,
        })
    })?;

    rows.collect()
}

pub fn get_password_by_service(conn: &Connection, service: &str) -> Result<Vec<Password>> {
    let mut stmt =
        conn.prepare("SELECT id, service, secret, description FROM passwords WHERE service = ?1")?;
    let rows = stmt.query_map(params![service], |row| {
        Ok(Password {
            id: row.get(0)?,
            service: row.get(1)?,
            encrypted_secret: row.get(2)?,
            description: row.get(3)?,
        })
    })?;

    rows.collect()
}

pub fn delete_password_by_id(conn: &Connection, id: &str) -> Result<usize> {
    conn.execute("DELETE FROM passwords WHERE id = ?1", params![id])
}

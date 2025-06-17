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

pub fn update_password_by_id(
    conn: &Connection,
    id: &str,
    secret: &str,
    new_master_pass: &str,
) -> Result<usize> {
    let encrypted = encrypt(new_master_pass, secret).map_err(|e| {
        Error::ToSqlConversionFailure(Box::new(std::io::Error::new(std::io::ErrorKind::Other, e)))
    })?;

    conn.execute(
        "UPDATE passwords SET secret = ?1 WHERE id = ?2",
        params![encrypted, id],
    )
}

pub fn save_backup(
    conn: &Connection,
    path: &str,
    master_password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut stmt = conn.prepare("SELECT id, service, secret, description FROM passwords")?;
    let entries = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,         // id
                row.get::<_, String>(1)?,         // service
                row.get::<_, String>(2)?,         // secret
                row.get::<_, Option<String>>(3)?, // description
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let plain_text = entries
        .iter()
        .map(|(id, service, secret, desc)| {
            format!(
                "{}|{}|{}|{}",
                id,
                service,
                secret,
                desc.clone().unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let encrypted = encrypt(master_password, &plain_text)?;
    std::fs::write(path, encrypted)?;
    Ok(())
}

pub fn load_backup(
    conn: &Connection,
    path: &str,
    master_password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let encrypted = std::fs::read_to_string(path)?;
    let decrypted = decrypt(master_password, &encrypted)?;

    for line in decrypted.lines() {
        let fields: Vec<&str> = line.splitn(4, '|').collect();
        if fields.len() >= 3 {
            let id = fields[0];
            let service = fields[1];
            let secret = fields[2];
            let description = if fields.len() == 4 && !fields[3].is_empty() {
                Some(fields[3])
            } else {
                None
            };

            conn.execute(
                "INSERT OR IGNORE INTO passwords (id, service, secret, description) VALUES (?1, ?2, ?3, ?4)",
                (&id, &service, &secret, &description),
            )?;
        }
    }

    Ok(())
}

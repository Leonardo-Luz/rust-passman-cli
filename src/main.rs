mod database;
use crate::database::init_db;
use crate::database::queries::{
    delete_password_by_id, get_all_passwords, get_password_by_id, get_password_by_service,
    insert_password,
};
use rpassword::prompt_password;

use clap::{ArgGroup, Parser, Subcommand};

use self::database::queries::update_password_by_id;

use rand::seq::SliceRandom;

#[derive(Parser)]
#[command(name = "passman", about = "Encrypted Password Manager CLI")]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Master password for encryption/decryption
    #[arg(short, long)]
    pub master_password: Option<String>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Add a new password entry
    #[command(group(
        ArgGroup::new("secret_input")
            .args(&["secret", "generate_secret"]),
    ))]
    Add {
        /// Name of the service
        #[arg(short, long)]
        service: String,

        /// Manually provide the secret or @filename to read from
        #[arg(short, long)]
        secret: Option<String>,

        /// Generate a secure random password instead
        #[arg(long = "generate-secret")]
        generate_secret: bool,

        /// Optional description of the entry
        #[arg(short, long)]
        description: Option<String>,
    },

    /// List all passwords (decrypted)
    List,

    /// Get password by ID or service name (decrypted)
    Get {
        /// Either "id" or "service"
        field: String,

        /// The value to search for (ID or service)
        value: String,
    },

    /// Delete password by ID
    Delete {
        #[arg(short, long)]
        id: String,
    },

    /// Update master password by ID
    Update {
        #[arg(short, long)]
        id: String,
    },
}

fn main() {
    let cli = Cli::parse();

    // Get master password: either from CLI or prompt
    let master_password = match cli.master_password {
        Some(pwd) => pwd,
        None => prompt_password("Enter master password: ").expect("Failed to read password"),
    };

    let conn = init_db().expect("Failed to open db");

    match &cli.command {
        Commands::Add {
            service,
            secret,
            generate_secret,
            description,
        } => {
            let final_secret = if *generate_secret {
                let pwd = generate_password(32);
                println!("Generated secret: {}", pwd);
                pwd
            } else {
                let temp_secret = match secret {
                    Some(pwd) => pwd,
                    None => &prompt_password("Enter secret: ").expect("Failed to read secret"),
                };

                if let Some(file_path) = temp_secret.strip_prefix('@') {
                    std::fs::read_to_string(file_path)
                        .expect("Failed to read secret file")
                        .trim_end()
                        .to_string()
                } else {
                    temp_secret.clone()
                }
            };

            insert_password(
                &conn,
                &master_password,
                &service,
                &final_secret,
                description.as_deref(),
            )
            .expect("Failed to insert password");

            println!("Password added for service '{}'.", service);
        }
        Commands::List => {
            let passwords = get_all_passwords(&conn).expect("Failed to get passwords");
            for pw in passwords {
                match pw.decrypted_secret(&master_password) {
                    Ok(secret) => {
                        println!("{} - {}: {}\n", pw.id, pw.service, secret);
                    }
                    Err(_e) => eprintln!("{} - {}: **********\n", pw.id, pw.service),
                }
            }
        }
        Commands::Get { field, value } => {
            let result = match field.as_str() {
                "id" => get_password_by_id(&conn, value),
                "service" => get_password_by_service(&conn, value),
                _ => {
                    eprintln!("Invalid field '{}'. Use 'id' or 'service'.", field);
                    return;
                }
            };

            match result {
                Ok(passwords) if !passwords.is_empty() => {
                    for pw in passwords {
                        match pw.decrypted_secret(&master_password) {
                            Ok(secret) => {
                                println!(
                                    "ID: {}\nService: {}\nPassword: {}",
                                    pw.id, pw.service, secret
                                );
                                if let Some(desc) = &pw.description {
                                    print!("Description:\n{}\n", desc);
                                }
                                println!();
                            }
                            Err(e) => {
                                eprintln!("Failed to decrypt password: {}", e);
                            }
                        }
                    }
                }
                Ok(_) => println!("No password found for {} = {}", field, value),
                Err(e) => eprintln!("Error querying password: {}", e),
            }
        }
        Commands::Delete { id } => {
            let result = get_password_by_id(&conn, id);
            match result {
                Ok(passwords) if !passwords.is_empty() => {
                    let pw = &passwords[0];

                    match pw.decrypted_secret(&master_password) {
                        Ok(_) => {
                            // Decryption succeeded — proceed to delete
                            match delete_password_by_id(&conn, id) {
                                Ok(deleted) if deleted > 0 => {
                                    println!("Password with ID {} deleted.", id)
                                }
                                Ok(_) => println!("No password found with ID {}.", id),
                                Err(e) => eprintln!("Error deleting password: {}", e),
                            }
                        }
                        Err(_) => {
                            eprintln!("Master password is incorrect. Cannot delete.");
                        }
                    }
                }
                Ok(_) => {
                    println!("No password found with ID {}.", id);
                }
                Err(e) => {
                    eprintln!("Error retrieving password: {}", e);
                }
            }
        }
        Commands::Update { id } => {
            let result = get_password_by_id(&conn, id);
            match result {
                Ok(passwords) if !passwords.is_empty() => {
                    let pw = &passwords[0];

                    match pw.decrypted_secret(&master_password) {
                        Ok(secret) => {
                            // Get new master password from prompt
                            let new_master_password =
                                prompt_password("Enter new master password: ")
                                    .expect("Failed to read password");

                            // Decryption succeeded — proceed to update
                            match update_password_by_id(&conn, id, &secret, &new_master_password) {
                                Ok(updated) if updated > 0 => {
                                    println!("Password with ID {} updated.", id)
                                }
                                Ok(_) => println!("No password found with ID {}.", id),
                                Err(e) => eprintln!("Error updating password: {}", e),
                            }
                        }
                        Err(_) => {
                            eprintln!("Master password is incorrect. Cannot update.");
                        }
                    }
                }
                Ok(_) => {
                    println!("No password found with ID {}.", id);
                }
                Err(e) => {
                    eprintln!("Error retrieving password: {}", e);
                }
            }
        }
    }
}

fn generate_password(length: usize) -> String {
    const LOWER: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
    const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
    const DIGITS: &[u8] = b"23456789";
    const SYMBOLS: &[u8] = b"!@#$^&*()-_+";

    let mut rng = rand::thread_rng();

    let mut password = vec![
        *LOWER.choose(&mut rng).unwrap() as char,
        *UPPER.choose(&mut rng).unwrap() as char,
        *DIGITS.choose(&mut rng).unwrap() as char,
        *SYMBOLS.choose(&mut rng).unwrap() as char,
    ];

    let all_chars: Vec<u8> = [LOWER, UPPER, DIGITS, SYMBOLS].concat();
    for _ in password.len()..length {
        password.push(*all_chars.choose(&mut rng).unwrap() as char);
    }

    password.shuffle(&mut rng);
    password.into_iter().collect()
}

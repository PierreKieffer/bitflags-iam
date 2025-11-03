use uuid::Uuid;
use bcrypt::{hash, DEFAULT_COST};

#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub name: String,
    pub email: String,
    pub password_hash: String,
    pub permissions: u64,
}

impl User {
    pub fn new(name: String, email: String, password: String, permissions: u64) -> Result<Self, String> {
        let password_hash = hash(password, DEFAULT_COST)
            .map_err(|e| format!("Failed to hash password: {}", e))?;

        Ok(Self {
            id: Uuid::new_v4().to_string(),
            name,
            email,
            password_hash,
            permissions,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Permission {
    pub name: String,
    pub value: u64,
}

impl Permission {
    pub fn new(name: String, value: u64) -> Self {
        Self { name, value }
    }
}
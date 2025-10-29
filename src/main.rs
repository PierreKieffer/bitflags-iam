use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tonic::{transport::Server, Request, Response, Status};
use uuid::Uuid;
use bcrypt::{hash, DEFAULT_COST};

pub mod iam {
    tonic::include_proto!("iam");
}

use iam::iam_service_server::{IamService, IamServiceServer};
use iam::*;

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

pub struct IamManager {
    users: Arc<RwLock<HashMap<String, User>>>,
    permissions: Arc<RwLock<HashMap<String, Permission>>>,
}

impl IamManager {
    pub fn new() -> Self {
        let mut permissions = HashMap::new();

        // Default permissions (using 64-bit values)
        permissions.insert("READ".to_string(), Permission {
            name: "READ".to_string(),
            value: 1 << 0,
        });
        permissions.insert("WRITE".to_string(), Permission {
            name: "WRITE".to_string(),
            value: 1 << 1,
        });
        permissions.insert("EXECUTE".to_string(), Permission {
            name: "EXECUTE".to_string(),
            value: 1 << 2,
        });
        permissions.insert("DELETE".to_string(), Permission {
            name: "DELETE".to_string(),
            value: 1 << 3,
        });

        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
            permissions: Arc::new(RwLock::new(permissions)),
        }
    }

    pub fn create_user(&self, name: String, email: String, password: String, permission_names: Vec<String>) -> Result<User, String> {
        let permissions_bits = self.permission_names_to_bits(&permission_names)?;
        let user = User::new(name, email, password, permissions_bits)?;

        // .write() - demande un verrou exclusif en écriture
        // Retourne Result<RwLockWriteGuard, PoisonError>
        // .map_err() - convertit l'erreur PoisonError en String
        // ? - propage l'erreur si le verrou échoue
        let mut users = self.users.write().map_err(|_| "Failed to acquire write lock")?;
        users.insert(user.id.clone(), user.clone());

        Ok(user)
    }

    pub fn get_user(&self, user_id: &str) -> Option<User> {
        let users = self.users.read().ok()?;
        users.get(user_id).cloned()
    }

    pub fn get_user_with_permission_names(&self, user_id: &str) -> Result<Option<(User, Vec<String>)>, String> {
        let users = self.users.read().map_err(|_| "Failed to acquire read lock")?;

        if let Some(user) = users.get(user_id) {
            let permission_names = self.bits_to_permission_names(user.permissions)?;
            Ok(Some((user.clone(), permission_names)))
        } else {
            Ok(None)
        }
    }

    pub fn update_user_permissions(&self, user_id: &str, permission_names: Vec<String>) -> Result<User, String> {
        let permissions_bits = self.permission_names_to_bits(&permission_names)?;
        let mut users = self.users.write().map_err(|_| "Failed to acquire write lock")?;

        if let Some(user) = users.get_mut(user_id) {
            user.permissions = permissions_bits;
            Ok(user.clone())
        } else {
            Err("User not found".to_string())
        }
    }

    pub fn add_permission(&self, name: String) -> Result<Permission, String> {
        let mut permissions = self.permissions.write().map_err(|_| "Failed to acquire write lock")?;

        if permissions.contains_key(&name) {
            return Err("Permission already exists".to_string());
        }

        // Find next available bit position
        // Extrait toutes les valeurs de bits des permissions existantes
        // Ex: [1, 2, 4, 8] pour READ, WRITE, EXECUTE, DELETE
        let mut used_values = permissions.values().map(|p| p.value).collect::<Vec<_>>();
        used_values.sort();

        let mut next_value = 1u64;
        for &used_value in &used_values {
            if next_value == used_value {
                // Ce bit est occupé, passe au suivant (x2 = décalage d'un bit)
                next_value = next_value.checked_mul(2).ok_or("No more permission slots available")?;
            } else {
                break;
            }
        }

        let permission = Permission {
            name: name.clone(),
            value: next_value
        };

        permissions.insert(name, permission.clone());
        Ok(permission)
    }

    pub fn remove_permission(&self, name: &str) -> Result<(), String> {
        // TODO: Peut entrainer incohérence lors de nouvelles créations de permissions -> Supprimer la permission sur les users concernés
        let mut permissions = self.permissions.write().map_err(|_| "Failed to acquire write lock")?;

        if permissions.remove(name).is_some() {
            Ok(())
        } else {
            Err("Permission not found".to_string())
        }
    }

    pub fn list_permissions(&self) -> Result<Vec<Permission>, String> {
        let permissions = self.permissions.read().map_err(|_| "Failed to acquire read lock")?;
        let mut perms: Vec<Permission> = permissions.values().cloned().collect();
        perms.sort_by(|a, b| a.value.cmp(&b.value));
        Ok(perms)
    }

    pub fn check_permissions(&self, user_id: &str, required_permission_names: &[String]) -> Result<(bool, Vec<String>), String> {
        // Exemple complet
        // Utilisateur avec READ(1) + WRITE(2) = 3
        // Demande READ(1) + DELETE(8) = 9
        // required_bits = 9           // 1001
        // user.permissions = 3        // 0011
        // has_all = (3 & 9) == 9     // (0011 & 1001) == 1001 → 1 == 9 → false
        // missing_bits = 9 & !3      // 1001 & 1100 = 1000 (DELETE)

        // Résultat: (false, ["DELETE"])
        let users = self.users.read().map_err(|_| "Failed to acquire read lock")?;

        if let Some(user) = users.get(user_id) {
            let required_bits = self.permission_names_to_bits(required_permission_names)?;
            let has_all = (user.permissions & required_bits) == required_bits;

            // Find missing permissions
            let missing_bits = required_bits & !user.permissions;
            // ! = not bitwise pour inverser les bits
            // Exemple :
            // required_bits = 11          // 1011 (READ|WRITE|DELETE)
            // user.permissions = 3        // 0011 (READ|WRITE)

            // !user.permissions = ~3      // 1100 (tous les bits sauf READ/write)
            // missing_bits = 11 & ~3 = 8  // 1011 & 1100 = 1000 (DELETE manquant)
            let missing_permissions = if missing_bits == 0 {
                Vec::new()
            } else {
                self.bits_to_permission_names(missing_bits)?
            };

            Ok((has_all, missing_permissions))
        } else {
            Err("User not found".to_string())
        }
    }

    fn permission_names_to_bits(&self, names: &[String]) -> Result<u64, String> {
        let permissions = self.permissions.read().map_err(|_| "Failed to acquire read lock")?;
        let mut bits = 0u64;

        for name in names {
            if let Some(permission) = permissions.get(name) {
                bits |= permission.value;
            } else {
                return Err(format!("Permission '{}' not found", name));
            }
        }

        Ok(bits)
    }

    fn bits_to_permission_names(&self, bits: u64) -> Result<Vec<String>, String> {
        let permissions = self.permissions.read().map_err(|_| "Failed to acquire read lock")?;
        let mut names = Vec::new();

        for permission in permissions.values() {
            if (bits & permission.value) == permission.value {
                names.push(permission.name.clone());
            }
        }

        names.sort();
        Ok(names)
    }
}

#[tonic::async_trait]
impl IamService for IamManager {
    async fn create_user(
        &self,
        request: Request<CreateUserRequest>,
    ) -> Result<Response<CreateUserResponse>, Status> {
        let req = request.into_inner();

        match self.create_user(req.name, req.email, req.password, req.permissions) {
            Ok(user) => {
                let permission_names = self.bits_to_permission_names(user.permissions)
                    .unwrap_or_else(|_| Vec::new());

                let response = CreateUserResponse {
                    success: true,
                    message: "User created successfully".to_string(),
                    user: Some(iam::User {
                        id: user.id,
                        name: user.name,
                        email: user.email,
                        permissions: permission_names,
                    }),
                };
                Ok(Response::new(response))
            }
            Err(e) => {
                let response = CreateUserResponse {
                    success: false,
                    message: e,
                    user: None,
                };
                Ok(Response::new(response))
            }
        }
    }

    async fn get_user(
        &self,
        request: Request<GetUserRequest>,
    ) -> Result<Response<GetUserResponse>, Status> {
        let req = request.into_inner();

        match self.get_user_with_permission_names(&req.user_id) {
            Ok(Some((user, permission_names))) => {
                let response = GetUserResponse {
                    success: true,
                    message: "User found".to_string(),
                    user: Some(iam::User {
                        id: user.id,
                        name: user.name,
                        email: user.email,
                        permissions: permission_names,
                    }),
                };
                Ok(Response::new(response))
            }
            Ok(None) => {
                let response = GetUserResponse {
                    success: false,
                    message: "User not found".to_string(),
                    user: None,
                };
                Ok(Response::new(response))
            }
            Err(e) => {
                let response = GetUserResponse {
                    success: false,
                    message: e,
                    user: None,
                };
                Ok(Response::new(response))
            }
        }
    }

    async fn add_permission(
        &self,
        request: Request<AddPermissionRequest>,
    ) -> Result<Response<AddPermissionResponse>, Status> {
        let req = request.into_inner();

        match self.add_permission(req.permission_name) {
            Ok(permission) => {
                let response = AddPermissionResponse {
                    success: true,
                    message: "Permission added successfully".to_string(),
                    permission: Some(iam::Permission {
                        name: permission.name,
                        value: permission.value,
                    }),
                };
                Ok(Response::new(response))
            }
            Err(e) => {
                let response = AddPermissionResponse {
                    success: false,
                    message: e,
                    permission: None,
                };
                Ok(Response::new(response))
            }
        }
    }

    async fn remove_permission(
        &self,
        request: Request<RemovePermissionRequest>,
    ) -> Result<Response<RemovePermissionResponse>, Status> {
        let req = request.into_inner();

        match self.remove_permission(&req.permission_name) {
            Ok(()) => {
                let response = RemovePermissionResponse {
                    success: true,
                    message: "Permission removed successfully".to_string(),
                };
                Ok(Response::new(response))
            }
            Err(e) => {
                let response = RemovePermissionResponse {
                    success: false,
                    message: e,
                };
                Ok(Response::new(response))
            }
        }
    }

    async fn list_permissions(
        &self,
        _request: Request<ListPermissionsRequest>,
    ) -> Result<Response<ListPermissionsResponse>, Status> {
        match self.list_permissions() {
            Ok(permissions) => {
                let response = ListPermissionsResponse {
                    success: true,
                    message: "Permissions listed successfully".to_string(),
                    permissions: permissions.into_iter().map(|p| iam::Permission {
                        name: p.name,
                        value: p.value,
                    }).collect(),
                };
                Ok(Response::new(response))
            }
            Err(e) => {
                let response = ListPermissionsResponse {
                    success: false,
                    message: e,
                    permissions: Vec::new(),
                };
                Ok(Response::new(response))
            }
        }
    }

    async fn update_user_permissions(
        &self,
        request: Request<UpdateUserPermissionsRequest>,
    ) -> Result<Response<UpdateUserPermissionsResponse>, Status> {
        let req = request.into_inner();

        match self.update_user_permissions(&req.user_id, req.permissions) {
            Ok(user) => {
                let permission_names = self.bits_to_permission_names(user.permissions)
                    .unwrap_or_else(|_| Vec::new());

                let response = UpdateUserPermissionsResponse {
                    success: true,
                    message: "User permissions updated successfully".to_string(),
                    user: Some(iam::User {
                        id: user.id,
                        name: user.name,
                        email: user.email,
                        permissions: permission_names,
                    }),
                };
                Ok(Response::new(response))
            }
            Err(e) => {
                let response = UpdateUserPermissionsResponse {
                    success: false,
                    message: e,
                    user: None,
                };
                Ok(Response::new(response))
            }
        }
    }

    async fn check_permissions(
        &self,
        request: Request<CheckPermissionsRequest>,
    ) -> Result<Response<CheckPermissionsResponse>, Status> {
        let req = request.into_inner();

        match self.check_permissions(&req.user_id, &req.required_permissions) {
            Ok((has_permissions, missing_permissions)) => {
                let message = if has_permissions {
                    "User has all required permissions".to_string()
                } else {
                    format!("User is missing permissions: {}", missing_permissions.join(", "))
                };

                let response = CheckPermissionsResponse {
                    success: true,
                    has_permissions,
                    message,
                    missing_permissions,
                };
                Ok(Response::new(response))
            }
            Err(e) => {
                let response = CheckPermissionsResponse {
                    success: false,
                    has_permissions: false,
                    message: e,
                    missing_permissions: Vec::new(),
                };
                Ok(Response::new(response))
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let iam_manager = IamManager::new();

    println!("IAM gRPC Server listening on {}", addr);

    Server::builder()
        .add_service(IamServiceServer::new(iam_manager))
        .serve(addr)
        .await?;

    Ok(())
}


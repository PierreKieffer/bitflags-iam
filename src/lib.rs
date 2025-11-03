pub mod models;
pub mod utils;
pub mod iam_manager;

pub mod iam {
    tonic::include_proto!("iam");
}

pub use models::{User, Permission};
pub use utils::{permission_names_to_bits, bits_to_permission_names, find_next_available_bit};
pub use iam_manager::IamManager;
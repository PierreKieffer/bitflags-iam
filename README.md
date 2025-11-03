# Bitflags IAM Service (gRPC)

**Educational Project**: This is an educational implementation of an Identity and Access Management (IAM) service developed in Rust using gRPC and bitflags for high-performance permission management. It demonstrates concepts of permissions systems, bitwise operations, and gRPC service development.

## Project Structure

```
bitflags-iam/
├── proto/
│   └── iam.proto           # Protobuf schema defining the gRPC API
├── src/
│   ├── main.rs             # gRPC IAM server
│   ├── client.rs           # Example client and tests
│   ├── iam_manager.rs      # Core IAM business logic and permission management
│   ├── lib.rs              # Library entry point and public exports
│   ├── models.rs           # Data structures and models
│   └── utils.rs            # Utility functions and helpers
├── build.rs                # Protobuf compilation script
├── Cargo.toml              # Dependencies and project configuration
├── Cargo.lock              # Dependency version lock
└── README.md               # This documentation
```

## Features

### User Management
- **User creation** with name, email, and password
- **Secure password storage** with bcrypt hashing
- **In-memory storage** via HashMap (no database for now)
- **User information retrieval** by ID

### Permission Management (64-bit)
- **Default permissions**: READ (1), WRITE (2), EXECUTE (4), DELETE (8)
- **Add/remove** custom permissions
- **Bitwise operations** for high-performance verification
- **Extensibility** up to 64 simultaneous permissions

### Permission Checking
- **Fast access control** based on bitwise operations
- **Composite verification**: checks if user has ALL required permissions
- **Error handling** with detailed messages

### Permission Modification
- **Real-time** user permission updates
- **Dynamic** system permission management
- **Thread-safe** with RwLock

## Build and Run

### Prerequisites
- Rust (version 1.70+)
- Cargo

### Install dependencies
```bash
cargo build
```

### Start the server
```bash
cargo run --bin server
```
The server starts on `[::1]:50051` (IPv6 localhost)

### Test with example client
```bash
# In another terminal
cargo run --bin client
```

### Release build
```bash
cargo build --release
```

### Compilation tests
```bash
cargo check
```

## API Documentation

### Client setup

```rust
use iam::iam_service_client::IamServiceClient;

let mut client = IamServiceClient::connect("http://[::1]:50051").await?;
```

### User Management

#### Create a user
```rust
let request = CreateUserRequest {
    name: "John Doe".to_string(),
    email: "john@example.com".to_string(),
    password: "secure_password".to_string(),
    permissions: vec!["READ".to_string(), "WRITE".to_string()],
};

let response = client.create_user(Request::new(request)).await?;
```

**Response:**
```rust
CreateUserResponse {
    success: bool,
    message: String,
    user: Option<User> // Contains id, name, email, permissions (Vec<String>)
}
```

#### Get a user
```rust
let request = GetUserRequest {
    user_id: "user_uuid".to_string(),
};

let response = client.get_user(Request::new(request)).await?;
```

**Response:**
```rust
GetUserResponse {
    success: bool,
    message: String,
    user: Option<User> // User.permissions is Vec<String>
}
```

### Permission Management

#### List all permissions
```rust
let request = ListPermissionsRequest {};

let response = client.list_permissions(Request::new(request)).await?;
```

**Response:**
```rust
ListPermissionsResponse {
    success: bool,
    message: String,
    permissions: Vec<Permission> // Permission { name: String, value: u64 }
}
```

#### Add a permission
```rust
let request = AddPermissionRequest {
    permission_name: "ADMIN".to_string(),
};

let response = client.add_permission(Request::new(request)).await?;
```

**Response:**
```rust
AddPermissionResponse {
    success: bool,
    message: String,
    permission: Option<Permission> // Contains name and auto-assigned bit value
}
```

#### Remove a permission
```rust
let request = RemovePermissionRequest {
    permission_name: "ADMIN".to_string(),
};

let response = client.remove_permission(Request::new(request)).await?;
```

#### Update user permissions
```rust
let request = UpdateUserPermissionsRequest {
    user_id: "user_uuid".to_string(),
    permissions: vec!["READ".to_string(), "WRITE".to_string(), "ADMIN".to_string()],
};

let response = client.update_user_permissions(Request::new(request)).await?;
```

### Permission Checking

#### Check multiple permissions
```rust
let request = CheckPermissionsRequest {
    user_id: "user_uuid".to_string(),
    required_permissions: vec!["READ".to_string(), "WRITE".to_string()],
};

let response = client.check_permissions(Request::new(request)).await?;
```

**Response:**
```rust
CheckPermissionsResponse {
    success: bool,
    has_permissions: bool, // true if user has ALL required permissions
    message: String,
    missing_permissions: Vec<String> // List of missing permissions if any
}
```

## Permission System (Bitflags)

The service uses 64-bit bitflags internally for high-performance permission checking, but clients work with human-readable permission names.

### Default permissions
| Permission | Value | Binary |
|------------|-------|--------|
| READ       | 1     | 0001   |
| WRITE      | 2     | 0010   |
| EXECUTE    | 4     | 0100   |
| DELETE     | 8     | 1000   |

### Client API (Recommended)
```rust
// Create user with named permissions
let permissions = vec!["READ".to_string(), "WRITE".to_string()];

// Check multiple permissions at once
let required = vec!["READ".to_string(), "ADMIN".to_string()];

// Add new permission (automatically assigns bit value)
let request = AddPermissionRequest {
    permission_name: "ADMIN".to_string(),
};
```

### Internal bitwise operations
The service automatically handles the conversion between permission names and bit values:
- Permission names → bit values for internal storage
- Bit values → permission names for client responses
- Bitwise AND operations for permission checking

### Permission checking logic
```rust
// The service verifies that users have ALL required permissions
// Internally: (user_permissions & required_permissions) == required_permissions
```

### Auto-assigned bit values
When adding new permissions, the service automatically finds the next available bit position:
- First available: 16 (1 << 4)
- Next: 32 (1 << 5)
- Up to: 1 << 63 (64th bit)

## Common Error Messages

- `"User not found"` - User ID doesn't exist
- `"Permission already exists"` - Attempt to add existing permission
- `"Permission not found"` - Attempt to remove non-existent permission
- `"Failed to hash password"` - Error during password hashing
- `"Failed to acquire write lock"` - Concurrency error (rare)

## Development

### Modify protobuf schema
1. Edit `proto/iam.proto`
2. Rebuild: `cargo build`
3. Rust bindings are generated automatically

### Add new features
- gRPC handlers are in `src/main.rs`
- Business logic is in `IamManager`
- Thread-safe by design with `Arc<RwLock<>>`

### Performance
- **In-memory storage**: O(1) access for users
- **Bitwise operations**: O(1) permission checking
- **Thread-safe**: Concurrency support with RwLock

## Complete Example

See `src/client.rs` for a complete usage example demonstrating:
- **Permission listing**: View all available permissions
- **User creation**: Create users with named permissions
- **Permission checking**: Check multiple permissions with detailed feedback
- **Dynamic permissions**: Add new permissions at runtime
- **Permission updates**: Modify user permissions
- **Error handling**: Handle non-existent permissions gracefully

### Key improvements over bit-based API:
- **Human-readable**: Use `"ADMIN"` instead of `16`
- **Multiple permissions**: Check `["READ", "WRITE", "ADMIN"]` at once
- **Auto-assignment**: Service assigns bit values automatically
- **Missing permissions**: Get detailed list of what's missing
- **Discovery**: List all available permissions

### Example client usage:
```bash
# Start server
cargo run --bin server

# Run example client (in another terminal)
cargo run --bin client
```

The client will demonstrate all features including creating a user with `["READ", "WRITE"]` permissions, adding an `"ADMIN"` permission, checking various permission combinations, and showing detailed error messages.

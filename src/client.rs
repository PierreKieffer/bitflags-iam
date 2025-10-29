use tonic::Request;

pub mod iam {
    tonic::include_proto!("iam");
}

use iam::iam_service_client::IamServiceClient;
use iam::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = IamServiceClient::connect("http://[::1]:50051").await?;

    println!("Connected to IAM gRPC server");

    // Test 0: List available permissions
    println!("\n=== Listing available permissions ===");
    let list_request = Request::new(ListPermissionsRequest {});
    let response = client.list_permissions(list_request).await?;
    let list_response = response.into_inner();

    if list_response.success {
        println!("Available permissions:");
        for permission in &list_response.permissions {
            println!("  - {} (value: {})", permission.name, permission.value);
        }
    } else {
        println!("✗ Failed to list permissions: {}", list_response.message);
    }

    // Test 1: Create a user with permission names
    println!("\n=== Creating a user ===");
    let create_request = Request::new(CreateUserRequest {
        name: "John Doe".to_string(),
        email: "john@example.com".to_string(),
        password: "secure_password".to_string(),
        permissions: vec!["READ".to_string(), "WRITE".to_string()],
    });

    let response = client.create_user(create_request).await?;
    let create_response = response.into_inner();

    if create_response.success {
        println!("✓ User created successfully!");
        let user = create_response.user.unwrap();
        println!("  ID: {}", user.id);
        println!("  Name: {}", user.name);
        println!("  Email: {}", user.email);
        println!("  Permissions: {:?}", user.permissions);

        let user_id = user.id.clone();

        // Test 2: Check permissions with permission names
        println!("\n=== Checking permissions ===");

        // Check READ and WRITE permissions (should pass)
        let check_request = Request::new(CheckPermissionsRequest {
            user_id: user_id.clone(),
            required_permissions: vec!["READ".to_string(), "WRITE".to_string()],
        });

        let response = client.check_permissions(check_request).await?;
        let check_response = response.into_inner();

        if check_response.success && check_response.has_permissions {
            println!("User has READ and WRITE permissions");
        } else {
            println!("User does not have required permissions: {:?}", check_response.missing_permissions);
        }

        // Check EXECUTE permission (should fail)
        let check_request = Request::new(CheckPermissionsRequest {
            user_id: user_id.clone(),
            required_permissions: vec!["EXECUTE".to_string()],
        });

        let response = client.check_permissions(check_request).await?;
        let check_response = response.into_inner();

        if check_response.success && check_response.has_permissions {
            println!("User has EXECUTE permission");
        } else {
            println!("User does not have EXECUTE permission (expected)");
            println!("  Missing: {:?}", check_response.missing_permissions);
        }

        // Test 3: Add a new permission
        println!("\n=== Adding a new permission ===");
        let add_perm_request = Request::new(AddPermissionRequest {
            permission_name: "ADMIN".to_string(),
        });

        let response = client.add_permission(add_perm_request).await?;
        let add_perm_response = response.into_inner();

        if add_perm_response.success {
            let permission = add_perm_response.permission.unwrap();
            println!("ADMIN permission added successfully!");
            println!("  Name: {}", permission.name);
            println!("  Value: {}", permission.value);
        } else {
            println!("Failed to add ADMIN permission: {}", add_perm_response.message);
        }

        // Test 4: Update user permissions
        println!("\n=== Updating user permissions ===");
        let update_request = Request::new(UpdateUserPermissionsRequest {
            user_id: user_id.clone(),
            permissions: vec!["READ".to_string(), "WRITE".to_string(), "EXECUTE".to_string(), "ADMIN".to_string()],
        });

        let response = client.update_user_permissions(update_request).await?;
        let update_response = response.into_inner();

        if update_response.success {
            println!("User permissions updated successfully!");
            let updated_user = update_response.user.unwrap();
            println!("  New permissions: {:?}", updated_user.permissions);
        } else {
            println!("Failed to update permissions: {}", update_response.message);
        }

        // Test 5: Check multiple permissions (should now pass)
        println!("\n=== Checking multiple permissions ===");
        let check_request = Request::new(CheckPermissionsRequest {
            user_id: user_id.clone(),
            required_permissions: vec!["READ".to_string(), "EXECUTE".to_string(), "ADMIN".to_string()],
        });

        let response = client.check_permissions(check_request).await?;
        let check_response = response.into_inner();

        if check_response.success && check_response.has_permissions {
            println!("User has READ, EXECUTE, and ADMIN permissions");
        } else {
            println!("User is missing some permissions: {:?}", check_response.missing_permissions);
        }

        // Test 6: Get user info
        println!("\n=== Getting user info ===");
        let get_request = Request::new(GetUserRequest {
            user_id: user_id.clone(),
        });

        let response = client.get_user(get_request).await?;
        let get_response = response.into_inner();

        if get_response.success {
            let user = get_response.user.unwrap();
            println!("User found:");
            println!("  ID: {}", user.id);
            println!("  Name: {}", user.name);
            println!("  Email: {}", user.email);
            println!("  Permissions: {:?}", user.permissions);
        }

        // Test 7: List permissions again to see the new ADMIN permission
        println!("\n=== Listing permissions again ===");
        let list_request = Request::new(ListPermissionsRequest {});
        let response = client.list_permissions(list_request).await?;
        let list_response = response.into_inner();

        if list_response.success {
            println!("All available permissions:");
            for permission in &list_response.permissions {
                println!("  - {} (value: {})", permission.name, permission.value);
            }
        }

        // Test 8: Try to check a non-existent permission
        println!("\n=== Checking non-existent permission ===");
        let check_request = Request::new(CheckPermissionsRequest {
            user_id: user_id.clone(),
            required_permissions: vec!["NONEXISTENT".to_string()],
        });

        let response = client.check_permissions(check_request).await?;
        let check_response = response.into_inner();

        if !check_response.success {
            println!("Correctly handled non-existent permission: {}", check_response.message);
        } else {
            println!("Should have failed for non-existent permission");
        }

    } else {
        println!("Failed to create user: {}", create_response.message);
    }

    Ok(())
}

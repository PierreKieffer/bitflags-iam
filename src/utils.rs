use std::collections::HashMap;
use crate::models::Permission;

pub fn permission_names_to_bits(
    permissions: &HashMap<String, Permission>,
    names: &[String]
) -> Result<u64, String> {
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

pub fn bits_to_permission_names(
    permissions: &HashMap<String, Permission>,
    bits: u64
) -> Result<Vec<String>, String> {
    let mut names = Vec::new();

    for permission in permissions.values() {
        if (bits & permission.value) == permission.value {
            names.push(permission.name.clone());
        }
    }

    names.sort();
    Ok(names)
}

pub fn find_next_available_bit(used_values: &[u64]) -> Result<u64, String> {
    let mut sorted_values = used_values.to_vec();
    sorted_values.sort();

    let mut next_value = 1u64;
    for &used_value in &sorted_values {
        if next_value == used_value {
            next_value = next_value.checked_mul(2).ok_or("No more permission slots available")?;
        } else {
            break;
        }
    }

    Ok(next_value)
}
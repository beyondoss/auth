use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuthzSchema {
    pub version: u32,
    pub resources: Vec<ResourceDef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subject_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ResourceDef {
    pub name: String,
    pub roles: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub role_hierarchy: Vec<RoleEdge>,
    pub permissions: HashMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hierarchy: Option<HierarchyDef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RoleEdge {
    pub superior: String,
    pub inferior: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HierarchyDef {
    /// The relation name on this resource that points to parent objects.
    pub parent_relation: String,
    /// The resource type of the parent.
    pub parent_resource: String,
}

/// A compiled authorization schema: maps `(resource_type, permission)` to an OR-chain
/// of check calls that are evaluated against the relation_tuple table.
#[derive(Debug, Clone)]
pub struct CompiledSchema {
    pub checks: HashMap<(String, String), Vec<AuthzCheckCall>>,
}

/// One call in the OR-chain for an authz check.
#[derive(Debug, Clone)]
pub enum AuthzCheckCall {
    /// Single-hop: subject directly holds one of `relations` on `object_type`.
    /// Compiled to: `auth.authz_check(subject, ARRAY[...relations], object_type, $object_id)`
    SingleHop {
        relations: Vec<String>,
        object_type: String,
    },
    /// Multi-hop: walk `relation_path[i]` on `object_type_path[i]` for each step.
    /// Compiled to: `auth.authz_check(subject, ARRAY[...relation_path], ARRAY[...object_type_path], $object_id)`
    MultiHop {
        relation_path: Vec<String>,
        object_type_path: Vec<String>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    #[error("invalid identifier {0:?}: must match [a-z][a-z0-9_]*")]
    InvalidIdentifier(String),
    #[error("resource {0:?}: role {1:?} in role_hierarchy is not defined")]
    UnknownHierarchyRole(String, String),
    #[error("resource {0:?}: role {1:?} in permissions for {2:?} is not defined")]
    UnknownPermissionRole(String, String, String),
    #[error("resource {0:?}: parent_resource {1:?} is not a defined resource")]
    UnknownParentResource(String, String),
    #[error("schema version {0} is not supported (expected 1)")]
    UnsupportedVersion(u32),
}

pub fn validate_ident(s: &str) -> Result<(), SchemaError> {
    if s.is_empty() {
        return Err(SchemaError::InvalidIdentifier(s.to_owned()));
    }
    let mut chars = s.chars();
    if !chars.next().unwrap().is_ascii_lowercase() {
        return Err(SchemaError::InvalidIdentifier(s.to_owned()));
    }
    if chars.any(|c| !matches!(c, 'a'..='z' | '0'..='9' | '_')) {
        return Err(SchemaError::InvalidIdentifier(s.to_owned()));
    }
    Ok(())
}

pub fn compile(schema: &AuthzSchema) -> Result<CompiledSchema, SchemaError> {
    if schema.version != 1 {
        return Err(SchemaError::UnsupportedVersion(schema.version));
    }

    let resource_names: HashSet<&str> = schema.resources.iter().map(|r| r.name.as_str()).collect();
    let mut checks: HashMap<(String, String), Vec<AuthzCheckCall>> = HashMap::new();

    for resource in &schema.resources {
        validate_ident(&resource.name)?;
        for role in &resource.roles {
            validate_ident(role)?;
        }

        let role_set: HashSet<&str> = resource.roles.iter().map(|r| r.as_str()).collect();

        for edge in &resource.role_hierarchy {
            if !role_set.contains(edge.superior.as_str()) {
                return Err(SchemaError::UnknownHierarchyRole(
                    resource.name.clone(),
                    edge.superior.clone(),
                ));
            }
            if !role_set.contains(edge.inferior.as_str()) {
                return Err(SchemaError::UnknownHierarchyRole(
                    resource.name.clone(),
                    edge.inferior.clone(),
                ));
            }
        }

        if let Some(h) = &resource.hierarchy {
            validate_ident(&h.parent_relation)?;
            if !resource_names.contains(h.parent_resource.as_str()) {
                return Err(SchemaError::UnknownParentResource(
                    resource.name.clone(),
                    h.parent_resource.clone(),
                ));
            }
        }

        let inherited = compute_inherited_roles(&resource.roles, &resource.role_hierarchy);

        for (permission, direct_roles) in &resource.permissions {
            validate_ident(permission)?;

            for role in direct_roles {
                if !role_set.contains(role.as_str()) {
                    return Err(SchemaError::UnknownPermissionRole(
                        resource.name.clone(),
                        role.clone(),
                        permission.clone(),
                    ));
                }
            }

            // All roles granting this permission: explicitly listed + any superior role
            // that inherits (is transitively above) a listed role.
            let all_roles: Vec<String> = resource
                .roles
                .iter()
                .filter(|r| {
                    direct_roles.contains(*r)
                        || inherited.get(r.as_str()).is_some_and(|inf| {
                            inf.iter()
                                .any(|i| direct_roles.iter().any(|d| d.as_str() == *i))
                        })
                })
                .cloned()
                .collect();

            if all_roles.is_empty() {
                continue;
            }

            let mut calls = vec![AuthzCheckCall::SingleHop {
                relations: all_roles.clone(),
                object_type: resource.name.clone(),
            }];

            // For each role, add a two-hop path through the parent resource.
            if let Some(h) = &resource.hierarchy {
                for role in &all_roles {
                    calls.push(AuthzCheckCall::MultiHop {
                        relation_path: vec![h.parent_relation.clone(), role.clone()],
                        object_type_path: vec![resource.name.clone(), h.parent_resource.clone()],
                    });
                }
            }

            checks.insert((resource.name.clone(), permission.clone()), calls);
        }
    }

    Ok(CompiledSchema { checks })
}

/// Compute transitive inferiors for each role. If owner > editor > viewer, then
/// `inherited["owner"] = {"editor", "viewer"}` and `inherited["editor"] = {"viewer"}`.
fn compute_inherited_roles<'a>(
    roles: &'a [String],
    edges: &'a [RoleEdge],
) -> HashMap<&'a str, HashSet<&'a str>> {
    let mut result: HashMap<&str, HashSet<&str>> = HashMap::new();
    for edge in edges {
        result
            .entry(edge.superior.as_str())
            .or_default()
            .insert(edge.inferior.as_str());
    }
    // Transitive closure. Roles per resource are small (single digits), so naive is fine.
    let role_strs: Vec<&str> = roles.iter().map(|r| r.as_str()).collect();
    let mut changed = true;
    while changed {
        changed = false;
        for &role in &role_strs {
            let inferiors: Vec<&str> = result
                .get(role)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .collect();
            for inf in inferiors {
                if let Some(sub_inferiors) = result.get(inf).cloned() {
                    let entry = result.entry(role).or_default();
                    for sub_inf in sub_inferiors {
                        if entry.insert(sub_inf) {
                            changed = true;
                        }
                    }
                }
            }
        }
    }
    result
}

impl CompiledSchema {
    pub fn get_checks(&self, resource_type: &str, permission: &str) -> Option<&[AuthzCheckCall]> {
        self.checks
            .get(&(resource_type.to_owned(), permission.to_owned()))
            .map(|v| v.as_slice())
    }

    pub fn resource_exists(&self, resource_type: &str) -> bool {
        self.checks.keys().any(|(rt, _)| rt == resource_type)
    }

    /// Build the SQL OR-chain fragment for a bundled CTE. `object_id` is always `$3`;
    /// `subject_id` is referenced as `subject.subject_id` from the CTE. Relation and
    /// resource type names come from the validated schema and are safe to embed as literals.
    pub fn build_or_chain(&self, resource_type: &str, permission: &str) -> Option<String> {
        let calls = self.get_checks(resource_type, permission)?;
        let parts: Vec<String> = calls
            .iter()
            .map(|c| match c {
                AuthzCheckCall::SingleHop {
                    relations,
                    object_type,
                } => {
                    let arr = relations
                        .iter()
                        .map(|r| format!("'{r}'"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!(
                        "auth.authz_check(subject.subject_id, ARRAY[{arr}]::text[], '{object_type}', $3)"
                    )
                }
                AuthzCheckCall::MultiHop {
                    relation_path,
                    object_type_path,
                } => {
                    let rels = relation_path
                        .iter()
                        .map(|r| format!("'{r}'"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    let types = object_type_path
                        .iter()
                        .map(|t| format!("'{t}'"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!(
                        "auth.authz_check(subject.subject_id, ARRAY[{rels}]::text[], ARRAY[{types}]::text[], $3)"
                    )
                }
            })
            .collect();
        Some(parts.join("\n    OR "))
    }

    /// Build an OR-chain for a standalone check (no session CTE). `subject_id` is `$1`,
    /// `object_id` is `$2`.
    pub fn build_standalone_or_chain(
        &self,
        resource_type: &str,
        permission: &str,
    ) -> Option<String> {
        let calls = self.get_checks(resource_type, permission)?;
        let parts: Vec<String> = calls
            .iter()
            .map(|c| match c {
                AuthzCheckCall::SingleHop {
                    relations,
                    object_type,
                } => {
                    let arr = relations
                        .iter()
                        .map(|r| format!("'{r}'"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!("auth.authz_check($1, ARRAY[{arr}]::text[], '{object_type}', $2)")
                }
                AuthzCheckCall::MultiHop {
                    relation_path,
                    object_type_path,
                } => {
                    let rels = relation_path
                        .iter()
                        .map(|r| format!("'{r}'"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    let types = object_type_path
                        .iter()
                        .map(|t| format!("'{t}'"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!(
                        "auth.authz_check($1, ARRAY[{rels}]::text[], ARRAY[{types}]::text[], $2)"
                    )
                }
            })
            .collect();
        Some(parts.join("\n    OR "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document_schema() -> AuthzSchema {
        serde_json::from_value(serde_json::json!({
            "version": 1,
            "resources": [{
                "name": "document",
                "roles": ["owner", "editor", "viewer"],
                "role_hierarchy": [
                    {"superior": "owner",  "inferior": "editor"},
                    {"superior": "editor", "inferior": "viewer"}
                ],
                "permissions": {
                    "read":   ["viewer"],
                    "write":  ["editor"],
                    "delete": ["owner"]
                },
                "hierarchy": {
                    "parent_relation": "folder",
                    "parent_resource": "folder"
                }
            }, {
                "name": "folder",
                "roles": ["owner", "editor", "viewer"],
                "role_hierarchy": [
                    {"superior": "owner",  "inferior": "editor"},
                    {"superior": "editor", "inferior": "viewer"}
                ],
                "permissions": {
                    "read":  ["viewer"],
                    "write": ["editor"]
                }
            }]
        }))
        .unwrap()
    }

    #[test]
    fn compile_expands_hierarchy() {
        let schema = document_schema();
        let compiled = compile(&schema).unwrap();

        // write on document: editor is listed; owner inherits editor; both should appear.
        let calls = compiled.get_checks("document", "write").unwrap();
        let single_hop = calls
            .iter()
            .find(|c| matches!(c, AuthzCheckCall::SingleHop { .. }))
            .unwrap();
        let AuthzCheckCall::SingleHop { relations, .. } = single_hop else {
            panic!()
        };
        assert!(relations.contains(&"editor".to_owned()));
        assert!(relations.contains(&"owner".to_owned()));
        assert!(!relations.contains(&"viewer".to_owned()));
    }

    #[test]
    fn compile_emits_parent_paths() {
        let schema = document_schema();
        let compiled = compile(&schema).unwrap();

        let calls = compiled.get_checks("document", "write").unwrap();
        let multi_hops: Vec<_> = calls
            .iter()
            .filter(|c| matches!(c, AuthzCheckCall::MultiHop { .. }))
            .collect();

        // One multi-hop per role (editor, owner) via folder parent.
        assert_eq!(multi_hops.len(), 2);
        for hop in &multi_hops {
            let AuthzCheckCall::MultiHop {
                relation_path,
                object_type_path,
            } = hop
            else {
                panic!()
            };
            assert_eq!(relation_path[0], "folder");
            assert_eq!(object_type_path[0], "document");
            assert_eq!(object_type_path[1], "folder");
        }
    }

    #[test]
    fn compile_delete_only_owner() {
        let schema = document_schema();
        let compiled = compile(&schema).unwrap();

        let calls = compiled.get_checks("document", "delete").unwrap();
        let AuthzCheckCall::SingleHop { relations, .. } = &calls[0] else {
            panic!()
        };
        assert_eq!(relations, &["owner"]);
    }

    #[test]
    fn invalid_identifier_rejected() {
        let mut schema = document_schema();
        schema.resources[0].name = "My-Resource".into();
        assert!(compile(&schema).is_err());
    }

    #[test]
    fn unknown_parent_resource_rejected() {
        let mut schema = document_schema();
        schema.resources[0].hierarchy = Some(HierarchyDef {
            parent_relation: "parent".into(),
            parent_resource: "nonexistent".into(),
        });
        assert!(compile(&schema).is_err());
    }
}

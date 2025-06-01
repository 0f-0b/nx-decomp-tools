use crate::repo;
use anyhow::{bail, Result};
use indexmap::IndexMap;
use rayon::prelude::*;
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize, Serializer};
use std::path::{Path, PathBuf};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum Status {
    Matching,
    NonMatchingMinor,
    NonMatchingMajor,
    NotDecompiled,
    Wip,
    Library,
}

impl Status {
    pub fn description(&self) -> &'static str {
        match &self {
            Status::Matching => "matching",
            Status::NonMatchingMinor => "non-matching (minor)",
            Status::NonMatchingMajor => "non-matching (major)",
            Status::NotDecompiled => "not decompiled",
            Status::Wip => "WIP",
            Status::Library => "library function",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum AddressLabel {
    Single(String),
    Multi(Vec<String>),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Info {
    #[serde(serialize_with = "as_hex")]
    pub offset: u32,
    pub size: u32,
    pub label: AddressLabel,
    pub status: Status,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub lazy: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub guess: bool,
}

fn as_hex<S>(offset: &u32, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&format!("0x{:06x}", offset))
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Object {
    #[serde(rename(serialize = ".text", deserialize = ".text"))]
    pub text_section: Vec<Info>,
}

impl Info {
    pub fn is_decompiled(&self) -> bool {
        !matches!(self.status, Status::NotDecompiled | Status::Library)
    }
    pub fn name(&self) -> &str {
        match &self.label {
            AddressLabel::Single(label) => label,
            AddressLabel::Multi(labels) => labels.first().unwrap(),
        }
    }
}

pub const ADDRESS_BASE: u64 = 0x71_0000_0000;

fn parse_base_16(value: &str) -> Result<u64> {
    if let Some(stripped) = value.strip_prefix("0x") {
        Ok(u64::from_str_radix(stripped, 16)?)
    } else {
        Ok(u64::from_str_radix(value, 16)?)
    }
}

pub fn parse_address(value: &str) -> Result<u64> {
    Ok(parse_base_16(value)? - ADDRESS_BASE)
}

pub type FileListMap = IndexMap<String, Object>; // Object name, object. Uses IndexMap to
                                                 // preserve map ordering

pub fn parse_file_list(file_list_path: &Path) -> Result<FileListMap> {
    let file_list_data = std::fs::read_to_string(file_list_path)?;
    let objects = serde_yml::from_str::<FileListMap>(&file_list_data)?;
    Ok(objects)
}

pub fn write_functions_to_path(file_list_path: &Path, file_list_data: &FileListMap) -> Result<()> {
    let mut serialized_yaml = serde_yml::to_string(file_list_data)?;
    let remove_offset_quotes: regex::Regex = regex::Regex::new(r"offset:\s'(?P<offset>\w+)'")?;
    serialized_yaml = remove_offset_quotes
        .replace_all(&serialized_yaml, "offset: ${offset}")
        .into_owned();
    std::fs::write(file_list_path, serialized_yaml)?;
    Ok(())
}

pub fn get_file_list_path(version: Option<&str>) -> PathBuf {
    let mut path = repo::get_repo_root().expect("Failed to get repo root");
    let config_file_list = repo::get_config().file_list.clone();
    let file_list = version
        .map(|s| config_file_list.replace("{version}", s))
        .unwrap_or(config_file_list);
    path.push(file_list);

    path
}

pub fn get_functions(file_list_data: &FileListMap) -> Vec<Info> {
    let mut result = Vec::with_capacity(110_000);
    for object in file_list_data.values() {
        result.extend(object.text_section.clone());
    }
    result
}

pub fn make_known_function_map(functions: &Vec<Info>) -> FxHashMap<u32, &Info> {
    let mut known_functions =
        FxHashMap::with_capacity_and_hasher(functions.len(), Default::default());

    for function in functions {
        if function.name().is_empty() {
            continue;
        }
        known_functions.insert(function.offset, function);
    }

    known_functions
}

pub fn make_known_function_name_map(functions: &Vec<Info>) -> FxHashMap<&str, &Info> {
    let mut known_functions =
        FxHashMap::with_capacity_and_hasher(functions.len(), Default::default());

    for function in functions {
        if function.name().is_empty() {
            continue;
        }
        match &function.label {
            AddressLabel::Single(label) => {
                known_functions.insert(label.as_str(), function);
            }
            AddressLabel::Multi(labels) => {
                for label in labels {
                    known_functions.insert(label.as_str(), function);
                }
            }
        }
    }

    known_functions
}

/// Demangle a C++ symbol.
pub fn demangle_str(name: &str) -> Result<String> {
    if !name.starts_with("_Z") {
        bail!("not an external mangled name");
    }

    let symbol = cpp_demangle::Symbol::new(name)?;
    let options = cpp_demangle::DemangleOptions::new();
    Ok(symbol.demangle(&options)?)
}

pub fn fuzzy_search<'a>(functions: &'a Vec<Info>, name: &str) -> Vec<&'a Info> {
    let exact_match = functions
        .par_iter()
        .find_first(|function| function.name() == name);

    if let Some(exact_match) = exact_match {
        return vec![exact_match];
    }

    // Find all functions whose demangled name contains the specified string.
    // This is more expensive than a simple string comparison, so only do this after
    // we have failed to find an exact match.
    let mut candidates: Vec<&'a Info> = functions
        .into_par_iter()
        .filter(|function| {
            demangle_str(function.name()).is_ok_and(|demangled| demangled.contains(name))
                || function.name().contains(name)
        })
        .collect();

    candidates.sort_by_key(|info| info.offset);
    candidates
}

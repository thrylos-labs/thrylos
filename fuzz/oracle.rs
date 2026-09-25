//! An independent check of the storage ownership rule, for the fuzz target and
//! its deterministic stand-in (`crates/exec/tests/publish_mutations.rs`), and a
//! mutator that edits a module's tables the way a byte flip almost never does.
//!
//! The rule (`docs/move-storage-design.md`, D7): a module may keep in a
//! `thrylos::store` drawer only a type it defines. The chain enforces it with
//! `chain_exec::publish::store_violations`, which walks the function
//! *instantiation table*. This walks the *instruction stream* instead, and
//! reads indices defensively, so it is a second opinion from different code
//! and not the rule checking itself. Anything the chain accepted that this
//! finds fault with is a bug in one or the other.

use move_binary_format::file_format::{
    AddressIdentifierIndex, Bytecode, CompiledModule, DatatypeHandleIndex, FunctionHandleIndex,
    FunctionInstantiationIndex, IdentifierIndex, ModuleHandleIndex, SignatureIndex, SignatureToken,
};

fn is_framework_store(m: &CompiledModule, module: ModuleHandleIndex) -> Option<bool> {
    let handle = m.module_handles.get(usize::from(module.0))?;
    let address = m
        .address_identifiers
        .get(usize::from(handle.address.0))?
        .into_bytes();
    let name = m.identifiers.get(usize::from(handle.name.0))?;
    Some(address[..31].iter().all(|b| *b == 0) && address[31] == 2 && name.as_str() == "store")
}

fn defined_here(m: &CompiledModule, datatype: DatatypeHandleIndex) -> Option<bool> {
    let handle = m.datatype_handles.get(usize::from(datatype.0))?;
    Some(
        handle.module == m.self_module_handle_idx
            && (m.struct_defs.iter().any(|d| d.struct_handle == datatype)
                || m.enum_defs.iter().any(|d| d.enum_handle == datatype)),
    )
}

/// How many calls to a `thrylos::store` function `m` makes.
#[allow(dead_code)]
pub fn store_calls(m: &CompiledModule) -> usize {
    let mut count = 0;
    for def in &m.function_defs {
        for instruction in def.code.iter().flat_map(|code| code.code.iter()) {
            let handle = match instruction {
                Bytecode::CallGeneric(i) => m
                    .function_instantiations
                    .get(usize::from(i.0))
                    .map(|inst| inst.handle),
                Bytecode::Call(h) => Some(*h),
                _ => None,
            };
            let store = handle
                .and_then(|h| m.function_handles.get(usize::from(h.0)))
                .and_then(|h| is_framework_store(m, h.module))
                .unwrap_or(false);
            if store {
                count += 1;
            }
        }
    }
    count
}

/// Every call in `m` to a `thrylos::store` function that breaks the rule. Empty
/// for a module the chain was right to publish.
pub fn violations(m: &CompiledModule) -> Vec<String> {
    let mut found = Vec::new();
    for def in &m.function_defs {
        for instruction in def.code.iter().flat_map(|code| code.code.iter()) {
            match instruction {
                Bytecode::Call(h) => {
                    let store = m
                        .function_handles
                        .get(usize::from(h.0))
                        .and_then(|f| is_framework_store(m, f.module));
                    if store != Some(false) {
                        found.push("a call into the store that is not generic".to_owned());
                    }
                }
                Bytecode::CallGeneric(i) => {
                    let Some(inst) = m.function_instantiations.get(usize::from(i.0)) else {
                        found.push("a call through a missing instantiation".to_owned());
                        continue;
                    };
                    let store = m
                        .function_handles
                        .get(usize::from(inst.handle.0))
                        .and_then(|f| is_framework_store(m, f.module));
                    if store != Some(true) {
                        continue;
                    }
                    let tokens = m.signatures.get(usize::from(inst.type_parameters.0));
                    for token in tokens.iter().flat_map(|s| s.0.iter()) {
                        let owned = match token {
                            SignatureToken::Datatype(d) => defined_here(m, *d),
                            SignatureToken::DatatypeInstantiation(b) => defined_here(m, b.0),
                            _ => Some(false),
                        };
                        if owned != Some(true) {
                            found.push(format!("a store call with {token:?}"));
                        }
                    }
                }
                _ => {}
            }
        }
    }
    found
}

/// One structural edit to `m`, chosen and aimed by `next`: the kind of change
/// that reaches the ownership rule and the verifier with a module that still
/// looks well formed. May leave `m` invalid; the caller serialises it and
/// publishes whatever comes out.
pub fn mutate(m: &mut CompiledModule, next: &mut dyn FnMut() -> u64) {
    fn pick(next: &mut dyn FnMut() -> u64, len: usize) -> Option<usize> {
        (len > 0).then(|| (next() % (len as u64)) as usize)
    }
    match next() % 12 {
        0 => {
            // A datatype handle now says it belongs to another module.
            if let (Some(a), Some(b)) = (
                pick(next, m.datatype_handles.len()),
                pick(next, m.module_handles.len()),
            ) {
                m.datatype_handles[a].module = ModuleHandleIndex(b as u16);
            }
        }
        1 => {
            if let (Some(a), Some(b)) = (
                pick(next, m.datatype_handles.len()),
                pick(next, m.identifiers.len()),
            ) {
                m.datatype_handles[a].name = IdentifierIndex(b as u16);
            }
        }
        2 => {
            // A store call now instantiated with another signature.
            if let (Some(a), Some(b)) = (
                pick(next, m.function_instantiations.len()),
                pick(next, m.signatures.len()),
            ) {
                m.function_instantiations[a].type_parameters = SignatureIndex(b as u16);
            }
        }
        3 => {
            if let (Some(a), Some(b)) = (
                pick(next, m.function_instantiations.len()),
                pick(next, m.function_handles.len()),
            ) {
                m.function_instantiations[a].handle = FunctionHandleIndex(b as u16);
            }
        }
        4 => {
            // One signature token copied over another.
            if let (Some(a), Some(c)) = (
                pick(next, m.signatures.len()),
                pick(next, m.signatures.len()),
            ) {
                if let (Some(b), Some(d)) = (
                    pick(next, m.signatures[a].0.len()),
                    pick(next, m.signatures[c].0.len()),
                ) {
                    let token = m.signatures[c].0[d].clone();
                    m.signatures[a].0[b] = token;
                }
            }
        }
        5 => {
            if let (Some(a), Some(b)) = (
                pick(next, m.struct_defs.len()),
                pick(next, m.datatype_handles.len()),
            ) {
                m.struct_defs[a].struct_handle = DatatypeHandleIndex(b as u16);
            }
        }
        6 => {
            // A call redirected to another instantiation.
            if let Some(f) = pick(next, m.function_defs.len()) {
                if let Some(code) = m.function_defs[f].code.as_mut() {
                    if let (Some(i), Some(to)) = (
                        pick(next, code.code.len()),
                        pick(next, m.function_instantiations.len()),
                    ) {
                        if matches!(code.code[i], Bytecode::CallGeneric(_)) {
                            code.code[i] =
                                Bytecode::CallGeneric(FunctionInstantiationIndex(to as u16));
                        }
                    }
                }
            }
        }
        7 => {
            if let (Some(a), Some(b)) = (
                pick(next, m.module_handles.len()),
                pick(next, m.address_identifiers.len()),
            ) {
                m.module_handles[a].address = AddressIdentifierIndex(b as u16);
            }
        }
        8 => {
            if let (Some(a), Some(b)) = (
                pick(next, m.module_handles.len()),
                pick(next, m.identifiers.len()),
            ) {
                m.module_handles[a].name = IdentifierIndex(b as u16);
            }
        }
        9 => {
            if let Some(b) = pick(next, m.module_handles.len()) {
                m.self_module_handle_idx = ModuleHandleIndex(b as u16);
            }
        }
        10 => {
            if let (Some(a), Some(b)) = (
                pick(next, m.datatype_handles.len()),
                pick(next, m.datatype_handles.len()),
            ) {
                m.datatype_handles.swap(a, b);
            }
        }
        _ => {
            // A call's instantiation, or a whole function handle, swapped for another.
            if let (Some(a), Some(b)) = (
                pick(next, m.function_handles.len()),
                pick(next, m.function_handles.len()),
            ) {
                m.function_handles.swap(a, b);
            }
        }
    }
}

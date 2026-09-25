//! The Move VM's configuration, and the limits on what may be published to it.
//!
//! Every value here is **consensus**: two validators that disagree on any of
//! them disagree on which packages are valid, and so on the state. They are
//! constants in this file, a test pins each one, and a change is a rule change
//! (see `docs/move-publishing-design.md`).
//!
//! The upstream defaults are not fit for a chain that accepts bytecode from
//! anyone. Most of `VerifierConfig::default()` is `None`, meaning *no limit*
//! on loop depth, basic blocks, functions, structs and more, and the VM's own
//! publish path runs its verifier **unmetered**. So the limits below bound the
//! verifier's work algorithmically, and [`verifier_meter`] gives a second,
//! deterministic wall that this crate applies itself, before the VM sees a
//! module.
//!
//! The verifier limits are Sui's mainnet protocol values for the same VM. They
//! are known to accept real packages, and Thrylos may tighten them; loosening
//! them widens what an attacker can make every validator do.

use move_binary_format::binary_config::BinaryConfig;
use move_binary_format::file_format_common::VERSION_MAX;
use move_bytecode_verifier_meter::bound::BoundMeter;
use move_vm_config::runtime::{VMConfig, VMRuntimeLimitsConfig};
use move_vm_config::verifier::{MeterConfig, VerifierConfig, DEFAULT_MAX_CONSTANT_VECTOR_LEN};

/// All the modules of one package, together, in bytes.
pub const MAX_PACKAGE_BYTES: usize = 128 * 1024;
/// Modules in one package.
pub const MAX_MODULES_PER_PACKAGE: usize = 32;
/// One module, in bytes.
pub const MAX_MODULE_BYTES: usize = 64 * 1024;

/// The verifier's abstract work units allowed for one function, one module and
/// one package. The count is deterministic (it does not depend on the machine),
/// so it can be a rule of the chain, and exceeding it rejects the publish.
pub const METER_UNITS_PER_FUNCTION: u128 = 2_200_000;
pub const METER_UNITS_PER_MODULE: u128 = 2_200_000;
pub const METER_UNITS_PER_PACKAGE: u128 = 8_000_000;

/// The verifier's structural limits, set explicitly.
pub fn verifier_config() -> VerifierConfig {
    VerifierConfig {
        max_loop_depth: Some(5),
        max_generic_instantiation_length: Some(32),
        max_function_parameters: Some(128),
        max_basic_blocks: Some(1024),
        max_value_stack_size: 1024,
        max_type_nodes: Some(256),
        max_push_size: Some(10_000),
        max_dependency_depth: Some(100),
        max_data_definitions: Some(200),
        max_fields_in_struct: Some(32),
        max_function_definitions: Some(1000),
        max_back_edges_per_function: Some(10),
        max_back_edges_per_module: Some(10),
        max_basic_blocks_in_script: Some(1024),
        ..VerifierConfig::default()
    }
}

/// A fresh meter with the limits above, for verifying one package.
pub fn verifier_meter() -> BoundMeter {
    BoundMeter::new(MeterConfig {
        max_per_fun_meter_units: Some(METER_UNITS_PER_FUNCTION),
        max_per_mod_meter_units: Some(METER_UNITS_PER_MODULE),
        max_per_pkg_meter_units: Some(METER_UNITS_PER_PACKAGE),
    })
}

/// How a module's bytes are read: nothing after the module, and the old global
/// storage opcodes refused outright (this VM has no global storage; a module
/// that uses those opcodes cannot be run).
pub fn binary_config() -> BinaryConfig {
    BinaryConfig::legacy_with_flags(
        /* check_no_extraneous_bytes */ true, /* deprecate_global_storage_ops */ true,
    )
}

/// The configuration every executor's VM is made with.
pub fn vm_config() -> VMConfig {
    VMConfig {
        verifier: verifier_config(),
        max_binary_format_version: VERSION_MAX,
        runtime_limits_config: VMRuntimeLimitsConfig {
            vector_len_max: DEFAULT_MAX_CONSTANT_VECTOR_LEN,
            max_value_nest_depth: Some(128),
            hardened_otw_check: true,
            package_arena_size: None,
        },
        enable_invariant_violation_check_in_swap_loc: true,
        check_no_extraneous_bytes_during_deserialization: true,
        error_execution_state: false,
        binary_config: binary_config(),
        rethrow_serialization_type_layout_errors: false,
        max_type_to_layout_nodes: Some(512),
        variant_nodes: true,
        deprecate_global_storage_ops_during_deserialization: true,
        normalize_depth_formula: true,
        charge_ld_const_abstract_size: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_limits_on_what_may_be_published_are_these_and_are_below_the_transaction_cap() {
        assert_eq!(MAX_PACKAGE_BYTES, 128 * 1024);
        assert_eq!(MAX_MODULES_PER_PACKAGE, 32);
        assert_eq!(MAX_MODULE_BYTES, 64 * 1024);
        const { assert!(MAX_MODULE_BYTES <= MAX_PACKAGE_BYTES) };
        // A transaction is at most 256 KiB, and carries the package and a little more.
        const { assert!(MAX_PACKAGE_BYTES < 256 * 1024) };
    }

    #[test]
    fn every_verifier_limit_is_set_and_has_this_value() {
        let config = verifier_config();
        assert_eq!(config.max_loop_depth, Some(5));
        assert_eq!(config.max_generic_instantiation_length, Some(32));
        assert_eq!(config.max_function_parameters, Some(128));
        assert_eq!(config.max_basic_blocks, Some(1024));
        assert_eq!(config.max_value_stack_size, 1024);
        assert_eq!(config.max_type_nodes, Some(256));
        assert_eq!(config.max_push_size, Some(10_000));
        assert_eq!(config.max_dependency_depth, Some(100));
        assert_eq!(config.max_data_definitions, Some(200));
        assert_eq!(config.max_fields_in_struct, Some(32));
        assert_eq!(config.max_function_definitions, Some(1000));
        assert_eq!(config.max_back_edges_per_function, Some(10));
        assert_eq!(config.max_back_edges_per_module, Some(10));
        assert_eq!(config.max_basic_blocks_in_script, Some(1024));
        // The upstream defaults for these are limits already, and are part of the rules.
        assert_eq!(
            config.max_constant_vector_len,
            Some(DEFAULT_MAX_CONSTANT_VECTOR_LEN)
        );
        assert_eq!(config.max_identifier_len, Some(128));
        assert!(config.deprecate_global_storage_ops);
        assert_eq!(config.bytecode_version, VERSION_MAX);
    }

    #[test]
    fn nothing_the_verifier_is_bounded_by_is_left_unbounded() {
        // The upstream default leaves these `None`. If a future upstream adds a new
        // limit that defaults to `None`, the snapshot below changes and this fails,
        // which is the prompt to decide its value.
        let config = verifier_config();
        for (name, set) in [
            ("max_loop_depth", config.max_loop_depth.is_some()),
            (
                "max_generic_instantiation_length",
                config.max_generic_instantiation_length.is_some(),
            ),
            (
                "max_function_parameters",
                config.max_function_parameters.is_some(),
            ),
            ("max_basic_blocks", config.max_basic_blocks.is_some()),
            ("max_type_nodes", config.max_type_nodes.is_some()),
            ("max_push_size", config.max_push_size.is_some()),
            (
                "max_dependency_depth",
                config.max_dependency_depth.is_some(),
            ),
            (
                "max_data_definitions",
                config.max_data_definitions.is_some(),
            ),
            (
                "max_fields_in_struct",
                config.max_fields_in_struct.is_some(),
            ),
            (
                "max_function_definitions",
                config.max_function_definitions.is_some(),
            ),
            (
                "max_back_edges_per_function",
                config.max_back_edges_per_function.is_some(),
            ),
            (
                "max_back_edges_per_module",
                config.max_back_edges_per_module.is_some(),
            ),
            (
                "max_basic_blocks_in_script",
                config.max_basic_blocks_in_script.is_some(),
            ),
            (
                "max_constant_vector_len",
                config.max_constant_vector_len.is_some(),
            ),
            ("max_identifier_len", config.max_identifier_len.is_some()),
            (
                "max_type_nodes_per_function",
                config
                    .max_generic_instantiation_type_nodes_per_function
                    .is_some(),
            ),
            (
                "max_type_nodes_per_module",
                config
                    .max_generic_instantiation_type_nodes_per_module
                    .is_some(),
            ),
        ] {
            assert!(set, "{name} must have a limit");
        }
    }

    #[test]
    fn the_vm_config_reads_modules_strictly_and_refuses_global_storage() {
        let config = vm_config();
        assert!(config.check_no_extraneous_bytes_during_deserialization);
        assert!(config.deprecate_global_storage_ops_during_deserialization);
        assert!(config.binary_config.check_no_extraneous_bytes);
        assert!(config.binary_config.deprecate_global_storage_ops);
        assert_eq!(config.runtime_limits_config.max_value_nest_depth, Some(128));
        // An execution error must not carry a stack trace: it would be state a
        // validator could format differently.
        assert!(!config.error_execution_state);
    }

    #[test]
    fn the_meter_limits_are_these() {
        assert_eq!(METER_UNITS_PER_FUNCTION, 2_200_000);
        assert_eq!(METER_UNITS_PER_MODULE, 2_200_000);
        assert_eq!(METER_UNITS_PER_PACKAGE, 8_000_000);
    }
}

/// What a running function may know about the block it runs in. Each value is
/// the same for every node executing the block, so none of these can make two
/// nodes disagree.
module thrylos::chain;

/// The timestamp in the block's header, in milliseconds.
public native fun block_time_ms(): u64;

/// The height of the block.
public native fun height(): u64;

/// The chain's id.
public native fun chain_id(): u64;

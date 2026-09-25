/// Reading the address out of a `signer`. A signer is the sender of the
/// transaction, supplied by the chain to an entry function's first parameter.
module thrylos::signer;

native fun borrow_address(s: &signer): &address;

public fun address_of(s: &signer): address {
    *borrow_address(s)
}

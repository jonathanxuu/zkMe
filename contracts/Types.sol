// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.9;

struct EIP712Signature {
    uint8 v; // The recovery ID.
    bytes32 r; // The x-coordinate of the nonce R.
    bytes32 s; // The signature data.
}

struct RevocationWithSig {
    bytes32 digest;
    address attester;
    EIP712Signature revocationSignature;
}

struct MultiRevocationWithSig {
    bytes32[] digest;
    address attester;
    EIP712Signature revocationSignature;
}

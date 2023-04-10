// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.8.9;

/**
 * @title The global CType registry interface.
 */
interface ICTypeResolver {

    // todo: add event

    /**
     * @dev store the Schema Data on-chain
     *
     * @param originData, the bytes form of the PublicVC
     * @param digest, the digest of the attestation
     */
    function store(bytes memory originData, bytes32 digest) external;

    /**
     * @dev compute the RootHash of the struct, using rlp decoding
     *
     * @param originData, the bytes form of the PublicVC
     */
    function computeRootHash(bytes memory originData) external pure returns (bytes32 roothash);


    /**
     * @dev replace the Schema Data on-chain, can only change the attestation uploaded by themselves
     *
     * @param originData, the bytes form of the PublicVC
     * @param digest, the digest of the attestation
     */
    function replace(bytes memory originData, bytes32 digest) external returns (bool);
}

// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.8.9;
import {libCredential} from "./library/libCredential.sol";
import {libAttestation} from "./library/libAttestation.sol";
import {ICTypeRegistry} from "./ICTypeRegistry.sol";
import { RevocationWithSig, MultiRevocationWithSig } from "./Types.sol";

/**
 * @title Converter - The contract used to convert a valid Credential to Attestation on-chain.
 */
interface IConverter {
    /**
     * @dev Emitted when an attestation has been converted.
     *
     * @param digest The digest of the attestation.
     */
    event ConvertSuccess(bytes32 indexed digest);

    /**
     * @dev Emitted when an attestation has been revoked.
     *
     * @param revoker The address of the revoker.
     * @param digest The digest of the attestation.
     */
    event Revoke(address indexed revoker, bytes32 indexed digest);

    /**
     * @dev Emitted when an attestation has been revoked with Sig.
     *
     * @param revoker The address of the revoker.
     * @param digest The digest of the attestation.
     * @param attester The address of the attestation's attester.
     */
    event RevokeWithSig(
        address indexed revoker,
        bytes32 indexed digest,
        address indexed attester
    );

    /**
     * @dev Returns the address of the global ctype registry.
     *
     * @return The address of the global ctype registry.
     */
    function getSchemaRegistry() external view returns (ICTypeRegistry);

    /**
     * @dev convert the Credential to attestation on-chain
     * @param credential, the credential to be converted
     *
     * @return Returns the digest of the attestation
     */
    function convertToAttestation(
        libCredential.Credential memory credential
    ) external returns (bytes32);

    /**
     * @dev convert the Credential to attestation on-chain in batch
     * @param credentialList, the credentials to be converted
     *
     * @return digest, Returns the digest of the attestation
     */
    function multiConvertToAttestation(
        libCredential.Credential[] memory credentialList
    ) external returns (bytes32[] memory);

    /**
     * @dev revoke certain attestation. Designed for the attester themselves.
     * @param digest, the digest of the attestation to be revoked
     *
     * @return Returns the timestamp of the revocation.
     */
    function revoke(bytes32 digest) external returns (uint64);

    /**
     * @dev revoke attestations in batch. Designed for the attester themselves.
     * @param digestList, the digest of the attestations to be revoked
     *
     * @return Returns the timestamp of the revocation.
     */
    function multiRevoke(bytes32[] memory digestList) external returns (uint64);

    /**
     * @dev revoke attestation with attester's signature. The signature must match the digest to be revoked.
     * @param revocationWithSigList, the digest, signature, attester of the attestation to be revoked
     * 
     * @return Returns the timestamp of the revocation.

     */
    function revokeWithSig(
        RevocationWithSig[] memory revocationWithSigList
    ) external returns (uint64);

    /**
     * @dev revoke attestation with attester's signature. The signature must match the digest to be revoked.
     * @param multiRevocationWithSigList, the digest, signature, attester of the attestation to be revoked
     * 
     * @return Returns the timestamp of the revocation.

     */
    function multiRevokeWithSig(
        MultiRevocationWithSig[] memory multiRevocationWithSigList
    ) external returns (uint64);

    /**
     * @dev check whether the attestation is valid and hasn't been revoked yet.
     * @param digest, the digest of the attestation to be checked
     *
     * @return Returns the check result
     */
    function validityCheck(bytes32 digest) external view returns (bool);

    /**
     * @dev fetch the attestation on-chain, no matter whether the attestation is revoked
     * @param digest, the digest of the attestation to be checked
     *
     * @return Returns the attestation stored on-chain
     */
    function getAttestation(
        bytes32 digest
    ) external view returns (libAttestation.Attestation memory);
}

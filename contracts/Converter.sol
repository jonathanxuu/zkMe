// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.8.9;

import {libCredential} from "./library/libCredential.sol";
import {libAttestation} from "./library/libAttestation.sol";
import {libRevocation} from "./library/libRevocation.sol";

/**
 * @title Converter
 * @dev used to convert Credential to Attestation on-chain. The contract will do the verification job.
 */
contract Converter {
    // checking the attestation details via its digest
    mapping(bytes32 => libAttestation.Attestation) private _db;

    // store the timestamp of the revocation
    mapping(bytes32 => mapping(address => uint64)) private _revokeDB;

    // todo: list all error scenairos
    error DigestInvalid();
    error SignatureInvalid();
    error AttestationAlreadyExist();
    error AttestationNotExist();
    error AlreadyRevoked();
    error RevokeWithInvalidSig();

    // todo：list all event
    event ConvertSuccess(address indexed converter, bytes32 indexed digest);
    event Revoke(address indexed revoker, bytes32 indexed digest);
    event RevokeWithSig(
        address indexed revoker,
        bytes32 indexed digest,
        address indexed attester
    );

    /**
     * @dev convert the Credential to attestation on-chain
     * @param credential, the credential to be converted
     *
     * @return Returns the digest of the attestation
     */
    function convertToAttestation(
        libCredential.Credential memory credential
    ) public returns (bytes32) {
        if (libCredential.verifyDigest(credential) == false) {
            revert DigestInvalid();
        }

        if (libCredential.verifySignature(credential) == false) {
            revert SignatureInvalid();
        }

        if (_db[credential.digest].digest != bytes32(0)) {
            revert AttestationAlreadyExist();
        }

        if (_revokeDB[credential.digest][credential.attester] != 0) {
            revert AlreadyRevoked();
        }

        libAttestation.Attestation memory attestation = libAttestation
            .fillAttestation(credential, msg.sender);
        _db[attestation.digest] = attestation;

        emit ConvertSuccess(msg.sender, attestation.digest);
        return attestation.digest;
    }

    /**
     * @dev convert the Credential to attestation on-chain in batch
     * @param credentialList, the credentials to be converted
     *
     * @return digest, Returns the digest of the attestation
     */
    function multiConvertToAttestation(
        libCredential.Credential[] memory credentialList
    ) public returns (bytes32[] memory) {
        bytes32[] memory digest = new bytes32[](credentialList.length);

        for (uint256 i = 0; i < credentialList.length; ) {
            libCredential.Credential memory currentCredential = credentialList[
                i
            ];
            bytes32 currentDigest = convertToAttestation(currentCredential);
            digest[i] = currentDigest;
        }
        return digest;
    }

    /**
     * @dev revoke certain attestation. Designed for the attester themselves.
     * @param digest, the digest of the attestation to be revoked
     *
     * @return Returns the timestamp of the revocation.
     */
    function revoke(bytes32 digest) public returns (uint64) {
        if (_revokeDB[digest][msg.sender] != 0) {
            revert AlreadyRevoked();
        }
        _revokeDB[digest][msg.sender] = _time();
        emit Revoke(msg.sender, digest);
        return _revokeDB[digest][msg.sender];
    }

    /**
     * @dev revoke attestations in batch. Designed for the attester themselves.
     * @param digestList, the digest of the attestations to be revoked
     *
     * @return Returns the timestamp of the revocation.
     */
    function multiRevoke(bytes32[] memory digestList) public returns (uint64) {
        for (uint256 i = 0; i < digestList.length; ) {
            revoke(digestList[i]);
        }
        return _time();
    }

    /**
     * @dev revoke attestation with attester's signature. The signature must match the digest to be revoked.
     * @param revocationWithSigList, the digest, signature, attester of the attestation to be revoked
     * 
     * @return Returns the timestamp of the revocation.

     */
    function revokeWithSig(
        libRevocation.RevocationWithSig[] memory revocationWithSigList
    ) public returns (uint64) {
        for (uint256 i = 0; i < revocationWithSigList.length; ) {
            libRevocation.RevocationWithSig
                memory currentRevocation = revocationWithSigList[i];
            if (libRevocation.verifySignature(currentRevocation) == false) {
                revert RevokeWithInvalidSig();
            }
            _revokeDB[currentRevocation.digest][
                currentRevocation.attester
            ] = _time();
        }
        return _time();
    }

    /**
     * @dev revoke attestation with attester's signature. The signature must match the digest to be revoked.
     * @param multiRevocationWithSigList, the digest, signature, attester of the attestation to be revoked
     * 
     * @return Returns the timestamp of the revocation.

     */
    function multiRevokeWithSig(
        libRevocation.MultiRevocationWithSig[] memory multiRevocationWithSigList
    ) public returns (uint64) {
        for (uint256 i = 0; i < multiRevocationWithSigList.length; ) {
            libRevocation.MultiRevocationWithSig
                memory currentRevocation = multiRevocationWithSigList[i];
            if (
                libRevocation.verifyMultiSignature(currentRevocation) == false
            ) {
                revert RevokeWithInvalidSig();
            }

            for (uint256 j = 0; j < currentRevocation.digest.length; ) {
                _revokeDB[currentRevocation.digest[j]][
                    currentRevocation.attester
                ] = _time();
                emit RevokeWithSig(
                    msg.sender,
                    currentRevocation.digest[j],
                    currentRevocation.attester
                );
            }
        }
        return _time();
    }

    /**
     * @dev check whether the attestation is valid and hasn't been revoked yet.
     * @param digest, the digest of the attestation to be checked
     *
     * @return Returns the check result
     */
    function isAttestationValid(bytes32 digest) public view returns (bool) {
        address attester = _db[digest].attester;
        if (
            _db[digest].digest == bytes32(0) || _revokeDB[digest][attester] != 0
        ) {
            return false;
        }
        return true;
    }

    /**
     * @dev fetch the attestation on-chain, no matter whether the attestation is revoked
     * @param digest, the digest of the attestation to be checked
     *
     * @return Returns the attestation stored on-chain
     */
    function getAttestation(
        bytes32 digest
    ) public view returns (libAttestation.Attestation memory) {
        return _db[digest];
    }

    /**
     * @dev Returns the current's block timestamp. This method is overridden during tests and used to simulate the
     * current block time.
     */
    function _time() internal view returns (uint64) {
        return uint64(block.timestamp);
    }
}

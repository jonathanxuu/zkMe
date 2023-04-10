// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.8.9;

import {libCredential} from "./library/libCredential.sol";
import {libAttestation} from "./library/libAttestation.sol";
import {ICTypeRegistry} from "./ICTypeRegistry.sol";
import {IConverter} from "./IConverter.sol";
import {EIP712Verifier} from "./EIP712Verifier.sol";
import {RevocationWithSig, MultiRevocationWithSig} from "./Types.sol";
import {ICTypeResolver} from "./ICTypeResolver.sol";

/**
 * @title Converter
 * @dev used to convert Credential to Attestation on-chain. The contract will do the verification job.
 */

contract Converter is IConverter, EIP712Verifier {
    // checking the attestation details via its digest
    mapping(bytes32 => libAttestation.Attestation) private _db;

    // store the timestamp of the revocation
    mapping(bytes32 => mapping(address => uint64)) private _revokeDB;

    // The global schema registry.
    ICTypeRegistry private immutable _ctypeRegistry;

    // todo: list all error scenairos
    error DigestInvalid();
    error RoothashInvalid();
    error SignatureInvalid();
    error AttestationAlreadyExist();
    error AttestationNotExist();
    error AlreadyRevoked();
    error RevokeWithInvalidSig();
    error InvalidRegistry();
    error CTypeNotExist();
    error StoreOnResolverFailed();
    /**
     * @dev The constructor function of the Converter Contract.
     *
     * @param registry The address of the global ctype registry.
     */
    constructor(ICTypeRegistry registry) {
        if (address(registry) == address(0)) {
            revert InvalidRegistry();
        }

        _ctypeRegistry = registry;
    }

    /**
     * @inheritdoc IConverter
     */
    function getSchemaRegistry() external view returns (ICTypeRegistry) {
        return _ctypeRegistry;
    }

    /**
     * @inheritdoc IConverter
     */
    function convertToAttestation(
        libCredential.Credential memory credential
    ) external returns (bytes32) {
        return _convertToAttestation(credential);
    }

    /**
     * @inheritdoc IConverter
     */
    function multiConvertToAttestation(
        libCredential.Credential[] memory credentialList
    ) external returns (bytes32[] memory) {
        bytes32[] memory digest = new bytes32[](credentialList.length);

        for (uint256 i = 0; i < credentialList.length; ) {
            libCredential.Credential memory currentCredential = credentialList[
                i
            ];
            bytes32 currentDigest = _convertToAttestation(currentCredential);
            digest[i] = currentDigest;
        }
        return digest;
    }

    /**
     * @inheritdoc IConverter
     */
    function revoke(bytes32 digest) external returns (uint64) {
        return _revoke(digest, msg.sender);
    }

    /**
     * @inheritdoc IConverter
     */
    function multiRevoke(
        bytes32[] memory digestList
    ) external returns (uint64) {
        for (uint256 i = 0; i < digestList.length; ) {
            _revoke(digestList[i], msg.sender);
        }
        return _time();
    }

    /**
     * @inheritdoc IConverter
     */
    function revokeWithSig(
        RevocationWithSig[] memory revocationWithSigList
    ) external returns (uint64) {
        for (uint256 i = 0; i < revocationWithSigList.length; ) {
            RevocationWithSig memory currentRevocation = revocationWithSigList[
                i
            ];
            if (_verifyRevoke(currentRevocation) == false) {
                revert RevokeWithInvalidSig();
            }
            _revokeDB[currentRevocation.digest][
                currentRevocation.attester
            ] = _time();
        }
        return _time();
    }

    /**
     * @inheritdoc IConverter
     */
    function multiRevokeWithSig(
        MultiRevocationWithSig[] memory multiRevocationWithSigList
    ) external returns (uint64) {
        for (uint256 i = 0; i < multiRevocationWithSigList.length; ) {
            MultiRevocationWithSig
                memory currentRevocation = multiRevocationWithSigList[i];
            if (_verifyMultiRevoke(currentRevocation) == false) {
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
     * @inheritdoc IConverter
     */
    function validityCheck(bytes32 digest) external view returns (bool) {
        address attester = _db[digest].attester;
        if (
            _db[digest].digest == bytes32(0) || _revokeDB[digest][attester] != 0
        ) {
            return false;
        }
        return true;
    }

    /**
     * @inheritdoc IConverter
     */
    function getAttestation(
        bytes32 digest
    ) external view returns (libAttestation.Attestation memory) {
        return _db[digest];
    }

    /**
     * @dev convert the Credential to attestation on-chain
     * @param credential, the credential to be converted
     *
     * @return Returns the digest of the attestation
     */
    function _convertToAttestation(
        libCredential.Credential memory credential
    ) internal returns (bytes32) {
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

        ICTypeResolver CTypeResolver = _ctypeRegistry.getResolver(
            credential.ctype,
            credential.attester
        );
        // if the data is empty this is a Private VC
        if (credential.data.length != 0){
            if (credential.roothash != CTypeResolver.computeRootHash(credential.data)) {
            revert RoothashInvalid();
            }
        }
        CTypeResolver.store(credential.data, credential.digest);
        libAttestation.Attestation memory attestation = libAttestation
            .fillAttestation(credential);
        _db[attestation.digest] = attestation;

        emit ConvertSuccess(attestation.digest);
        return attestation.digest;
    }

    /**
     * @dev revoke certain attestation. Designed for the attester themselves.
     * @param digest, the digest of the attestation to be revoked
     * @param revoker, the revoker address of the attestation
     *
     * @return Returns the timestamp of the revocation.
     */
    function _revoke(
        bytes32 digest,
        address revoker
    ) internal returns (uint64) {
        if (_revokeDB[digest][revoker] != 0) {
            revert AlreadyRevoked();
        }
        _revokeDB[digest][revoker] = _time();
        emit Revoke(revoker, digest);
        return _revokeDB[digest][revoker];
    }

    /**
     * @dev Returns the current's block timestamp. This method is overridden during tests and used to simulate the
     * current block time.
     */
    function _time() internal view returns (uint64) {
        return uint64(block.timestamp);
    }
}

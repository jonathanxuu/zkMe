// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { EIP712Signature, RevocationWithSig, MultiRevocationWithSig } from "./Types.sol";


contract EIP712Verifier is EIP712 {
    // The hash of the data type used to revoke attestation.
	bytes32 private constant REVOKE_TYPEHASH =
		keccak256("Revoke(bytes32 digest,address attester)");

        // The hash of the data type used to multi-revoke attestation.
	bytes32 private constant MULTI_REVOKE_TYPEHASH =
		keccak256("Revoke(bytes32[] digest,address attester)");

	constructor() EIP712("EIP712 Verifier", "1") {}

    /**
     * Returns the EIP712 type hash for the revoke function.
     */
    function getRevokeTypeHash() external pure returns (bytes32) {
        return REVOKE_TYPEHASH;
    }

    /**
     * @dev Returns the domain separator used in the encoding of the signatures for revocation。
     */
	function DOMAIN_SEPARATOR() external view returns (bytes32) {
		return _domainSeparatorV4();
	}

    /**
     * @dev Verifies delegated revocation request.
     *
     * @param request The arguments of the delegated revocation request.
     */
    function _verifyRevoke(RevocationWithSig memory request) internal pure returns (bool) {
        EIP712Signature memory signature = request.revocationSignature;

        bytes32 structHash = keccak256(abi.encode(REVOKE_TYPEHASH, request.digest, request.attester));

        if (ECDSA.recover(structHash, signature.v, signature.r, signature.s) != request.attester) {
            return false;
        }
        return true;
    }

        /**
     * @dev Verifies delegated multi revocation request.
     *
     * @param request The arguments of the delegated revocation request.
     */
    function _verifyMultiRevoke(MultiRevocationWithSig memory request) internal pure returns (bool) {
        EIP712Signature memory signature = request.revocationSignature;

        bytes32 structHash = keccak256(abi.encode(MULTI_REVOKE_TYPEHASH, request.digest, request.attester));

        if (ECDSA.recover(structHash, signature.v, signature.r, signature.s) != request.attester) {
            return false;
        }
        return true;
    }
}
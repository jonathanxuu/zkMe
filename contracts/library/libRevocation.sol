// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.9;

// this library defines the struct and the functions of a Revocation Behavior
library libRevocation {
    struct RevocationWithSig {
        bytes32 digest;
        address attester;
        bytes revocationSignature;
    }

    struct MultiRevocationWithSig {
        bytes32[] digest;
        address attester;
        bytes revocationSignature;
    }

    /**
     * @dev verify whether the signature is signed by the attester
     * @param revocationWithSigData, the credential to be verified
     */
    function verifySignature(
        RevocationWithSig memory revocationWithSigData
    ) public pure returns (bool) {
        // todo: defines a signature way for MultiRevocation
        // the require below needs to be replaced with real verification method
        require(revocationWithSigData.digest[1] != 0);

        return true;
    }

    /**
     * @dev verify whether the signature is signed by the attester
     * @param revocationWithSigData, the credential to be verified
     */
    function verifyMultiSignature(
        MultiRevocationWithSig memory revocationWithSigData
    ) public pure returns (bool) {
        // todo: defines a signature way for MultiRevocation
        // the require below needs to be replaced with real verification method
        require(revocationWithSigData.digest[1] != 0);

        return true;
    }
}

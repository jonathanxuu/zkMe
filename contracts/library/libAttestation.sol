// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.9;

import {libCredential} from "./libCredential.sol";

// this library defines the struct and the functions of an attestation
library libAttestation {
    struct ConverterDetail {
        uint64 convertDate;
        address converter;
    }

    struct Attestation {
        bytes2 version;
        bytes32 ctype;
        bytes32 digest;
        string[] data;
        // bytes[] data;
        address claimer;
        address attester;
        uint64 issuanceDate;
        uint64 expirationDate;
        ConverterDetail converterDetail;
    }

    /**
     * @dev fill the attestation with the VC
     * @param credential, the credential to be verified
     */
    function fillAttestation(
        libCredential.Credential memory credential,
        address converter
    ) public view returns (Attestation memory attestation) {
        ConverterDetail memory converterDetail = ConverterDetail(
            _time(),
            converter
        );

        attestation.version = credential.version;
        attestation.ctype = credential.ctype;
        attestation.digest = credential.digest;
        attestation.data = credential.data;
        attestation.claimer = credential.claimer;
        attestation.attester = credential.attester;
        attestation.issuanceDate = credential.issuanceDate;
        attestation.expirationDate = credential.expirationDate;
        attestation.converterDetail = converterDetail;

        return attestation;
    }

    /**
     * @dev Returns the current's block timestamp. This method is overridden during tests and used to simulate the
     * current block time.
     */
    function _time() internal view returns (uint64) {
        return uint64(block.timestamp);
    }
}

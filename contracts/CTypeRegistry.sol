// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.8.9;
import {ICTypeRegistry, CTypeRecord} from "./ICTypeRegistry.sol";

/**
 * @title The global CType registry.
 */
contract CTypeRegistry is ICTypeRegistry {
    error AlreadyExists();
    error CTypeRecordNotValid();

    // The global mapping between CTypeHash and Register and the CTypeRecord
    mapping(bytes32 => mapping(address => CTypeRecord)) private _registry;

    /**
     * @inheritdoc ICTypeRegistry
     */
    function register(
        CTypeRecord memory ctypeRecord,
        bytes32 ctypeHash
    ) external {
        if (_checkCTypeRecord(ctypeRecord) == false) {
            revert CTypeRecordNotValid();
        }

        if (_registry[ctypeHash][msg.sender].fieldData.length != 0) {
            revert AlreadyExists();
        }

        _registry[ctypeHash][msg.sender] = ctypeRecord;

        emit Registered(ctypeHash, msg.sender);
    }

    /**
     * @inheritdoc ICTypeRegistry
     */
    function getCType(
        bytes32 ctypeHash,
        address registerer
    ) external view returns (CTypeRecord memory) {
        return _registry[ctypeHash][registerer];
    }

    /**
     * @dev Check whether the CTypeRecord is a valid one.
     *
     * @param ctypeRecord The CTypeRecord of the CType.
     *
     * @return The checking result.
     */
    function _checkCTypeRecord(
        CTypeRecord memory ctypeRecord
    ) private pure returns (bool) {
        if (ctypeRecord.fieldData.length == ctypeRecord.fieldType.length) {
            return true;
        }
        return false;
    }
}

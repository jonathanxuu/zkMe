// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.8.9;
import {ICTypeResolver} from "./ICTypeResolver.sol";

/**
 * @title The global CType registry interface.
 */
interface ICTypeRegistry {
    /**
     * @dev Emitted when a new CType has been registered
     *
     * @param ctypeHash The CTypeHash which has been registered.
     * @param registerer The address of the account used to register the CType.
     * @param CTypeResolver The address of the Resolver Contract.
     */
    event Registered(bytes32 indexed ctypeHash, address registerer, ICTypeResolver CTypeResolver);

    /**
     * @dev Submits and Register a new CType
     *
     * @param ctypeHash The CTypeHash which to been registered.
     * @param CTypeResolver The address of the Resolver Contract.
     */
    function register(
        bytes32 ctypeHash,
        ICTypeResolver CTypeResolver
    ) external;

    /**
     * @dev Returns an existing CType by UID
     *
     * @param ctypeHash The UID of the CType to retrieve.
     * @param registerer The address of the register
     *
     * @return The address of the Resolver Contract.
     */
    function getResolver(
        bytes32 ctypeHash,
        address registerer
    ) external view returns (ICTypeResolver);
}

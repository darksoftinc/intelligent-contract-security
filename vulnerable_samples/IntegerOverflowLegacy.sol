// SPDX-License-Identifier: MIT
pragma solidity 0.6.12;

contract IntegerOverflowLegacy {
    uint8 public x;

    function add(uint8 y) external {
        x = x + y;
    }

    function inc() external {
        x++;
    }
}

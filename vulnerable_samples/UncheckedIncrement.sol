// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract UncheckedIncrement {
    uint256 public counter;

    function inc() external {
        unchecked { counter++; }
    }
}

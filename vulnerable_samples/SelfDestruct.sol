// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SelfDestruct {
    function destroy() external {
        selfdestruct(payable(msg.sender));
    }

    receive() external payable {}
}

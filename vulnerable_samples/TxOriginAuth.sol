// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TxOriginAuth {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function withdraw(address payable to) external {
        require(tx.origin == owner, "not owner");
        (bool ok, ) = to.call{value: address(this).balance}("");
        require(ok, "fail");
    }

    receive() external payable {}
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SendEtherIgnore {
    function pay(address payable to) external payable {
        to.send(msg.value);
    }
}

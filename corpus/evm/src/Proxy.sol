// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.19;

contract Proxy {
    bytes32 private constant IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    bytes32 private constant ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

    event Upgraded(address indexed implementation);
    event AdminChanged(address previousAdmin, address newAdmin);

    constructor(address implementation_) {
        _setImplementation(implementation_);
        assembly {
            sstore(ADMIN_SLOT, caller())
        }
    }

    function implementation() external view returns (address impl) {
        assembly {
            impl := sload(IMPLEMENTATION_SLOT)
        }
    }

    function upgradeTo(address newImplementation) external {
        require(msg.sender == _admin(), "Proxy: caller is not the admin");
        _setImplementation(newImplementation);
    }

    function changeAdmin(address newAdmin) external {
        address previous = _admin();
        require(msg.sender == previous, "Proxy: caller is not the admin");
        assembly {
            sstore(ADMIN_SLOT, newAdmin)
        }
        emit AdminChanged(previous, newAdmin);
    }

    fallback() external payable {
        assembly {
            let impl := sload(IMPLEMENTATION_SLOT)
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}

    function _admin() private view returns (address admin) {
        assembly {
            admin := sload(ADMIN_SLOT)
        }
    }

    function _setImplementation(address newImplementation) private {
        require(newImplementation.code.length > 0, "Proxy: implementation is not a contract");
        assembly {
            sstore(IMPLEMENTATION_SLOT, newImplementation)
        }
        emit Upgraded(newImplementation);
    }
}

contract CloneFactory {
    event Cloned(address indexed implementation, address instance);

    function clone(address implementation) external returns (address instance) {
        assembly {
            mstore(0x00, or(shr(0xe8, shl(0x60, implementation)), 0x3d602d80600a3d3981f3363d3d373d3d3d363d730000000000))
            mstore(0x20, or(shl(0x78, implementation), 0x5af43d82803e903d91602b57fd5bf3))
            instance := create(0, 0x09, 0x37)
        }
        require(instance != address(0), "CloneFactory: create failed");
        emit Cloned(implementation, instance);
    }
}

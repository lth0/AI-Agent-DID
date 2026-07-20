// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract AgentLineageRegistry {
    uint256 private constant SECP256K1N_HALF =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    bytes32 private constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 private constant ENVELOPE_TYPEHASH = keccak256(
        "AgentLineageEnvelope(string purpose,bytes32 payloadHash)"
    );
    bytes32 private constant NAME_HASH = keccak256("AgentLineage-DID");
    bytes32 private constant VERSION_HASH = keccak256("1");

    struct RootRecord {
        address governance;
        uint64 currentEpoch;
        address delegationKey;
        bytes32 epochCertificateHash;
        bool active;
    }

    struct DelegationRecord {
        bytes32 rootId;
        bytes32 parentCredentialId;
        bytes32 credentialHash;
        bytes32 parentId;
        bytes32 childId;
        bytes32 edgeId;
        bytes32 lineageCommitment;
        bytes32 policyHash;
        bytes32 budgetId;
        bytes32 replicaGroupId;
        address operationKey;
        address delegationKey;
        uint64 epoch;
        uint64 expiresAt;
        bool exists;
        bool revoked;
    }

    struct Budget {
        bytes32 rootId;
        bytes32 ownerCredentialId;
        bytes32 parentBudgetId;
        uint64 limitCalls;
        uint64 limitCost;
        uint32 limitConcurrency;
        uint64 spentCalls;
        uint64 spentCost;
        uint32 activeConcurrency;
        uint64 reservedCalls;
        uint64 reservedCost;
        uint32 reservedConcurrency;
        bool exists;
        bool closed;
    }

    struct InvocationLease {
        bytes32 budgetId;
        bytes32 credentialId;
        address executor;
        uint64 expiresAt;
        bool active;
    }

    struct ReplicaGroupRecord {
        bytes32 rootId;
        bytes32 parentBudgetId;
        bytes32 budgetId;
        bool exists;
        bool closed;
    }

    mapping(bytes32 => RootRecord) public roots;
    mapping(bytes32 => mapping(uint64 => bool)) public revokedEpochs;
    mapping(bytes32 => DelegationRecord) public delegations;
    mapping(bytes32 => Budget) public budgets;
    mapping(bytes32 => InvocationLease) public invocations;
    mapping(bytes32 => ReplicaGroupRecord) public replicaGroups;
    mapping(bytes32 => bytes32) public budgetReplicaGroups;
    mapping(bytes32 => mapping(bytes32 => bool)) public revokedEdges;
    mapping(bytes32 => mapping(bytes32 => bool)) public revokedNodes;
    mapping(bytes32 => bool) public usedRequestHashes;

    event RootRegistered(bytes32 indexed rootId, address indexed governance, uint64 epoch);
    event EpochRotated(bytes32 indexed rootId, uint64 indexed epoch, address delegationKey);
    event DelegationRegistered(
        bytes32 indexed credentialId, bytes32 indexed parentCredentialId, bytes32 indexed childId
    );
    event BudgetCreated(bytes32 indexed budgetId, bytes32 indexed parentBudgetId, uint64 calls, uint64 cost);
    event ReplicaGroupCreated(bytes32 indexed groupId, bytes32 indexed budgetId, bytes32 parentBudgetId);
    event InvocationStarted(bytes32 indexed requestHash, bytes32 indexed budgetId, bytes32 credentialId);
    event InvocationFinished(bytes32 indexed requestHash, bytes32 indexed budgetId);
    event StatusRevoked(bytes32 indexed rootId, bytes32 indexed subject, uint8 kind);

    modifier onlyGovernance(bytes32 rootId) {
        require(roots[rootId].active, "ROOT_INACTIVE");
        require(msg.sender == roots[rootId].governance, "NOT_GOVERNANCE");
        _;
    }

    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(
            DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)
        ));
    }

    function registerRoot(
        bytes32 rootId,
        uint64 epoch,
        address delegationKey,
        bytes32 epochCertificateHash
    ) external {
        require(!roots[rootId].active, "ROOT_EXISTS");
        require(delegationKey != address(0), "ZERO_DELEGATION_KEY");
        roots[rootId] = RootRecord({
            governance: msg.sender,
            currentEpoch: epoch,
            delegationKey: delegationKey,
            epochCertificateHash: epochCertificateHash,
            active: true
        });
        emit RootRegistered(rootId, msg.sender, epoch);
    }

    function rotateEpoch(
        bytes32 rootId,
        uint64 newEpoch,
        address delegationKey,
        bytes32 epochCertificateHash,
        bool revokePrevious
    ) external onlyGovernance(rootId) {
        RootRecord storage root = roots[rootId];
        require(newEpoch > root.currentEpoch, "EPOCH_NOT_INCREASING");
        require(delegationKey != address(0), "ZERO_DELEGATION_KEY");
        if (revokePrevious) revokedEpochs[rootId][root.currentEpoch] = true;
        root.currentEpoch = newEpoch;
        root.delegationKey = delegationKey;
        root.epochCertificateHash = epochCertificateHash;
        emit EpochRotated(rootId, newEpoch, delegationKey);
    }

    function registerDelegation(
        bytes32 credentialId,
        bytes32 parentCredentialId,
        bytes32 credentialHash,
        bytes32 parentCredentialHash,
        bytes32 rootId,
        bytes32 parentId,
        bytes32 childId,
        bytes32 edgeId,
        bytes32 lineageCommitment,
        bytes32 policyHash,
        bytes32 budgetId,
        bytes32 replicaGroupId,
        address operationKey,
        address delegationKey,
        uint64 expiresAt,
        bytes calldata authorization
    ) external {
        require(!delegations[credentialId].exists, "DELEGATION_EXISTS");
        RootRecord storage root = roots[rootId];
        require(root.active, "ROOT_INACTIVE");
        require(expiresAt > block.timestamp, "DELEGATION_EXPIRED");
        require(operationKey != address(0), "ZERO_OPERATION_KEY");
        if (replicaGroupId != bytes32(0)) {
            ReplicaGroupRecord storage group = replicaGroups[replicaGroupId];
            require(group.exists && !group.closed, "REPLICA_GROUP_INACTIVE");
            require(group.rootId == rootId && group.budgetId == budgetId, "REPLICA_GROUP_BINDING_MISMATCH");
        }

        address expectedSigner;
        uint64 epoch;
        if (parentCredentialId == bytes32(0)) {
            expectedSigner = root.delegationKey;
            epoch = root.currentEpoch;
            require(parentCredentialHash == root.epochCertificateHash, "EPOCH_HASH_MISMATCH");
        } else {
            DelegationRecord storage parent = delegations[parentCredentialId];
            require(parent.exists && !parent.revoked, "PARENT_INACTIVE");
            require(parent.rootId == rootId, "CROSS_ROOT_PARENT");
            require(!revokedNodes[rootId][parent.childId], "PARENT_NODE_REVOKED");
            require(!revokedEdges[rootId][parent.edgeId], "PARENT_EDGE_REVOKED");
            require(parent.delegationKey != address(0), "PARENT_NOT_DELEGABLE");
            require(parent.expiresAt >= expiresAt, "EXPIRY_ESCALATION");
            require(parent.credentialHash == parentCredentialHash, "PARENT_HASH_MISMATCH");
            expectedSigner = parent.delegationKey;
            epoch = parent.epoch;
        }
        if (replicaGroupId != bytes32(0)) {
            ReplicaGroupRecord storage groupBinding = replicaGroups[replicaGroupId];
            if (parentCredentialId == bytes32(0)) {
                Budget storage groupParent = budgets[groupBinding.parentBudgetId];
                require(
                    groupParent.rootId == rootId && groupParent.ownerCredentialId == bytes32(0),
                    "REPLICA_GROUP_PARENT_MISMATCH"
                );
            } else {
                require(
                    groupBinding.parentBudgetId == delegations[parentCredentialId].budgetId,
                    "REPLICA_GROUP_PARENT_MISMATCH"
                );
            }
        }
        require(!revokedEpochs[rootId][epoch], "EPOCH_REVOKED");

        bytes32 payloadHash = keccak256(abi.encode(
            credentialId, parentCredentialId, credentialHash, parentCredentialHash,
            rootId, parentId, childId, edgeId, lineageCommitment, policyHash,
            budgetId, replicaGroupId, operationKey, delegationKey, expiresAt
        ));
        require(
            _recoverEnvelope("AgentLineage/REGISTER_DELEGATION/v1", payloadHash, authorization)
                == expectedSigner,
            "INVALID_DELEGATION_AUTH"
        );
        delegations[credentialId] = DelegationRecord({
            rootId: rootId,
            parentCredentialId: parentCredentialId,
            credentialHash: credentialHash,
            parentId: parentId,
            childId: childId,
            edgeId: edgeId,
            lineageCommitment: lineageCommitment,
            policyHash: policyHash,
            budgetId: budgetId,
            replicaGroupId: replicaGroupId,
            operationKey: operationKey,
            delegationKey: delegationKey,
            epoch: epoch,
            expiresAt: expiresAt,
            exists: true,
            revoked: false
        });
        emit DelegationRegistered(credentialId, parentCredentialId, childId);
    }

    function createRootBudget(
        bytes32 budgetId,
        bytes32 rootId,
        uint64 calls,
        uint64 cost,
        uint32 concurrency
    ) external onlyGovernance(rootId) {
        require(!budgets[budgetId].exists, "BUDGET_EXISTS");
        _requireNonZeroBudget(calls, cost, concurrency);
        budgets[budgetId] = Budget({
            rootId: rootId, ownerCredentialId: bytes32(0), parentBudgetId: bytes32(0),
            limitCalls: calls, limitCost: cost, limitConcurrency: concurrency,
            spentCalls: 0, spentCost: 0, activeConcurrency: 0,
            reservedCalls: 0, reservedCost: 0, reservedConcurrency: 0,
            exists: true, closed: false
        });
        emit BudgetCreated(budgetId, bytes32(0), calls, cost);
    }

    function reserveChildBudget(
        bytes32 parentBudgetId,
        bytes32 childBudgetId,
        bytes32 ownerCredentialId,
        uint64 calls,
        uint64 cost,
        uint32 concurrency,
        bytes calldata authorization
    ) external {
        Budget storage parent = budgets[parentBudgetId];
        require(parent.exists && !parent.closed, "PARENT_BUDGET_INACTIVE");
        require(budgetReplicaGroups[parentBudgetId] == bytes32(0), "REPLICA_GROUP_CANNOT_DELEGATE");
        require(!budgets[childBudgetId].exists, "CHILD_BUDGET_EXISTS");
        DelegationRecord storage owner = delegations[ownerCredentialId];
        require(owner.exists && !owner.revoked, "OWNER_CREDENTIAL_INACTIVE");
        require(owner.rootId == parent.rootId && owner.budgetId == childBudgetId, "BUDGET_BINDING_MISMATCH");
        _requireNonZeroBudget(calls, cost, concurrency);
        require(parent.spentCalls + parent.reservedCalls + calls <= parent.limitCalls, "CALL_BUDGET_EXCEEDED");
        require(parent.spentCost + parent.reservedCost + cost <= parent.limitCost, "COST_BUDGET_EXCEEDED");
        require(
            uint256(parent.activeConcurrency) + parent.reservedConcurrency + concurrency
                <= parent.limitConcurrency,
            "CONCURRENCY_BUDGET_EXCEEDED"
        );

        address expectedSigner = _budgetAuthority(parent);
        bytes32 payloadHash = keccak256(abi.encode(
            parentBudgetId, childBudgetId, ownerCredentialId, calls, cost, concurrency
        ));
        require(
            _recoverEnvelope("AgentLineage/RESERVE_BUDGET/v1", payloadHash, authorization)
                == expectedSigner,
            "INVALID_BUDGET_AUTH"
        );
        parent.reservedCalls += calls;
        parent.reservedCost += cost;
        parent.reservedConcurrency += concurrency;
        budgets[childBudgetId] = Budget({
            rootId: parent.rootId, ownerCredentialId: ownerCredentialId,
            parentBudgetId: parentBudgetId, limitCalls: calls, limitCost: cost,
            limitConcurrency: concurrency, spentCalls: 0, spentCost: 0,
            activeConcurrency: 0, reservedCalls: 0, reservedCost: 0,
            reservedConcurrency: 0, exists: true, closed: false
        });
        emit BudgetCreated(childBudgetId, parentBudgetId, calls, cost);
    }

    function createReplicaGroupBudget(
        bytes32 parentBudgetId,
        bytes32 groupId,
        bytes32 groupBudgetId,
        uint64 calls,
        uint64 cost,
        uint32 concurrency,
        bytes calldata authorization
    ) external {
        require(groupId != bytes32(0), "ZERO_REPLICA_GROUP");
        require(!replicaGroups[groupId].exists, "REPLICA_GROUP_EXISTS");
        Budget storage parent = budgets[parentBudgetId];
        require(parent.exists && !parent.closed, "PARENT_BUDGET_INACTIVE");
        require(budgetReplicaGroups[parentBudgetId] == bytes32(0), "NESTED_REPLICA_GROUP_FORBIDDEN");
        require(!budgets[groupBudgetId].exists, "GROUP_BUDGET_EXISTS");
        _requireNonZeroBudget(calls, cost, concurrency);
        require(parent.spentCalls + parent.reservedCalls + calls <= parent.limitCalls, "CALL_BUDGET_EXCEEDED");
        require(parent.spentCost + parent.reservedCost + cost <= parent.limitCost, "COST_BUDGET_EXCEEDED");
        require(
            uint256(parent.activeConcurrency) + parent.reservedConcurrency + concurrency
                <= parent.limitConcurrency,
            "CONCURRENCY_BUDGET_EXCEEDED"
        );
        bytes32 payloadHash = keccak256(abi.encode(
            parentBudgetId, groupId, groupBudgetId, calls, cost, concurrency
        ));
        require(
            _recoverEnvelope("AgentLineage/CREATE_REPLICA_GROUP/v1", payloadHash, authorization)
                == _budgetAuthority(parent),
            "INVALID_REPLICA_GROUP_AUTH"
        );
        parent.reservedCalls += calls;
        parent.reservedCost += cost;
        parent.reservedConcurrency += concurrency;
        budgets[groupBudgetId] = Budget({
            rootId: parent.rootId, ownerCredentialId: bytes32(0),
            parentBudgetId: parentBudgetId, limitCalls: calls, limitCost: cost,
            limitConcurrency: concurrency, spentCalls: 0, spentCost: 0,
            activeConcurrency: 0, reservedCalls: 0, reservedCost: 0,
            reservedConcurrency: 0, exists: true, closed: false
        });
        replicaGroups[groupId] = ReplicaGroupRecord({
            rootId: parent.rootId, parentBudgetId: parentBudgetId,
            budgetId: groupBudgetId, exists: true, closed: false
        });
        budgetReplicaGroups[groupBudgetId] = groupId;
        emit BudgetCreated(groupBudgetId, parentBudgetId, calls, cost);
        emit ReplicaGroupCreated(groupId, groupBudgetId, parentBudgetId);
    }

    function beginInvocation(
        bytes32 credentialId,
        bytes32 budgetId,
        bytes32 requestHash,
        uint64 costUnits,
        uint32 leaseSeconds,
        bytes calldata authorization
    ) external {
        DelegationRecord storage credential = delegations[credentialId];
        Budget storage budget = budgets[budgetId];
        require(credential.exists && !credential.revoked, "CREDENTIAL_INACTIVE");
        require(block.timestamp <= credential.expiresAt, "CREDENTIAL_EXPIRED");
        require(!revokedEpochs[credential.rootId][credential.epoch], "EPOCH_REVOKED");
        require(
            !revokedNodes[credential.rootId][credential.childId]
                && !revokedEdges[credential.rootId][credential.edgeId],
            "LINEAGE_REVOKED"
        );
        require(budget.exists && !budget.closed, "BUDGET_INACTIVE");
        if (credential.replicaGroupId == bytes32(0)) {
            require(
                budget.ownerCredentialId == credentialId && credential.budgetId == budgetId,
                "BUDGET_BINDING_MISMATCH"
            );
        } else {
            ReplicaGroupRecord storage group = replicaGroups[credential.replicaGroupId];
            require(group.exists && !group.closed, "REPLICA_GROUP_INACTIVE");
            require(
                group.rootId == credential.rootId && group.budgetId == budgetId
                    && credential.budgetId == budgetId,
                "REPLICA_GROUP_BINDING_MISMATCH"
            );
        }
        require(!usedRequestHashes[requestHash], "REQUEST_REPLAY");
        require(leaseSeconds > 0 && leaseSeconds <= 86400, "INVALID_LEASE");
        require(budget.spentCalls + budget.reservedCalls + 1 <= budget.limitCalls, "CALL_BUDGET_EXCEEDED");
        require(budget.spentCost + budget.reservedCost + costUnits <= budget.limitCost, "COST_BUDGET_EXCEEDED");
        require(
            uint256(budget.activeConcurrency) + budget.reservedConcurrency + 1
                <= budget.limitConcurrency,
            "CONCURRENCY_BUDGET_EXCEEDED"
        );

        require(
            _recoverEnvelope("AgentLineage/REQUEST/v1", requestHash, authorization)
                == credential.operationKey,
            "INVALID_INVOCATION_AUTH"
        );
        usedRequestHashes[requestHash] = true;
        budget.spentCalls += 1;
        budget.spentCost += costUnits;
        budget.activeConcurrency += 1;
        invocations[requestHash] = InvocationLease({
            budgetId: budgetId, credentialId: credentialId, executor: msg.sender,
            expiresAt: uint64(block.timestamp + leaseSeconds), active: true
        });
        emit InvocationStarted(requestHash, budgetId, credentialId);
    }

    function finishInvocation(bytes32 requestHash) external {
        InvocationLease storage lease = invocations[requestHash];
        require(lease.active, "INVOCATION_INACTIVE");
        DelegationRecord storage credential = delegations[lease.credentialId];
        require(
            msg.sender == lease.executor || msg.sender == roots[credential.rootId].governance,
            "NOT_INVOCATION_EXECUTOR"
        );
        _finishInvocation(requestHash, lease);
    }

    function reapExpiredInvocation(bytes32 requestHash) external {
        InvocationLease storage lease = invocations[requestHash];
        require(lease.active, "INVOCATION_INACTIVE");
        require(block.timestamp > lease.expiresAt, "LEASE_NOT_EXPIRED");
        _finishInvocation(requestHash, lease);
    }

    function closeBudget(bytes32 budgetId, bytes calldata authorization) external {
        Budget storage budget = budgets[budgetId];
        require(budget.exists && !budget.closed, "BUDGET_INACTIVE");
        require(budgetReplicaGroups[budgetId] == bytes32(0), "USE_REPLICA_GROUP_CLOSE");
        require(budget.parentBudgetId != bytes32(0), "ROOT_BUDGET_CANNOT_CLOSE");
        require(
            budget.activeConcurrency == 0 && budget.reservedCalls == 0
                && budget.reservedCost == 0 && budget.reservedConcurrency == 0,
            "BUDGET_HAS_ACTIVE_CHILDREN"
        );
        DelegationRecord storage owner = delegations[budget.ownerCredentialId];
        bytes32 payloadHash = keccak256(abi.encode(budgetId, budget.spentCalls, budget.spentCost));
        require(
            _recoverEnvelope("AgentLineage/CLOSE_BUDGET/v1", payloadHash, authorization)
                == owner.operationKey,
            "INVALID_CLOSE_AUTH"
        );
        Budget storage parent = budgets[budget.parentBudgetId];
        parent.reservedCalls -= budget.limitCalls;
        parent.reservedCost -= budget.limitCost;
        parent.reservedConcurrency -= budget.limitConcurrency;
        parent.spentCalls += budget.spentCalls;
        parent.spentCost += budget.spentCost;
        budget.closed = true;
    }

    function closeReplicaGroupBudget(bytes32 groupId, bytes calldata authorization) external {
        ReplicaGroupRecord storage group = replicaGroups[groupId];
        require(group.exists && !group.closed, "REPLICA_GROUP_INACTIVE");
        Budget storage budget = budgets[group.budgetId];
        require(
            budget.activeConcurrency == 0 && budget.reservedCalls == 0
                && budget.reservedCost == 0 && budget.reservedConcurrency == 0,
            "BUDGET_HAS_ACTIVE_CHILDREN"
        );
        Budget storage parent = budgets[group.parentBudgetId];
        bytes32 payloadHash = keccak256(abi.encode(
            groupId, group.budgetId, budget.spentCalls, budget.spentCost
        ));
        require(
            _recoverEnvelope("AgentLineage/CLOSE_REPLICA_GROUP/v1", payloadHash, authorization)
                == _budgetAuthority(parent),
            "INVALID_REPLICA_GROUP_CLOSE_AUTH"
        );
        parent.reservedCalls -= budget.limitCalls;
        parent.reservedCost -= budget.limitCost;
        parent.reservedConcurrency -= budget.limitConcurrency;
        parent.spentCalls += budget.spentCalls;
        parent.spentCost += budget.spentCost;
        budget.closed = true;
        group.closed = true;
    }

    function revokeCredential(bytes32 rootId, bytes32 credentialId)
        external onlyGovernance(rootId)
    {
        require(delegations[credentialId].rootId == rootId, "ROOT_MISMATCH");
        delegations[credentialId].revoked = true;
        emit StatusRevoked(rootId, credentialId, 1);
    }

    function revokeEdge(bytes32 rootId, bytes32 edgeId) external onlyGovernance(rootId) {
        revokedEdges[rootId][edgeId] = true;
        emit StatusRevoked(rootId, edgeId, 2);
    }

    function revokeNode(bytes32 rootId, bytes32 nodeId) external onlyGovernance(rootId) {
        revokedNodes[rootId][nodeId] = true;
        emit StatusRevoked(rootId, nodeId, 3);
    }

    function revokeEpoch(bytes32 rootId, uint64 epoch) external onlyGovernance(rootId) {
        revokedEpochs[rootId][epoch] = true;
        emit StatusRevoked(rootId, bytes32(uint256(epoch)), 4);
    }

    function getValidationState(
        bytes32 rootId,
        uint64 epoch,
        bytes32[] calldata credentialIds,
        bytes32[] calldata edgeIds,
        bytes32[] calldata nodeIds
    ) external view returns (bool active, bytes32 reason, uint256 checkedBlock) {
        if (!roots[rootId].active) return (false, "ROOT_INACTIVE", block.number);
        if (revokedEpochs[rootId][epoch]) return (false, "EPOCH_REVOKED", block.number);
        for (uint256 i = 0; i < credentialIds.length; i++) {
            DelegationRecord storage item = delegations[credentialIds[i]];
            if (item.rootId != rootId) return (false, "CREDENTIAL_ROOT_MISMATCH", block.number);
            if (!item.exists || item.revoked || item.expiresAt < block.timestamp) {
                return (false, "CREDENTIAL_INACTIVE", block.number);
            }
        }
        for (uint256 i = 0; i < edgeIds.length; i++) {
            if (revokedEdges[rootId][edgeIds[i]]) return (false, "EDGE_REVOKED", block.number);
        }
        for (uint256 i = 0; i < nodeIds.length; i++) {
            if (revokedNodes[rootId][nodeIds[i]]) return (false, "NODE_REVOKED", block.number);
        }
        return (true, bytes32(0), block.number);
    }

    function _budgetAuthority(Budget storage budget) internal view returns (address) {
        if (budget.ownerCredentialId == bytes32(0)) {
            require(budgetReplicaGroups[budget.parentBudgetId] == bytes32(0), "INVALID_BUDGET_AUTHORITY");
            return roots[budget.rootId].delegationKey;
        }
        DelegationRecord storage owner = delegations[budget.ownerCredentialId];
        require(owner.delegationKey != address(0), "BUDGET_OWNER_NOT_DELEGABLE");
        return owner.delegationKey;
    }

    function _requireNonZeroBudget(uint64 calls, uint64 cost, uint32 concurrency) internal pure {
        require(calls > 0 && cost > 0 && concurrency > 0, "ZERO_BUDGET_LIMIT");
    }

    function _finishInvocation(bytes32 requestHash, InvocationLease storage lease) internal {
        budgets[lease.budgetId].activeConcurrency -= 1;
        lease.active = false;
        emit InvocationFinished(requestHash, lease.budgetId);
    }

    function _recoverEnvelope(
        string memory purpose,
        bytes32 payloadHash,
        bytes calldata signature
    ) internal view returns (address) {
        bytes32 structHash = keccak256(abi.encode(
            ENVELOPE_TYPEHASH, keccak256(bytes(purpose)), payloadHash
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
        return _recover(digest, signature);
    }

    function _recover(bytes32 digest, bytes calldata signature) internal pure returns (address) {
        require(signature.length == 65, "INVALID_SIGNATURE_LENGTH");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (v < 27) v += 27;
        require(v == 27 || v == 28, "INVALID_SIGNATURE_V");
        require(uint256(s) <= SECP256K1N_HALF, "INVALID_SIGNATURE_S");
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "INVALID_SIGNATURE");
        return signer;
    }
}

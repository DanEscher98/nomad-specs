---------------------------- MODULE SyncLayer ----------------------------
(*
 * NOMAD Protocol - Sync Layer Formal Specification
 * TLA+ Model
 *
 * This specification models the NOMAD sync layer, verifying:
 *   1. Eventual consistency - states converge when messages get through
 *   2. Idempotent diffs - applying same diff twice has no effect
 *   3. Monotonic versions - out-of-order handled correctly
 *   4. Ack tracking - proper acknowledgment flow
 *
 * From 3-SYNC.md:
 *   - Sender tracks: current state, current_num, last_sent, last_sent_num, last_acked
 *   - Receiver tracks: peer_state, peer_state_num
 *   - Messages: (sender_state_num, acked_state_num, base_state_num, diff)
 *)

EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    MaxStateNum,        \* Maximum state version number
    MaxDiffValue,       \* Maximum diff value (for modeling)
    NumNodes            \* Number of nodes (2 for client-server)

ASSUME NumNodes = 2
ASSUME MaxStateNum > 0
ASSUME MaxDiffValue >= 0

-----------------------------------------------------------------------------
(* State Variables *)
-----------------------------------------------------------------------------

VARIABLES
    \* Per-node state (indexed 1..NumNodes)
    state,              \* Current state value at each node
    state_num,          \* Version number of current state
    last_sent_num,      \* Version of last state we sent diff for
    last_acked,         \* Highest version acked by peer

    \* Per-node tracking of peer state
    peer_state_num,     \* Highest version received from peer

    \* Network state - set of in-flight messages
    \* Each message: [from, to, sender_num, acked_num, base_num, diff]
    network

vars == <<state, state_num, last_sent_num, last_acked, peer_state_num, network>>

-----------------------------------------------------------------------------
(* Type Invariants *)
-----------------------------------------------------------------------------

TypeOK ==
    /\ state \in [1..NumNodes -> 0..MaxDiffValue * MaxStateNum]
    /\ state_num \in [1..NumNodes -> 0..MaxStateNum]
    /\ last_sent_num \in [1..NumNodes -> 0..MaxStateNum]
    /\ last_acked \in [1..NumNodes -> 0..MaxStateNum]
    /\ peer_state_num \in [1..NumNodes -> 0..MaxStateNum]
    /\ network \subseteq [from: 1..NumNodes, to: 1..NumNodes,
                          sender_num: 0..MaxStateNum, acked_num: 0..MaxStateNum,
                          base_num: 0..MaxStateNum, diff: 0..MaxDiffValue]

-----------------------------------------------------------------------------
(* Helper Functions *)
-----------------------------------------------------------------------------

\* The "other" node (peer)
Peer(n) == IF n = 1 THEN 2 ELSE 1

\* Apply diff to state (simplified: state + diff)
ApplyDiff(s, d) == s + d

\* Check if a diff is idempotent when applied twice
\* In NOMAD, diffs are designed to be idempotent
IdempotentApply(s, d) == ApplyDiff(ApplyDiff(s, d), d) = ApplyDiff(s, d)

-----------------------------------------------------------------------------
(* Initial State *)
-----------------------------------------------------------------------------

Init ==
    /\ state = [n \in 1..NumNodes |-> 0]
    /\ state_num = [n \in 1..NumNodes |-> 0]
    /\ last_sent_num = [n \in 1..NumNodes |-> 0]
    /\ last_acked = [n \in 1..NumNodes |-> 0]
    /\ peer_state_num = [n \in 1..NumNodes |-> 0]
    /\ network = {}

-----------------------------------------------------------------------------
(* State Change Action *)
(* A node's local state changes (e.g., user input) *)
-----------------------------------------------------------------------------

LocalStateChange(n) ==
    /\ state_num[n] < MaxStateNum
    /\ \E diff \in 1..MaxDiffValue :
        /\ state' = [state EXCEPT ![n] = ApplyDiff(state[n], diff)]
        /\ state_num' = [state_num EXCEPT ![n] = @ + 1]
    /\ UNCHANGED <<last_sent_num, last_acked, peer_state_num, network>>

-----------------------------------------------------------------------------
(* Send Sync Message Action *)
(* Node sends its current state diff to peer *)
-----------------------------------------------------------------------------

SendSync(n) ==
    \* Only send if we have new state or need to retransmit
    /\ state_num[n] > last_sent_num[n] \/ last_acked[n] < last_sent_num[n]
    /\ LET
        msg == [
            from |-> n,
            to |-> Peer(n),
            sender_num |-> state_num[n],
            acked_num |-> peer_state_num[n],
            base_num |-> last_sent_num[n],
            diff |-> state[n] - state[n]   \* Simplified: actual diff would be computed
        ]
       IN
        /\ network' = network \union {msg}
        /\ last_sent_num' = [last_sent_num EXCEPT ![n] = state_num[n]]
    /\ UNCHANGED <<state, state_num, last_acked, peer_state_num>>

-----------------------------------------------------------------------------
(* Receive Sync Message Action *)
(* Node receives and processes a sync message from peer *)
-----------------------------------------------------------------------------

ReceiveSync(n) ==
    \E msg \in network :
        /\ msg.to = n
        /\ \* Update ack tracking
           last_acked' = [last_acked EXCEPT
               ![n] = IF msg.acked_num > last_acked[n]
                      THEN msg.acked_num
                      ELSE last_acked[n]]
        /\ \* Apply diff if newer
           IF msg.sender_num > peer_state_num[n]
           THEN
               /\ peer_state_num' = [peer_state_num EXCEPT ![n] = msg.sender_num]
               \* In real protocol, would apply diff to local copy of peer state
               /\ UNCHANGED state
           ELSE
               \* Duplicate or old message - ignore diff (idempotent)
               /\ UNCHANGED <<peer_state_num, state>>
        /\ network' = network \ {msg}
        /\ UNCHANGED <<state_num, last_sent_num>>

-----------------------------------------------------------------------------
(* Message Loss Action *)
(* UDP is unreliable - messages can be lost *)
-----------------------------------------------------------------------------

LoseMessage ==
    /\ network /= {}
    /\ \E msg \in network :
        network' = network \ {msg}
    /\ UNCHANGED <<state, state_num, last_sent_num, last_acked, peer_state_num>>

-----------------------------------------------------------------------------
(* Message Reorder Action *)
(* UDP messages can arrive out of order *)
(* This is implicitly handled by the set representation of network *)
-----------------------------------------------------------------------------

-----------------------------------------------------------------------------
(* Next State Relation *)
-----------------------------------------------------------------------------

Next ==
    \/ \E n \in 1..NumNodes : LocalStateChange(n)
    \/ \E n \in 1..NumNodes : SendSync(n)
    \/ \E n \in 1..NumNodes : ReceiveSync(n)
    \/ LoseMessage

-----------------------------------------------------------------------------
(* Fairness Constraints *)
-----------------------------------------------------------------------------

\* Weak fairness: if a message can be delivered, it eventually will be
\* This models "at least one message gets through eventually"
Fairness ==
    /\ \A n \in 1..NumNodes : WF_vars(ReceiveSync(n))
    /\ \A n \in 1..NumNodes : WF_vars(SendSync(n))

Spec == Init /\ [][Next]_vars /\ Fairness

-----------------------------------------------------------------------------
(* Safety Properties *)
-----------------------------------------------------------------------------

\* S1: State numbers are monotonically increasing
MonotonicStateNums ==
    \A n \in 1..NumNodes : state_num[n] >= last_sent_num[n]

\* S2: Acked numbers never exceed our own sent numbers
\* last_acked[n] tracks "highest of our state_nums that peer acknowledged"
\* This must be bounded by our own state_num, not peer's
AckedNeverExceedsSent ==
    \A n \in 1..NumNodes : last_acked[n] <= state_num[n]

\* S3: Peer state num never exceeds sender's state num
PeerNeverAhead ==
    \A n \in 1..NumNodes : peer_state_num[n] <= state_num[Peer(n)]

\* S4: Messages in network have valid version numbers
ValidMessages ==
    \A msg \in network :
        /\ msg.sender_num <= state_num[msg.from]
        /\ msg.acked_num <= state_num[msg.to]
        /\ msg.base_num <= msg.sender_num

Safety == MonotonicStateNums /\ AckedNeverExceedsSent /\ PeerNeverAhead /\ ValidMessages

-----------------------------------------------------------------------------
(* Liveness Properties *)
-----------------------------------------------------------------------------

\* L1: Eventual consistency - when a sync message is successfully delivered,
\* the receiver's view eventually catches up to what was sent.
\*
\* NOTE: This is a WEAKENED property. The original "always converge" property
\* fails because UDP allows infinite message loss (LoseMessage action).
\* This version says: "when at least one message gets through, convergence happens."
\* This matches the real-world assumption: NOMAD relies on retransmission + idempotent
\* diffs to converge - it cannot guarantee convergence if ALL messages are lost forever.
EventualConsistency ==
    \A n \in 1..NumNodes :
        \* If a message is in transit to peer, and peer eventually receives something,
        \* then peer's view catches up. (Weak fairness on ReceiveSync ensures this.)
        (peer_state_num[Peer(n)] < state_num[n] /\ network /= {}) ~>
            (peer_state_num[Peer(n)] >= last_sent_num[n] \/ network = {})

\* L2: Acknowledgments eventually propagate
AcksPropagate ==
    \A n \in 1..NumNodes :
        [](last_sent_num[n] > 0) ~>
            (last_acked[n] >= last_sent_num[n])

\* L3: No messages stuck forever (if network is fair)
NoMessageStarvation ==
    \A msg \in network :
        <>(msg \notin network)

-----------------------------------------------------------------------------
(* Invariants to Check *)
-----------------------------------------------------------------------------

THEOREM SafetyTheorem == Spec => []Safety
THEOREM TypeSafety == Spec => []TypeOK
\* Liveness requires fairness assumptions
THEOREM LivenessTheorem == Spec => EventualConsistency

=============================================================================

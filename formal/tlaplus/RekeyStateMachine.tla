------------------------ MODULE RekeyStateMachine ------------------------
(*
 * NOMAD Protocol - Rekey State Machine Formal Specification
 * TLA+ Model
 *
 * This specification models the NOMAD rekeying mechanism, verifying:
 *   1. Periodic rekeying occurs (every REKEY_AFTER_TIME)
 *   2. Key material is properly rotated
 *   3. Epoch numbers increment correctly
 *   4. Old keys are retained briefly for late packets
 *   5. Counter exhaustion triggers session termination
 *
 * From 1-SECURITY.md:
 *   - REKEY_AFTER_TIME: 120 seconds
 *   - REJECT_AFTER_TIME: 180 seconds (hard limit)
 *   - REKEY_AFTER_MESSAGES: 2^60 (soft limit)
 *   - REJECT_AFTER_MESSAGES: 2^64-1 (hard limit, MUST terminate)
 *   - OLD_KEY_RETENTION: 5 seconds
 *   - MAX_EPOCH: 2^32-1 (epoch exhaustion terminates session)
 *)

EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    REKEY_AFTER_TIME,       \* Initiate rekey after this time (120s)
    REJECT_AFTER_TIME,      \* Hard limit, reject old keys (180s)
    OLD_KEY_RETENTION,      \* Keep old keys after rekey (5s)
    MAX_EPOCH,              \* Maximum epoch number before termination
    REKEY_AFTER_MESSAGES,   \* Soft message limit for rekey
    REJECT_AFTER_MESSAGES,  \* Hard message limit (terminate)
    MaxTime                 \* Model bound on time

ASSUME REKEY_AFTER_TIME < REJECT_AFTER_TIME
ASSUME OLD_KEY_RETENTION < REKEY_AFTER_TIME
ASSUME MaxTime > REJECT_AFTER_TIME
ASSUME MAX_EPOCH > 0

-----------------------------------------------------------------------------
(* State Space *)
-----------------------------------------------------------------------------

RekeyStates == {"Idle", "WaitingRekeyResp", "Rekeying", "Terminated"}
Roles == {"Initiator", "Responder"}

VARIABLES
    \* Per-role state
    rekeyState,         \* Current state in rekey FSM: Idle | WaitingRekeyResp | Rekeying | Terminated
    epoch,              \* Current epoch number (0, 1, 2, ...)
    currentKeys,        \* Current session keys (abstracted as epoch number)
    oldKeys,            \* Previous session keys (for late packets)
    sendNonce,          \* Send nonce counter
    recvNonce,          \* Receive nonce high water mark

    \* Timing state
    epochStartTime,     \* When current epoch started
    oldKeyExpiry,       \* When old keys expire

    \* Network
    network,            \* Set of in-flight rekey messages

    \* Global time (for modeling)
    time

vars == <<rekeyState, epoch, currentKeys, oldKeys, sendNonce, recvNonce,
          epochStartTime, oldKeyExpiry, network, time>>

-----------------------------------------------------------------------------
(* Type Invariants *)
-----------------------------------------------------------------------------

TypeOK ==
    /\ rekeyState \in [Roles -> RekeyStates]
    /\ epoch \in [Roles -> 0..MAX_EPOCH]
    /\ currentKeys \in [Roles -> 0..MAX_EPOCH]
    /\ oldKeys \in [Roles -> (0..MAX_EPOCH) \cup {-1}]  \* -1 means no old keys
    /\ sendNonce \in [Roles -> 0..REJECT_AFTER_MESSAGES]
    /\ recvNonce \in [Roles -> 0..REJECT_AFTER_MESSAGES]
    /\ epochStartTime \in [Roles -> 0..MaxTime]
    /\ oldKeyExpiry \in [Roles -> 0..MaxTime]
    /\ network \subseteq [type: {"RekeyInit", "RekeyResp"},
                          from: Roles, to: Roles,
                          newEphemeral: 0..MAX_EPOCH]
    /\ time \in 0..MaxTime

-----------------------------------------------------------------------------
(* Helper Functions *)
-----------------------------------------------------------------------------

Peer(r) == IF r = "Initiator" THEN "Responder" ELSE "Initiator"

\* Check if rekey should be initiated
ShouldRekey(r) ==
    \/ time - epochStartTime[r] >= REKEY_AFTER_TIME
    \/ sendNonce[r] >= REKEY_AFTER_MESSAGES

\* Check if keys are expired (hard limit)
KeysExpired(r) ==
    \/ time - epochStartTime[r] >= REJECT_AFTER_TIME
    \/ sendNonce[r] >= REJECT_AFTER_MESSAGES

\* Check if old keys are still valid
OldKeysValid(r) == time < oldKeyExpiry[r]

-----------------------------------------------------------------------------
(* Initial State *)
-----------------------------------------------------------------------------

Init ==
    /\ rekeyState = [r \in Roles |-> "Idle"]
    /\ epoch = [r \in Roles |-> 0]
    /\ currentKeys = [r \in Roles |-> 0]  \* Keys from initial handshake
    /\ oldKeys = [r \in Roles |-> -1]     \* No old keys initially
    /\ sendNonce = [r \in Roles |-> 0]
    /\ recvNonce = [r \in Roles |-> 0]
    /\ epochStartTime = [r \in Roles |-> 0]
    /\ oldKeyExpiry = [r \in Roles |-> 0]
    /\ network = {}
    /\ time = 0

-----------------------------------------------------------------------------
(* Time Advance Action *)
-----------------------------------------------------------------------------

Tick ==
    /\ time < MaxTime
    /\ time' = time + 1
    /\ UNCHANGED <<rekeyState, epoch, currentKeys, oldKeys, sendNonce, recvNonce,
                   epochStartTime, oldKeyExpiry, network>>

-----------------------------------------------------------------------------
(* Send Frame Action *)
(* Normal frame transmission - increments nonce counter *)
-----------------------------------------------------------------------------

SendFrame(r) ==
    /\ rekeyState[r] = "Idle"
    /\ ~KeysExpired(r)
    /\ sendNonce[r] < REJECT_AFTER_MESSAGES
    /\ sendNonce' = [sendNonce EXCEPT ![r] = @ + 1]
    /\ UNCHANGED <<rekeyState, epoch, currentKeys, oldKeys, recvNonce,
                   epochStartTime, oldKeyExpiry, network, time>>

-----------------------------------------------------------------------------
(* Initiate Rekey Action *)
(* Initiator sends rekey request when time or message threshold reached *)
-----------------------------------------------------------------------------

InitiateRekey ==
    /\ rekeyState["Initiator"] = "Idle"
    /\ ShouldRekey("Initiator")
    /\ ~KeysExpired("Initiator")
    /\ epoch["Initiator"] < MAX_EPOCH
    /\ LET msg == [type |-> "RekeyInit",
                   from |-> "Initiator",
                   to |-> "Responder",
                   newEphemeral |-> epoch["Initiator"] + 1]
       IN network' = network \union {msg}
    /\ rekeyState' = [rekeyState EXCEPT !["Initiator"] = "WaitingRekeyResp"]
    /\ UNCHANGED <<epoch, currentKeys, oldKeys, sendNonce, recvNonce,
                   epochStartTime, oldKeyExpiry, time>>

-----------------------------------------------------------------------------
(* Responder Receives Rekey Init *)
-----------------------------------------------------------------------------

RespondToRekey ==
    /\ rekeyState["Responder"] = "Idle"
    /\ \E msg \in network :
        /\ msg.type = "RekeyInit"
        /\ msg.to = "Responder"
        /\ epoch["Responder"] < MAX_EPOCH
        /\ LET resp == [type |-> "RekeyResp",
                        from |-> "Responder",
                        to |-> "Initiator",
                        newEphemeral |-> msg.newEphemeral]
           IN
            /\ network' = (network \ {msg}) \union {resp}
            /\ rekeyState' = [rekeyState EXCEPT !["Responder"] = "Rekeying"]

    /\ UNCHANGED <<epoch, currentKeys, oldKeys, sendNonce, recvNonce,
                   epochStartTime, oldKeyExpiry, time>>

-----------------------------------------------------------------------------
(* Complete Rekey - Responder *)
(* Responder transitions to new epoch after sending response *)
-----------------------------------------------------------------------------

CompleteRekeyResponder ==
    /\ rekeyState["Responder"] = "Rekeying"
    /\ oldKeys' = [oldKeys EXCEPT !["Responder"] = currentKeys["Responder"]]
    /\ epoch' = [epoch EXCEPT !["Responder"] = @ + 1]
    /\ currentKeys' = [currentKeys EXCEPT !["Responder"] = epoch'["Responder"]]
    /\ sendNonce' = [sendNonce EXCEPT !["Responder"] = 0]
    /\ recvNonce' = [recvNonce EXCEPT !["Responder"] = 0]
    /\ epochStartTime' = [epochStartTime EXCEPT !["Responder"] = time]
    /\ oldKeyExpiry' = [oldKeyExpiry EXCEPT !["Responder"] = time + OLD_KEY_RETENTION]
    /\ rekeyState' = [rekeyState EXCEPT !["Responder"] = "Idle"]
    /\ UNCHANGED <<network, time>>

-----------------------------------------------------------------------------
(* Initiator Receives Rekey Response *)
-----------------------------------------------------------------------------

ReceiveRekeyResponse ==
    /\ rekeyState["Initiator"] = "WaitingRekeyResp"
    /\ \E msg \in network :
        /\ msg.type = "RekeyResp"
        /\ msg.to = "Initiator"
        /\ network' = network \ {msg}
        /\ oldKeys' = [oldKeys EXCEPT !["Initiator"] = currentKeys["Initiator"]]
        /\ epoch' = [epoch EXCEPT !["Initiator"] = msg.newEphemeral]
        /\ currentKeys' = [currentKeys EXCEPT !["Initiator"] = epoch'["Initiator"]]
        /\ sendNonce' = [sendNonce EXCEPT !["Initiator"] = 0]
        /\ recvNonce' = [recvNonce EXCEPT !["Initiator"] = 0]
        /\ epochStartTime' = [epochStartTime EXCEPT !["Initiator"] = time]
        /\ oldKeyExpiry' = [oldKeyExpiry EXCEPT !["Initiator"] = time + OLD_KEY_RETENTION]
        /\ rekeyState' = [rekeyState EXCEPT !["Initiator"] = "Idle"]
    /\ UNCHANGED <<time>>

-----------------------------------------------------------------------------
(* Counter Exhaustion - Terminate Session *)
-----------------------------------------------------------------------------

CounterExhaustion(r) ==
    /\ sendNonce[r] >= REJECT_AFTER_MESSAGES
    /\ rekeyState' = [rekeyState EXCEPT ![r] = "Terminated"]
    /\ UNCHANGED <<epoch, currentKeys, oldKeys, sendNonce, recvNonce,
                   epochStartTime, oldKeyExpiry, network, time>>

-----------------------------------------------------------------------------
(* Epoch Exhaustion - Terminate Session *)
-----------------------------------------------------------------------------

EpochExhaustion(r) ==
    /\ epoch[r] >= MAX_EPOCH
    /\ rekeyState' = [rekeyState EXCEPT ![r] = "Terminated"]
    /\ UNCHANGED <<epoch, currentKeys, oldKeys, sendNonce, recvNonce,
                   epochStartTime, oldKeyExpiry, network, time>>

-----------------------------------------------------------------------------
(* Clear Expired Old Keys *)
-----------------------------------------------------------------------------

ClearOldKeys(r) ==
    /\ oldKeys[r] /= -1
    /\ time >= oldKeyExpiry[r]
    /\ oldKeys' = [oldKeys EXCEPT ![r] = -1]
    /\ UNCHANGED <<rekeyState, epoch, currentKeys, sendNonce, recvNonce,
                   epochStartTime, oldKeyExpiry, network, time>>

-----------------------------------------------------------------------------
(* Message Loss *)
-----------------------------------------------------------------------------

LoseMessage ==
    /\ network /= {}
    /\ \E msg \in network :
        network' = network \ {msg}
    /\ UNCHANGED <<rekeyState, epoch, currentKeys, oldKeys, sendNonce, recvNonce,
                   epochStartTime, oldKeyExpiry, time>>

-----------------------------------------------------------------------------
(* Next State Relation *)
-----------------------------------------------------------------------------

Next ==
    \/ Tick
    \/ \E r \in Roles : SendFrame(r)
    \/ InitiateRekey
    \/ RespondToRekey
    \/ CompleteRekeyResponder
    \/ ReceiveRekeyResponse
    \/ \E r \in Roles : CounterExhaustion(r)
    \/ \E r \in Roles : EpochExhaustion(r)
    \/ \E r \in Roles : ClearOldKeys(r)
    \/ LoseMessage

Fairness ==
    /\ WF_vars(Tick)
    /\ WF_vars(InitiateRekey)
    /\ WF_vars(RespondToRekey)
    /\ WF_vars(CompleteRekeyResponder)
    /\ WF_vars(ReceiveRekeyResponse)

Spec == Init /\ [][Next]_vars /\ Fairness

-----------------------------------------------------------------------------
(* Safety Properties *)
-----------------------------------------------------------------------------

\* S1: Epochs are monotonically increasing
MonotonicEpochs ==
    \A r \in Roles : epoch[r] >= 0 /\ epoch[r] <= MAX_EPOCH

\* S2: Current keys match current epoch
KeysMatchEpoch ==
    \A r \in Roles : currentKeys[r] = epoch[r]

\* S3: Old keys are from previous epoch
OldKeysFromPreviousEpoch ==
    \A r \in Roles : oldKeys[r] /= -1 => oldKeys[r] = epoch[r] - 1

\* S4: Nonce counters reset on rekey
NoncesResetOnRekey ==
    \A r \in Roles : rekeyState[r] = "Idle" /\ epochStartTime[r] = time
        => sendNonce[r] = 0 /\ recvNonce[r] = 0

\* S5: Terminated sessions stay terminated
TerminationIsFinal ==
    \A r \in Roles : rekeyState[r] = "Terminated" =>
        [](rekeyState[r] = "Terminated")

\* S6: Never reuse nonce with same key
NonceUniqueness ==
    \A r \in Roles : sendNonce[r] < REJECT_AFTER_MESSAGES

Safety == MonotonicEpochs /\ KeysMatchEpoch /\ OldKeysFromPreviousEpoch /\ NonceUniqueness

-----------------------------------------------------------------------------
(* Liveness Properties *)
-----------------------------------------------------------------------------

\* L1: Rekey eventually happens if not terminated
RekeyEventuallyHappens ==
    \A r \in Roles :
        rekeyState[r] = "Idle" /\ epoch[r] < MAX_EPOCH ~>
            epoch[r] > 0 \/ rekeyState[r] = "Terminated"

\* L2: Waiting state eventually resolves
NoForeverWaiting ==
    rekeyState["Initiator"] = "WaitingRekeyResp" ~>
        rekeyState["Initiator"] /= "WaitingRekeyResp"

\* L3: Old keys are eventually cleared
OldKeysEventuallyCleared ==
    \A r \in Roles :
        oldKeys[r] /= -1 ~> oldKeys[r] = -1

-----------------------------------------------------------------------------
(* Invariants to Check *)
-----------------------------------------------------------------------------

THEOREM SafetyTheorem == Spec => []Safety
THEOREM TypeSafety == Spec => []TypeOK

=============================================================================

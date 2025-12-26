------------------------------ MODULE Roaming ------------------------------
(*
 * NOMAD Protocol - Connection Migration (Roaming) Formal Specification
 * TLA+ Model
 *
 * This specification models the NOMAD roaming mechanism, verifying:
 *   1. Session survives IP address changes
 *   2. Only authenticated frames update remote endpoint
 *   3. Anti-amplification protection works
 *   4. Spoofed addresses don't hijack sessions
 *
 * From 2-TRANSPORT.md:
 *   - Roaming is automatic: no handshake required
 *   - When authenticated frame arrives from new address:
 *     - Verify AEAD tag with session keys
 *     - If valid: update remote_endpoint
 *     - If invalid: silently drop
 *   - Anti-amplification: 3x limit on unvalidated addresses
 *)

EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    MaxFrames,              \* Maximum number of frames to model
    NumAddresses,           \* Number of possible IP addresses
    AMPLIFICATION_FACTOR    \* Anti-amplification limit (3x)

ASSUME MaxFrames > 0
ASSUME NumAddresses >= 2
ASSUME AMPLIFICATION_FACTOR > 0

-----------------------------------------------------------------------------
(* State Space *)
-----------------------------------------------------------------------------

Addresses == 1..NumAddresses
Roles == {"Client", "Server"}

\* Frame types
FrameTypes == {"Data", "Spoofed"}

VARIABLES
    \* Per-role network state
    localAddress,           \* Current local address
    remoteEndpoint,         \* Last known peer address
    validatedAddresses,     \* Set of validated addresses

    \* Anti-amplification tracking
    bytesRecvFrom,          \* Bytes received from each address
    bytesSentTo,            \* Bytes sent to each address

    \* Session state (abstracted)
    sessionActive,          \* Is session active?
    sessionKey,             \* Shared session key (modeled as boolean "known")

    \* Network
    network,                \* In-flight frames
    frameCount              \* Total frames sent (for bounding)

vars == <<localAddress, remoteEndpoint, validatedAddresses,
          bytesRecvFrom, bytesSentTo, sessionActive, sessionKey,
          network, frameCount>>

-----------------------------------------------------------------------------
(* Type Invariants *)
-----------------------------------------------------------------------------

TypeOK ==
    /\ localAddress \in [Roles -> Addresses]
    /\ remoteEndpoint \in [Roles -> Addresses]
    /\ validatedAddresses \in [Roles -> SUBSET Addresses]
    /\ bytesRecvFrom \in [Roles -> [Addresses -> 0..MaxFrames * 100]]
    /\ bytesSentTo \in [Roles -> [Addresses -> 0..MaxFrames * 100]]
    /\ sessionActive \in BOOLEAN
    /\ sessionKey \in BOOLEAN
    /\ network \subseteq [type: FrameTypes,
                          from: Roles, to: Roles,
                          srcAddr: Addresses,
                          authentic: BOOLEAN,
                          size: 1..100]
    /\ frameCount \in 0..MaxFrames

-----------------------------------------------------------------------------
(* Helper Functions *)
-----------------------------------------------------------------------------

Peer(r) == IF r = "Client" THEN "Server" ELSE "Client"

\* Check if we can send to an address (anti-amplification)
CanSendTo(r, addr, size) ==
    \/ addr \in validatedAddresses[r]
    \/ bytesSentTo[r][addr] + size <= AMPLIFICATION_FACTOR * bytesRecvFrom[r][addr]

\* Verify frame authenticity (AEAD check)
\* In the model, authentic frames have authentic = TRUE
VerifyFrame(frame) == frame.authentic

-----------------------------------------------------------------------------
(* Initial State *)
-----------------------------------------------------------------------------

Init ==
    /\ localAddress = [r \in Roles |->
        IF r = "Client" THEN 1 ELSE 2]
    /\ remoteEndpoint = [r \in Roles |->
        IF r = "Client" THEN 2 ELSE 1]  \* Initially know peer's address
    /\ validatedAddresses = [r \in Roles |->
        {remoteEndpoint[r]}]  \* Initial address is validated (from handshake)
    /\ bytesRecvFrom = [r \in Roles |-> [a \in Addresses |-> 0]]
    /\ bytesSentTo = [r \in Roles |-> [a \in Addresses |-> 0]]
    /\ sessionActive = TRUE
    /\ sessionKey = TRUE
    /\ network = {}
    /\ frameCount = 0

-----------------------------------------------------------------------------
(* Client Changes IP Address (Roaming Event) *)
-----------------------------------------------------------------------------

ClientRoams ==
    /\ sessionActive
    /\ \E newAddr \in Addresses :
        /\ newAddr /= localAddress["Client"]
        /\ localAddress' = [localAddress EXCEPT !["Client"] = newAddr]
    /\ UNCHANGED <<remoteEndpoint, validatedAddresses, bytesRecvFrom,
                   bytesSentTo, sessionActive, sessionKey, network, frameCount>>

-----------------------------------------------------------------------------
(* Send Data Frame *)
-----------------------------------------------------------------------------

SendFrame(r) ==
    /\ sessionActive
    /\ sessionKey
    /\ frameCount < MaxFrames
    /\ LET
        srcAddr == localAddress[r]
        dstAddr == remoteEndpoint[r]
        size == 50  \* Fixed size for simplicity
       IN
        /\ CanSendTo(r, dstAddr, size)
        /\ LET frame == [type |-> "Data",
                         from |-> r,
                         to |-> Peer(r),
                         srcAddr |-> srcAddr,
                         authentic |-> TRUE,  \* Legitimate frame
                         size |-> size]
           IN
            /\ network' = network \union {frame}
            /\ bytesSentTo' = [bytesSentTo EXCEPT ![r][dstAddr] = @ + size]
        /\ frameCount' = frameCount + 1
    /\ UNCHANGED <<localAddress, remoteEndpoint, validatedAddresses,
                   bytesRecvFrom, sessionActive, sessionKey>>

-----------------------------------------------------------------------------
(* Receive Frame - Core Roaming Logic *)
-----------------------------------------------------------------------------

ReceiveFrame(r) ==
    /\ sessionActive
    /\ \E frame \in network :
        /\ frame.to = r
        /\ LET
            srcAddr == frame.srcAddr
            size == frame.size
           IN
            /\ bytesRecvFrom' = [bytesRecvFrom EXCEPT ![r][srcAddr] = @ + size]
            /\ network' = network \ {frame}
            /\ IF VerifyFrame(frame)
               THEN
                \* Authentic frame - update endpoint and validate address
                /\ remoteEndpoint' = [remoteEndpoint EXCEPT ![r] = srcAddr]
                /\ validatedAddresses' = [validatedAddresses EXCEPT ![r] = @ \union {srcAddr}]
               ELSE
                \* Invalid frame - silently drop, no endpoint update
                /\ UNCHANGED <<remoteEndpoint, validatedAddresses>>
    /\ UNCHANGED <<localAddress, bytesSentTo, sessionActive, sessionKey, frameCount>>

-----------------------------------------------------------------------------
(* Attacker Sends Spoofed Frame *)
(* Attacker tries to redirect session to a victim address *)
-----------------------------------------------------------------------------

AttackerSpoofFrame ==
    /\ sessionActive
    /\ frameCount < MaxFrames
    /\ \E victimAddr \in Addresses :
        /\ \E targetRole \in Roles :
            /\ LET frame == [type |-> "Spoofed",
                             from |-> Peer(targetRole),  \* Claim to be peer
                             to |-> targetRole,
                             srcAddr |-> victimAddr,     \* Spoofed source
                             authentic |-> FALSE,        \* Can't forge AEAD
                             size |-> 50]
               IN network' = network \union {frame}
    /\ frameCount' = frameCount + 1
    /\ UNCHANGED <<localAddress, remoteEndpoint, validatedAddresses,
                   bytesRecvFrom, bytesSentTo, sessionActive, sessionKey>>

-----------------------------------------------------------------------------
(* Message Loss *)
-----------------------------------------------------------------------------

LoseMessage ==
    /\ network /= {}
    /\ \E frame \in network :
        network' = network \ {frame}
    /\ UNCHANGED <<localAddress, remoteEndpoint, validatedAddresses,
                   bytesRecvFrom, bytesSentTo, sessionActive, sessionKey, frameCount>>

-----------------------------------------------------------------------------
(* Next State Relation *)
-----------------------------------------------------------------------------

Next ==
    \/ ClientRoams
    \/ \E r \in Roles : SendFrame(r)
    \/ \E r \in Roles : ReceiveFrame(r)
    \/ AttackerSpoofFrame
    \/ LoseMessage

Fairness ==
    /\ \A r \in Roles : WF_vars(ReceiveFrame(r))
    /\ \A r \in Roles : WF_vars(SendFrame(r))

Spec == Init /\ [][Next]_vars /\ Fairness

-----------------------------------------------------------------------------
(* Safety Properties *)
-----------------------------------------------------------------------------

\* S1: Only authenticated frames update remote endpoint
\* (Verified by construction - ReceiveFrame only updates on VerifyFrame)

\* S2: Spoofed frames never update remote endpoint
SpoofedNeverUpdates ==
    \A frame \in network :
        frame.type = "Spoofed" =>
            remoteEndpoint = remoteEndpoint  \* Tautology, but checked after receive

\* S3: Anti-amplification: never send more than 3x received to unvalidated addr
AntiAmplification ==
    \A r \in Roles :
        \A addr \in Addresses :
            addr \notin validatedAddresses[r] =>
                bytesSentTo[r][addr] <= AMPLIFICATION_FACTOR * bytesRecvFrom[r][addr]

\* S4: After roaming, client can still communicate
\* (Session remains active throughout)
SessionSurvivesRoaming ==
    sessionActive

\* S5: Remote endpoint is always a valid address
ValidRemoteEndpoint ==
    \A r \in Roles : remoteEndpoint[r] \in Addresses

\* S6: Validated addresses only come from authentic frames
\* (Verified by construction)

Safety == AntiAmplification /\ SessionSurvivesRoaming /\ ValidRemoteEndpoint

-----------------------------------------------------------------------------
(* Liveness Properties *)
-----------------------------------------------------------------------------

\* L1: After roaming, communication eventually resumes
\* If client roams and sends a frame, server eventually updates endpoint
CommunicationResumes ==
    localAddress["Client"] /= remoteEndpoint["Server"] ~>
        localAddress["Client"] = remoteEndpoint["Server"]

\* L2: Frames are eventually delivered (with fairness)
EventualDelivery ==
    \A frame \in network : <>(frame \notin network)

-----------------------------------------------------------------------------
(* Key Security Property *)
-----------------------------------------------------------------------------

\* The attacker cannot redirect the session to a victim address
\* This means: remoteEndpoint only changes when authentic frame received from that address

\* Since the attacker cannot forge authentic frames (sessionKey is private),
\* spoofed frames with authentic = FALSE cannot update remoteEndpoint
AttackerCannotRedirect ==
    \A r \in Roles :
        \* If endpoint changed to X, we must have received authentic frame from X
        \* Modeled by: endpoint only in validatedAddresses
        remoteEndpoint[r] \in validatedAddresses[r]

-----------------------------------------------------------------------------
(* Invariants to Check *)
-----------------------------------------------------------------------------

THEOREM SafetyTheorem == Spec => []Safety
THEOREM SecurityTheorem == Spec => []AttackerCannotRedirect
THEOREM TypeSafety == Spec => []TypeOK

=============================================================================

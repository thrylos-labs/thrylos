---------------------------- MODULE Consensus ----------------------------
EXTENDS FiniteSets, Integers, Naturals

(***************************************************************************)
(* A deliberately small abstraction of one Thrylos consensus height.       *)
(*                                                                         *)
(* It models the parts on which the host adapter relies:                    *)
(* - fewer than one third of validators are Byzantine;                     *)
(* - a quorum contains more than two thirds of the validators;             *)
(* - a correct validator casts at most one vote of each type per round;    *)
(* - a correct validator locks only after a prevote quorum and will not     *)
(*   vote for another value;                                               *)
(* - after eventual synchrony there is a round with a proposal compatible  *)
(*   with every correct lock, and enabled correct actions are scheduled.   *)
(*                                                                         *)
(* Signatures, byte encoding, execution validity and proposer selection are *)
(* outside this model. They are checked by the Rust tests. MaxRound is the  *)
(* first synchronous round; the earlier finite rounds represent an         *)
(* arbitrarily long asynchronous prefix by symmetry.                       *)
(***************************************************************************)

CONSTANTS Validators, Byzantine, Values,
          Nil, NoVote, Async, Sync, MaxRound, Quorum

Correct == Validators \ Byzantine
Rounds == 0..MaxRound
VoteValues == Values \cup {Nil, NoVote}

ASSUME /\ Validators # {}
       /\ Byzantine \subseteq Validators
       /\ Values # {}
       /\ Nil \notin Values
       /\ NoVote \notin Values \cup {Nil}
       /\ Async # Sync
       /\ MaxRound > 0
       /\ Quorum > (2 * Cardinality(Validators)) \div 3
       /\ Cardinality(Byzantine) < Cardinality(Validators) \div 3 + 1

VARIABLES round, network, proposal, prevotes, precommits,
          lockedValue, lockedRound, decisions

vars == <<round, network, proposal, prevotes, precommits,
          lockedValue, lockedRound, decisions>>

NoVotes == [r \in Rounds |-> [n \in Validators |-> NoVote]]

Init ==
    /\ round = 0
    /\ network = Async
    /\ proposal = [r \in Rounds |-> NoVote]
    /\ prevotes = NoVotes
    /\ precommits = NoVotes
    /\ lockedValue = [n \in Validators |-> Nil]
    /\ lockedRound = [n \in Validators |-> -1]
    /\ decisions = [n \in Validators |-> Nil]

TypeOK ==
    /\ round \in Rounds
    /\ network \in {Async, Sync}
    /\ proposal \in [Rounds -> Values \cup {NoVote}]
    /\ prevotes \in [Rounds -> [Validators -> VoteValues]]
    /\ precommits \in [Rounds -> [Validators -> VoteValues]]
    /\ lockedValue \in [Validators -> Values \cup {Nil}]
    /\ lockedRound \in [Validators -> -1..MaxRound]
    /\ decisions \in [Validators -> Values \cup {Nil}]

VoteCount(votes, r, value) ==
    Cardinality({n \in Validators : votes[r][n] = value})

HasQuorum(votes, r, value) == VoteCount(votes, r, value) >= Quorum

(***************************************************************************)
(* The asynchronous prefix may contain arbitrary proposals and Byzantine   *)
(* votes. Correct votes remain constrained by locks and quorums.            *)
(***************************************************************************)
AsyncPropose ==
    /\ network = Async
    /\ round < MaxRound
    /\ proposal[round] = NoVote
    /\ \E value \in Values:
          proposal' = [proposal EXCEPT ![round] = value]
    /\ UNCHANGED <<round, network, prevotes, precommits,
                    lockedValue, lockedRound, decisions>>

AdvanceAsyncRound ==
    /\ network = Async
    /\ round < MaxRound - 1
    /\ round' = round + 1
    /\ UNCHANGED <<network, proposal, prevotes, precommits,
                    lockedValue, lockedRound, decisions>>

(***************************************************************************)
(* Eventual synchrony moves to a fresh reserved round. A correct proposer   *)
(* chooses the unique locked value, if one exists, otherwise any value.     *)
(***************************************************************************)
EnterSynchrony ==
    /\ network = Async
    /\ network' = Sync
    /\ round' = MaxRound
    /\ UNCHANGED <<proposal, prevotes, precommits,
                    lockedValue, lockedRound, decisions>>

SyncPropose ==
    /\ network = Sync
    /\ proposal[MaxRound] = NoVote
    /\ \E value \in Values:
          /\ \A n \in Correct: lockedValue[n] \in {Nil, value}
          /\ proposal' = [proposal EXCEPT ![MaxRound] = value]
    /\ UNCHANGED <<round, network, prevotes, precommits,
                    lockedValue, lockedRound, decisions>>

CorrectPrevote(n) ==
    /\ n \in Correct
    /\ prevotes[round][n] = NoVote
    /\ \E value \in Values:
          /\ proposal[round] = value
          /\ lockedValue[n] \in {Nil, value}
          /\ prevotes' = [prevotes EXCEPT ![round][n] = value]
    /\ UNCHANGED <<round, network, proposal, precommits,
                    lockedValue, lockedRound, decisions>>

ByzantinePrevote ==
    \E n \in Byzantine, value \in Values \cup {Nil}:
        /\ prevotes[round][n] = NoVote
        /\ prevotes' = [prevotes EXCEPT ![round][n] = value]
        /\ UNCHANGED <<round, network, proposal, precommits,
                        lockedValue, lockedRound, decisions>>

CorrectPrecommit(n) ==
    /\ n \in Correct
    /\ precommits[round][n] = NoVote
    /\ \E value \in Values:
          /\ HasQuorum(prevotes, round, value)
          /\ precommits' = [precommits EXCEPT ![round][n] = value]
          /\ lockedValue' = [lockedValue EXCEPT ![n] = value]
          /\ lockedRound' = [lockedRound EXCEPT ![n] = round]
    /\ UNCHANGED <<round, network, proposal, prevotes, decisions>>

ByzantinePrecommit ==
    \E n \in Byzantine, value \in Values \cup {Nil}:
        /\ precommits[round][n] = NoVote
        /\ precommits' = [precommits EXCEPT ![round][n] = value]
        /\ UNCHANGED <<round, network, proposal, prevotes,
                        lockedValue, lockedRound, decisions>>

Decide(n) ==
    /\ n \in Correct
    /\ decisions[n] = Nil
    /\ \E r \in Rounds, value \in Values:
          /\ HasQuorum(precommits, r, value)
          /\ decisions' = [decisions EXCEPT ![n] = value]
    /\ UNCHANGED <<round, network, proposal, prevotes, precommits,
                    lockedValue, lockedRound>>

Next ==
    \/ AsyncPropose
    \/ AdvanceAsyncRound
    \/ EnterSynchrony
    \/ SyncPropose
    \/ \E n \in Correct: CorrectPrevote(n)
    \/ ByzantinePrevote
    \/ \E n \in Correct: CorrectPrecommit(n)
    \/ ByzantinePrecommit
    \/ \E n \in Correct: Decide(n)

(***************************************************************************)
(* Fairness is required only for the eventual-synchrony premise and correct *)
(* validators. Byzantine actions are never assumed to happen.               *)
(***************************************************************************)
Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(EnterSynchrony)
    /\ WF_vars(SyncPropose)
    /\ \A n \in Correct: WF_vars(CorrectPrevote(n))
    /\ \A n \in Correct: WF_vars(CorrectPrecommit(n))
    /\ \A n \in Correct: WF_vars(Decide(n))

DecidedValues == {value \in Values : \E n \in Correct: decisions[n] = value}

Safety == Cardinality(DecidedValues) <= 1

EventualSynchronyLiveness == <> (\E n \in Correct: decisions[n] # Nil)

=============================================================================

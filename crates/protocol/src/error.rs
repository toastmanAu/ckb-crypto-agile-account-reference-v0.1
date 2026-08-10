#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i8)]
pub enum ProtocolError {
    InvalidArgs = 20,
    InvalidState = 21,
    InvalidWitness = 22,
    StateNotFound = 23,
    DuplicateState = 24,
    StateConsumedOnSpend = 25,
    InvalidTransition = 26,
    InvalidSequence = 27,
    ThresholdUnsatisfied = 28,
    InvalidCapability = 29,
    InvalidVerifierRef = 30,
    VerifierFailure = 31,
    UnsupportedVersion = 32,
    UnsupportedAlgorithm = 33,
    RecoveryLocked = 34,
    InvalidRequest = 35,
    InvalidProof = 36,
    InvalidOperation = 37,
    UnsatisfiableThreshold = 38,
    LengthOverflow = 39,
}

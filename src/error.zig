pub const Error = error{
    CorruptedSignature,
    CorruptedHeader,
    CorruptedBlock,
    UnsupportedKDF,
    UnsupportedKDFVersion,
    UnsupportedVersion, 
    InvalidCredentials,
    OutOfMemory
};

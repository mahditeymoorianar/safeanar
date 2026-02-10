#pragma once

#include <string_view>

namespace safeanar {

enum class AnarStatus {
    Ok = 0,
    InvalidWord,
    InvalidChar,
    InvalidLength,
    InvalidDictionary,
    InvalidKeyLength,
    InvalidBlockLength,
    BadHex,
    KeyTooShort,
    FileIOError,
    InvalidPath,
    InvalidArchive,
    InvalidPaddingTarget,
    CorruptInput,
    MissingRngBytes,
    InsufficientRngBytes,
    UnknownOp,
    BadJson
};

inline std::string_view ToString(const AnarStatus status) {
    switch (status) {
        case AnarStatus::Ok:
            return "Ok";
        case AnarStatus::InvalidWord:
            return "InvalidWord";
        case AnarStatus::InvalidChar:
            return "InvalidChar";
        case AnarStatus::InvalidLength:
            return "InvalidLength";
        case AnarStatus::InvalidDictionary:
            return "InvalidDictionary";
        case AnarStatus::InvalidKeyLength:
            return "InvalidKeyLength";
        case AnarStatus::InvalidBlockLength:
            return "InvalidBlockLength";
        case AnarStatus::BadHex:
            return "BadHex";
        case AnarStatus::KeyTooShort:
            return "KeyTooShort";
        case AnarStatus::FileIOError:
            return "FileIOError";
        case AnarStatus::InvalidPath:
            return "InvalidPath";
        case AnarStatus::InvalidArchive:
            return "InvalidArchive";
        case AnarStatus::InvalidPaddingTarget:
            return "InvalidPaddingTarget";
        case AnarStatus::CorruptInput:
            return "CorruptInput";
        case AnarStatus::MissingRngBytes:
            return "MissingRngBytes";
        case AnarStatus::InsufficientRngBytes:
            return "InsufficientRngBytes";
        case AnarStatus::UnknownOp:
            return "UnknownOp";
        case AnarStatus::BadJson:
            return "BadJson";
    }
    return "UnknownStatus";
}

}  // namespace safeanar

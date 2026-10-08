"use strict";

/**
 * nyuu/lib/encryption.js
 *
 * yEnc Body & Control Lines Encryption Standards v1.2 implementation for Nyuu.
 *
 * Covers:
 * - 253-byte Alphabet mapping (excluding 0x00, 0x0A, 0x0D)
 * - Uniform Alphabet salt rejection sampling
 * - RFC 9106 Argon2id master key derivation (t=1, m=64MiB, p=4, 32B tag)
 * - HMAC-SHA256 nonces and tweaks
 * - SegmentIndexAllocator skipping 0x0A/0x0D bytes (VEC-07)
 * - RFC 8439 Extended XChaCha20-Poly1305 body AEAD (VEC-03)
 * - Canonical 128-char =yencryption header builder and strict parser (VEC-05)
 * - NIST SP 800-38G FF1 control-line encryption/decryption (Radix 253) (VEC-04)
 * - Line 1 bootstrap prefix (16B salt || 4B segmentIndex)
 * - Full article control line encryption preserving data lines and endings
 * - EncryptionSession state container
 *
 * Self-containment: Uses @noble/ciphers, @noble/hashes, and Node.js built-ins.
 */

var crypto = require("crypto");
var { argon2id } = require("@noble/hashes/argon2.js");
var { xchacha20poly1305 } = require("@noble/ciphers/chacha.js");
var { FF1 } = require("@noble/ciphers/ff1.js");

var ALPHABET_LEN = 253;
var SALT_LEN = 16;
var BOOTSTRAP_LEN = 20;
var TAG_LEN = 16;

/**
 * Maps a single byte to an Alphabet numeral in 0..252.
 * The 253-byte Alphabet contains all octets except 0x00, 0x0A, and 0x0D in ascending order:
 *   0x01..=0x09 -> numeral 0..=8 (b - 1)
 *   0x0B..=0x0C -> numeral 9..=10 (b - 2)
 *   0x0E..=0xFF -> numeral 11..=252 (b - 3)
 */
function byteToNumeral(b) {
    if (typeof b !== "number") {
        throw new Error("INVALID_BYTE");
    }
    if (b === 0x00 || b === 0x0a || b === 0x0d) {
        throw new Error("INVALID_SALT_CHARACTER");
    }
    if (b >= 0x01 && b <= 0x09) {
        return b - 1;
    }
    if (b >= 0x0b && b <= 0x0c) {
        return b - 2;
    }
    if (b >= 0x0e && b <= 0xff) {
        return b - 3;
    }
    throw new Error("INVALID_BYTE");
}

/**
 * Maps an Alphabet numeral in 0..252 back to its byte octet.
 */
function numeralToByte(n) {
    if (typeof n !== "number" || n < 0 || n >= ALPHABET_LEN) {
        throw new Error("CONTROL_LINE_DECRYPT_FAILURE");
    }
    if (n <= 8) {
        return n + 1;
    }
    if (n <= 10) {
        return n + 2;
    }
    return n + 3;
}

/**
 * Rejection-samples 16 random bytes from the 253-byte Alphabet (no 0x00, 0x0A, 0x0D).
 */
function sampleAlphabetSalt() {
    var salt = Buffer.alloc(SALT_LEN);
    var filled = 0;
    while (filled < SALT_LEN) {
        var pool = crypto.randomBytes(32);
        for (var i = 0; i < pool.length && filled < SALT_LEN; i++) {
            var b = pool[i];
            if (b !== 0x00 && b !== 0x0a && b !== 0x0d) {
                salt[filled++] = b;
            }
        }
    }
    return salt;
}

/**
 * Derives a 32-byte master key via Argon2id (RFC 9106).
 * Parameters: t=1, m=65536 KiB (64 MiB), p=4, dkLen=32, version=0x13.
 */
function deriveMasterKey(password, salt) {
    var passBuf = typeof password === "string" ? Buffer.from(password, "utf8") : Buffer.from(password);
    var saltBuf = Buffer.isBuffer(salt) ? salt : Buffer.from(salt);
    if (saltBuf.length !== SALT_LEN) {
        throw new Error("INVALID_SALT_LENGTH");
    }
    var key = argon2id(passBuf, saltBuf, {
        t: 1,
        m: 65536,
        p: 4,
        dkLen: 32,
        version: 0x13
    });
    return Buffer.from(key);
}

/**
 * Derives a 24-byte body nonce via HMAC-SHA256:
 * HMAC-SHA256(masterKey, "yenc-body nonce" || uint32_be(segmentIndex))[0..24]
 */
function deriveBodyNonce(masterKey, segmentIndex) {
    var be = Buffer.alloc(4);
    be.writeUInt32BE(segmentIndex >>> 0, 0);
    var msg = Buffer.concat([Buffer.from("yenc-body nonce", "ascii"), be]);
    var hmac = crypto.createHmac("sha256", masterKey).update(msg).digest();
    return hmac.subarray(0, 24);
}

/**
 * Derives the 32-byte control encryption key via HMAC-SHA256:
 * HMAC-SHA256(masterKey, "yenc-control key")[0..32]
 */
function deriveControlEncKey(masterKey) {
    var msg = Buffer.from("yenc-control key", "ascii");
    return crypto.createHmac("sha256", masterKey).update(msg).digest();
}

/**
 * Derives the 8-byte control tweak via HMAC-SHA256:
 * HMAC-SHA256(masterKey, "yenc-control tweak" || uint32_be(segmentIndex) || uint32_be(lineIndex))[0..8]
 */
function deriveControlTweak(masterKey, segmentIndex, lineIndex) {
    var buf = Buffer.alloc(26);
    buf.write("yenc-control tweak", 0, 18, "ascii");
    buf.writeUInt32BE(segmentIndex >>> 0, 18);
    buf.writeUInt32BE(lineIndex >>> 0, 22);
    var hmac = crypto.createHmac("sha256", masterKey).update(buf).digest();
    return hmac.subarray(0, 8);
}

/**
 * Returns true if the big-endian 4-byte representation of index contains 0x0A or 0x0D.
 */
function isIndexForbidden(index) {
    var be = Buffer.alloc(4);
    be.writeUInt32BE(index >>> 0, 0);
    return be[0] === 0x0a || be[0] === 0x0d ||
           be[1] === 0x0a || be[1] === 0x0d ||
           be[2] === 0x0a || be[2] === 0x0d ||
           be[3] === 0x0a || be[3] === 0x0d;
}

/**
 * Finds the next permitted index >= candidate.
 */
function nextPermittedIndex(candidate) {
    var i = candidate >>> 0;
    while (isIndexForbidden(i)) {
        i = (i + 1) >>> 0;
    }
    return i;
}

/**
 * Monotonically allocates segmentIndex values, starting at startIndex (default 1)
 * and skipping any values whose uint32_be bytes contain 0x0A or 0x0D (VEC-07).
 */
function SegmentIndexAllocator(startIndex) {
    var start = (typeof startIndex === "number" ? startIndex : 1) >>> 0;
    this.current = nextPermittedIndex(start);
}

SegmentIndexAllocator.prototype.next = function() {
    var val = this.current;
    this.current = nextPermittedIndex((this.current + 1) >>> 0);
    return val;
};

SegmentIndexAllocator.prototype.peek = function() {
    return this.current;
};

/**
 * Encrypts a body payload with XChaCha20-Poly1305.
 * Returns { ciphertext: Buffer, tag: Buffer }.
 */
function encryptBody(masterKey, segmentIndex, plaintext) {
    var ptBuf = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext);
    var nonce = deriveBodyNonce(masterKey, segmentIndex);
    var cipher = xchacha20poly1305(masterKey, nonce);
    var encrypted = cipher.encrypt(ptBuf);
    var ciphertext = Buffer.from(encrypted.subarray(0, encrypted.length - TAG_LEN));
    var tag = Buffer.from(encrypted.subarray(encrypted.length - TAG_LEN));
    return { ciphertext: ciphertext, tag: tag };
}

/**
 * Decrypts a body payload with XChaCha20-Poly1305.
 * Throws AUTHENTICATION_FAILURE if authentication fails.
 */
function decryptBody(masterKey, segmentIndex, ciphertext, tag) {
    var ctBuf = Buffer.isBuffer(ciphertext) ? ciphertext : Buffer.from(ciphertext);
    var tagBuf = Buffer.isBuffer(tag) ? tag : Buffer.from(tag);
    if (tagBuf.length !== TAG_LEN) {
        throw new Error("INVALID_TAG_LENGTH");
    }
    var nonce = deriveBodyNonce(masterKey, segmentIndex);
    var cipher = xchacha20poly1305(masterKey, nonce);
    var combined = Buffer.concat([ctBuf, tagBuf]);
    try {
        var plaintext = cipher.decrypt(combined);
        return Buffer.from(plaintext);
    } catch (err) {
        var error = new Error("AUTHENTICATION_FAILURE");
        error.code = "AUTHENTICATION_FAILURE";
        throw error;
    }
}

/**
 * Formats a 32-bit integer as an 8-character lowercase hexadecimal string.
 */
function formatIndexHex(index) {
    var be = Buffer.alloc(4);
    be.writeUInt32BE(index >>> 0, 0);
    return be.toString("hex");
}

/**
 * Builds the canonical 128-character =yencryption line:
 * =yencryption cipher=XChaCha20-Poly1305 salt=<32-hex> index=<8-hex> tag=<32-hex>
 */
function buildYencryptionLine(salt, segmentIndex, tag) {
    var saltHex = (Buffer.isBuffer(salt) ? salt.toString("hex") : String(salt)).toLowerCase();
    var tagHex = (Buffer.isBuffer(tag) ? tag.toString("hex") : String(tag)).toLowerCase();
    var indexHex = typeof segmentIndex === "number" ? formatIndexHex(segmentIndex) : String(segmentIndex).toLowerCase();
    if (saltHex.length !== 32) throw new Error("INVALID_SALT_LENGTH");
    if (indexHex.length !== 8) throw new Error("INVALID_INDEX_LENGTH");
    if (tagHex.length !== 32) throw new Error("INVALID_TAG_LENGTH");
    var line = "=yencryption cipher=XChaCha20-Poly1305 salt=" + saltHex + " index=" + indexHex + " tag=" + tagHex;
    if (line.length !== 128) {
        throw new Error("INVALID_LINE_LENGTH");
    }
    return line;
}

/**
 * Strictly parses and validates a =yencryption line according to v1.2 specification.
 */
function parseYencryptionLine(line) {
    if (typeof line !== "string") {
        line = line.toString("ascii");
    }
    if (line.indexOf("\t") !== -1 || line.indexOf("  ") !== -1) {
        throw new Error("INVALID_WHITESPACE");
    }
    var tokens = line.split(" ");
    if (tokens.length !== 5) {
        throw new Error("INVALID_TOKEN_COUNT");
    }
    if (tokens[0] !== "=yencryption") {
        throw new Error("INVALID_TOKEN_COUNT");
    }
    if (!tokens[1].startsWith("cipher=")) {
        throw new Error("UNSUPPORTED_CIPHER");
    }
    if (tokens[1] !== "cipher=XChaCha20-Poly1305") {
        throw new Error("UNSUPPORTED_CIPHER");
    }
    if (!tokens[2].startsWith("salt=")) {
        throw new Error("INVALID_TOKEN_COUNT");
    }
    var saltVal = tokens[2].slice(5);
    if (/[A-Z]/.test(saltVal)) throw new Error("UPPERCASE_HEX");
    if (saltVal.length !== 32) throw new Error("INVALID_SALT_LENGTH");
    if (!/^[0-9a-f]{32}$/.test(saltVal)) throw new Error("INVALID_SALT_HEX");

    if (!tokens[3].startsWith("index=")) {
        throw new Error("INVALID_TOKEN_COUNT");
    }
    var indexVal = tokens[3].slice(6);
    if (/[A-Z]/.test(indexVal)) throw new Error("UPPERCASE_HEX");
    if (indexVal.length !== 8) throw new Error("INVALID_INDEX_LENGTH");
    if (!/^[0-9a-f]{8}$/.test(indexVal)) throw new Error("INVALID_INDEX_HEX");
    if (indexVal === "00000000") throw new Error("ZERO_SEGMENT_INDEX");

    if (!tokens[4].startsWith("tag=")) {
        throw new Error("INVALID_TOKEN_COUNT");
    }
    var tagVal = tokens[4].slice(4);
    if (/[A-Z]/.test(tagVal)) throw new Error("UPPERCASE_HEX");
    if (tagVal.length !== 32) throw new Error("INVALID_TAG_LENGTH");
    if (!/^[0-9a-f]{32}$/.test(tagVal)) throw new Error("INVALID_TAG_HEX");

    var segmentIndex = parseInt(indexVal, 16);
    if (isIndexForbidden(segmentIndex)) {
        throw new Error("FORBIDDEN_SEGMENT_INDEX_BYTE");
    }

    return {
        cipher: "XChaCha20-Poly1305",
        salt: Buffer.from(saltVal, "hex"),
        segmentIndex: segmentIndex,
        tag: Buffer.from(tagVal, "hex")
    };
}

/**
 * Encrypts a single control line with Radix-253 FF1 (AES-256).
 */
function ff1EncryptLine(encKey, tweak, plaintextLine) {
    var lineBuf = Buffer.isBuffer(plaintextLine) ? plaintextLine : Buffer.from(plaintextLine, "latin1");
    if (lineBuf.length < 2) {
        throw new Error("LINE_TOO_SHORT");
    }
    var numerals = new Array(lineBuf.length);
    for (var i = 0; i < lineBuf.length; i++) {
        numerals[i] = byteToNumeral(lineBuf[i]);
    }
    var cipher = FF1(ALPHABET_LEN, encKey, tweak);
    var encNums = cipher.encrypt(numerals);
    var outBuf = Buffer.alloc(encNums.length);
    for (var j = 0; j < encNums.length; j++) {
        outBuf[j] = numeralToByte(encNums[j]);
    }
    return outBuf;
}

/**
 * Decrypts a single control line with Radix-253 FF1 (AES-256).
 */
function ff1DecryptLine(encKey, tweak, ciphertextLine) {
    var lineBuf = Buffer.isBuffer(ciphertextLine) ? ciphertextLine : Buffer.from(ciphertextLine, "latin1");
    if (lineBuf.length < 2) {
        throw new Error("LINE_TOO_SHORT");
    }
    var numerals = new Array(lineBuf.length);
    for (var i = 0; i < lineBuf.length; i++) {
        numerals[i] = byteToNumeral(lineBuf[i]);
    }
    var cipher = FF1(ALPHABET_LEN, encKey, tweak);
    var decNums = cipher.decrypt(numerals);
    var outBuf = Buffer.alloc(decNums.length);
    for (var j = 0; j < decNums.length; j++) {
        outBuf[j] = numeralToByte(decNums[j]);
    }
    return outBuf;
}

/**
 * Encrypts Line 1 with prepended 20-byte bootstrap:
 * [salt (16B)] || [segmentIndex (4B uint32_be)] || [FF1(line1Content)]
 */
function encryptLine1(encKey, masterKey, segmentIndex, salt, line1Content) {
    var saltBuf = Buffer.isBuffer(salt) ? salt : Buffer.from(salt);
    if (saltBuf.length !== SALT_LEN) throw new Error("INVALID_SALT_LENGTH");
    if (segmentIndex === 0) throw new Error("ZERO_SEGMENT_INDEX");
    if (isIndexForbidden(segmentIndex)) throw new Error("FORBIDDEN_SEGMENT_INDEX_BYTE");

    var tweak = deriveControlTweak(masterKey, segmentIndex, 1);
    var encLine = ff1EncryptLine(encKey, tweak, line1Content);
    var be = Buffer.alloc(4);
    be.writeUInt32BE(segmentIndex >>> 0, 0);
    return Buffer.concat([saltBuf, be, encLine]);
}

/**
 * Decrypts Line 1 from wire:
 * Extracts 16B salt, 4B segmentIndex, verifies them, then FF1-decrypts remainder.
 */
function decryptLine1(encKey, masterKey, wireLine1) {
    var lineBuf = Buffer.isBuffer(wireLine1) ? wireLine1 : Buffer.from(wireLine1, "latin1");
    if (lineBuf.length < BOOTSTRAP_LEN + 2) {
        throw new Error("LINE_TRUNCATED");
    }
    var salt = lineBuf.subarray(0, SALT_LEN);
    for (var i = 0; i < salt.length; i++) {
        var sb = salt[i];
        if (sb === 0x00 || sb === 0x0a || sb === 0x0d) {
            throw new Error("INVALID_SALT_CHARACTER");
        }
    }
    var segmentIndex = lineBuf.readUInt32BE(SALT_LEN);
    if (segmentIndex === 0) {
        throw new Error("ZERO_SEGMENT_INDEX");
    }
    if (isIndexForbidden(segmentIndex)) {
        throw new Error("FORBIDDEN_SEGMENT_INDEX_BYTE");
    }
    var ct = lineBuf.subarray(BOOTSTRAP_LEN);
    var tweak = deriveControlTweak(masterKey, segmentIndex, 1);
    var decrypted = ff1DecryptLine(encKey, tweak, ct);
    if (!decrypted.toString("ascii").startsWith("=ybegin")) {
        throw new Error("CONTROL_LINE_DECRYPT_FAILURE");
    }
    return {
        salt: salt,
        segmentIndex: segmentIndex,
        plaintextLine: decrypted
    };
}

/**
 * Applies control-line encryption pass to a full yEnc article buffer.
 * Preserves data lines and line endings (\r\n or \n) byte-for-byte.
 */
function encryptControlLines(session, segmentIndex, articleBuffer) {
    var masterKey = session.masterKey;
    var encKey = session.controlEncKey;
    var salt = session.salt;

    var buf = Buffer.isBuffer(articleBuffer) ? articleBuffer : Buffer.from(articleBuffer);
    var lines = [];
    var start = 0;

    // Split preserving delimiters
    for (var i = 0; i < buf.length; i++) {
        if (buf[i] === 0x0a) { // LF
            lines.push(buf.subarray(start, i + 1));
            start = i + 1;
        }
    }
    if (start < buf.length) {
        lines.push(buf.subarray(start));
    }

    var outLines = [];
    var physicalLine = 0;

    for (var idx = 0; idx < lines.length; idx++) {
        var rawLine = lines[idx];
        var lineContent = rawLine;
        var eol = Buffer.alloc(0);

        if (lineContent.length >= 2 && lineContent[lineContent.length - 2] === 0x0d && lineContent[lineContent.length - 1] === 0x0a) {
            eol = lineContent.subarray(lineContent.length - 2);
            lineContent = lineContent.subarray(0, lineContent.length - 2);
        } else if (lineContent.length >= 1 && lineContent[lineContent.length - 1] === 0x0a) {
            eol = lineContent.subarray(lineContent.length - 1);
            lineContent = lineContent.subarray(0, lineContent.length - 1);
        }

        physicalLine++;
        var strPrefix = lineContent.subarray(0, 15).toString("ascii");

        if (physicalLine === 1 && strPrefix.startsWith("=ybegin")) {
            var encL1 = encryptLine1(encKey, masterKey, segmentIndex, salt, lineContent);
            outLines.push(Buffer.concat([encL1, eol]));
        } else if (strPrefix.startsWith("=ypart") || strPrefix.startsWith("=yencryption") || strPrefix.startsWith("=yend")) {
            var tweak = deriveControlTweak(masterKey, segmentIndex, physicalLine);
            var encLn = ff1EncryptLine(encKey, tweak, lineContent);
            outLines.push(Buffer.concat([encLn, eol]));
        } else {
            // Data line or blank line — preserve byte-for-byte
            outLines.push(rawLine);
        }
    }

    return Buffer.concat(outLines);
}

/**
 * Decrypts control lines in a full yEnc article buffer.
 * Preserves data lines and line endings byte-for-byte.
 */
function decryptControlLines(masterKey, articleBuffer) {
    var encKey = deriveControlEncKey(masterKey);
    var buf = Buffer.isBuffer(articleBuffer) ? articleBuffer : Buffer.from(articleBuffer);
    var lines = [];
    var start = 0;

    for (var i = 0; i < buf.length; i++) {
        if (buf[i] === 0x0a) {
            lines.push(buf.subarray(start, i + 1));
            start = i + 1;
        }
    }
    if (start < buf.length) {
        lines.push(buf.subarray(start));
    }

    var outLines = [];
    var physicalLine = 0;
    var salt = null;
    var segmentIndex = null;

    for (var idx = 0; idx < lines.length; idx++) {
        var rawLine = lines[idx];
        var lineContent = rawLine;
        var eol = Buffer.alloc(0);

        if (lineContent.length >= 2 && lineContent[lineContent.length - 2] === 0x0d && lineContent[lineContent.length - 1] === 0x0a) {
            eol = lineContent.subarray(lineContent.length - 2);
            lineContent = lineContent.subarray(0, lineContent.length - 2);
        } else if (lineContent.length >= 1 && lineContent[lineContent.length - 1] === 0x0a) {
            eol = lineContent.subarray(lineContent.length - 1);
            lineContent = lineContent.subarray(0, lineContent.length - 1);
        }

        physicalLine++;

        if (physicalLine === 1) {
            var decL1 = decryptLine1(encKey, masterKey, lineContent);
            salt = decL1.salt;
            segmentIndex = decL1.segmentIndex;
            outLines.push(Buffer.concat([decL1.plaintextLine, eol]));
        } else if (segmentIndex !== null) {
            var tweak = deriveControlTweak(masterKey, segmentIndex, physicalLine);
            try {
                var decLn = ff1DecryptLine(encKey, tweak, lineContent);
                var decStr = decLn.toString("ascii");
                if (decStr.startsWith("=ypart") || decStr.startsWith("=yencryption") || decStr.startsWith("=yend")) {
                    outLines.push(Buffer.concat([decLn, eol]));
                } else {
                    outLines.push(rawLine);
                }
            } catch (e) {
                // Not an encrypted control line or decryption failed -> keep as data line
                outLines.push(rawLine);
            }
        } else {
            outLines.push(rawLine);
        }
    }

    return {
        salt: salt,
        segmentIndex: segmentIndex,
        buffer: Buffer.concat(outLines)
    };
}

/**
 * EncryptionSession manages the cryptographic state for an upload session:
 * salt, masterKey, controlEncKey, and monotonic SegmentIndexAllocator.
 */
function EncryptionSession(password, salt, startIndex) {
    if (!password) {
        throw new Error("MISSING_PASSWORD");
    }
    this.salt = salt ? (Buffer.isBuffer(salt) ? salt : Buffer.from(salt, "hex")) : sampleAlphabetSalt();
    this.masterKey = deriveMasterKey(password, this.salt);
    this.controlEncKey = deriveControlEncKey(this.masterKey);
    this.allocator = new SegmentIndexAllocator(startIndex);
}

EncryptionSession.prototype.encryptBody = function(segmentIndex, data) {
    return encryptBody(this.masterKey, segmentIndex, data);
};

EncryptionSession.prototype.decryptBody = function(segmentIndex, ciphertext, tag) {
    return decryptBody(this.masterKey, segmentIndex, ciphertext, tag);
};

EncryptionSession.prototype.encryptControlLines = function(segmentIndex, buffer) {
    return encryptControlLines(this, segmentIndex, buffer);
};

EncryptionSession.prototype.buildYencryptionLine = function(segmentIndex, tag) {
    return buildYencryptionLine(this.salt, segmentIndex, tag);
};

module.exports = {
    ALPHABET_LEN: ALPHABET_LEN,
    SALT_LEN: SALT_LEN,
    BOOTSTRAP_LEN: BOOTSTRAP_LEN,
    TAG_LEN: TAG_LEN,
    byteToNumeral: byteToNumeral,
    numeralToByte: numeralToByte,
    sampleAlphabetSalt: sampleAlphabetSalt,
    deriveMasterKey: deriveMasterKey,
    deriveBodyNonce: deriveBodyNonce,
    deriveControlEncKey: deriveControlEncKey,
    deriveControlTweak: deriveControlTweak,
    isIndexForbidden: isIndexForbidden,
    nextPermittedIndex: nextPermittedIndex,
    SegmentIndexAllocator: SegmentIndexAllocator,
    encryptBody: encryptBody,
    decryptBody: decryptBody,
    buildYencryptionLine: buildYencryptionLine,
    parseYencryptionLine: parseYencryptionLine,
    ff1EncryptLine: ff1EncryptLine,
    ff1DecryptLine: ff1DecryptLine,
    encryptLine1: encryptLine1,
    decryptLine1: decryptLine1,
    encryptControlLines: encryptControlLines,
    decryptControlLines: decryptControlLines,
    EncryptionSession: EncryptionSession
};

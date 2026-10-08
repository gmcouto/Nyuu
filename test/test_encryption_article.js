"use strict";

var assert = require("assert");
var MultiEncoder = require("../lib/article");
var BufferPool = require("../lib/bufferpool");
var encryption = require("../lib/encryption");
var UploadManager = require("../lib/uploadmgr");
var y = require("yencode");

var toBuffer = Buffer.alloc ? Buffer.from : Buffer;
var bufferSlice = Buffer.prototype.readBigInt64BE ? Buffer.prototype.subarray : Buffer.prototype.slice;

if (typeof describe === "undefined") {
    global.describe = function(name, fn) { fn(); };
    global.it = function(name, fn) {
        if (fn.length > 0) {
            fn(function(err) {
                if (err) throw err;
                console.log("ok - " + name);
            });
        } else {
            fn();
            console.log("ok - " + name);
        }
    };
}

describe("Encrypted Article & Pipeline", function() {
    var password = "test-secret-password-12345";

    it("MultiEncoder produces encrypted article with bootstrap and control line encryption (unpooled)", function(done) {
        var encSession = new encryption.EncryptionSession(password, "0102030405060708090b0c0e0f101112", 1);
        var encoder = new MultiEncoder("test_file.bin", 100, 100, new Date("2026-01-01T00:00:00Z"), {
            encryptionSession: encSession
        });

        encoder.setHeaders({
            Subject: null,
            From: "poster@example.com"
        }, "[01/01] - ", " yEnc (1/1) 100");

        var plaintext = Buffer.alloc(100);
        for (var i = 0; i < 100; i++) plaintext[i] = (i * 7 + 13) & 0xff;

        var post = encoder.generate(plaintext, null);
        assert.ok(post.data, "post.data must exist");
        assert.equal(post.segmentIndex, 1, "segmentIndex should be 1");
        assert.ok(post.tag, "tag must exist");
        assert.equal(post.tag.length, 16, "tag must be 16 bytes");

        // Split NNTP headers and article body
        var headerEnd = post.data.indexOf("\r\n\r\n");
        assert.ok(headerEnd > 0, "must contain header separator");
        var body = bufferSlice.call(post.data, headerEnd + 4);

        // Check Line 1 bootstrap prefix: 16B salt + 4B segmentIndex
        assert.ok(body.length >= 20, "body must be at least 20 bytes for bootstrap");
        var salt = body.subarray(0, 16);
        assert.equal(salt.toString("hex"), "0102030405060708090b0c0e0f101112");
        var segIdx = body.readUInt32BE(16);
        assert.equal(segIdx, 1);

        // Line 1 does NOT start with plain "=ybegin" on the wire
        var line1End = body.indexOf("\r\n");
        assert.ok(line1End > 20);
        var line1Raw = body.subarray(0, line1End);
        assert.ok(!line1Raw.toString("ascii").startsWith("=ybegin"), "Line 1 must be encrypted");

        // Decrypt control lines
        var decResult = encryption.decryptControlLines(encSession.masterKey, body);
        assert.equal(decResult.segmentIndex, 1);
        assert.equal(decResult.salt.toString("hex"), "0102030405060708090b0c0e0f101112");

        var decBodyStr = decResult.buffer.toString("latin1");
        var decLines = decBodyStr.split("\r\n").filter(function(l) { return l.length > 0 && l !== "."; });

        // Line 1: =ybegin
        assert.ok(decLines[0].startsWith("=ybegin "), "Decrypted Line 1 must start with =ybegin");
        assert.ok(decLines[0].indexOf("name=test_file.bin") !== -1);

        // Line 2: =ypart
        assert.ok(decLines[1].startsWith("=ypart "), "Decrypted Line 2 must start with =ypart");

        // Line 3: =yencryption
        assert.ok(decLines[2].startsWith("=yencryption "), "Decrypted Line 3 must start with =yencryption");
        var parsedYenc = encryption.parseYencryptionLine(decLines[2]);
        assert.equal(parsedYenc.cipher, "XChaCha20-Poly1305");
        assert.equal(parsedYenc.segmentIndex, 1);
        assert.equal(parsedYenc.salt.toString("hex"), "0102030405060708090b0c0e0f101112");
        assert.equal(parsedYenc.tag.toString("hex"), post.tag.toString("hex"));

        // Footer: =yend
        var lastLine = decLines[decLines.length - 1];
        assert.ok(lastLine.startsWith("=yend "), "Decrypted footer must start with =yend");

        // Data lines decode to ciphertext, which then decrypts to plaintext
        var dataLines = decLines.slice(3, decLines.length - 1);
        var dataBuf = Buffer.from(dataLines.join("\r\n") + "\r\n", "latin1");
        var decodedCiphertext = y.decode(dataBuf);
        assert.equal(decodedCiphertext.length, plaintext.length);
        assert.notEqual(decodedCiphertext.toString("hex"), plaintext.toString("hex"), "Ciphertext must differ from plaintext");

        var decryptedPlaintext = encSession.decryptBody(1, decodedCiphertext, parsedYenc.tag);
        assert.equal(decryptedPlaintext.toString("hex"), plaintext.toString("hex"), "Decrypted plaintext must match original");

        done();
    });

    it("MultiEncoder produces encrypted article with pooled buffer and deterministic reload", function(done) {
        var encSession = new encryption.EncryptionSession(password, null, 42);
        var pool = new BufferPool(MultiEncoder.maxSize(200, 128) + 1024);

        var encoder = new MultiEncoder("archive.tar", 200, 100, new Date("2026-01-01T00:00:00Z"), {
            encryptionSession: encSession
        });

        encoder.setHeaders({
            Subject: null
        }, "[01/02] - ", " yEnc (1/2) 200");

        var chunk1 = Buffer.alloc(100, 0x41); // 'A'
        var post1 = encoder.generate(chunk1, pool);
        assert.equal(post1.segmentIndex, 42);

        var chunk2 = Buffer.alloc(100, 0x42); // 'B'
        var post2 = encoder.generate(chunk2, pool);
        assert.equal(post2.segmentIndex, 43);

        // Check determinism across releaseData() and reloadData()
        var originalData1 = Buffer.from(post1.data);
        post1.releaseData();
        assert.equal(post1.data, null);

        post1.reloadData(chunk1);
        assert.ok(post1.data, "post1.data must be reloaded");
        assert.equal(post1.segmentIndex, 42, "post1.segmentIndex must be preserved on reload");
        assert.equal(post1.data.toString("hex"), originalData1.toString("hex"), "Reloaded bytes must match original byte-for-byte");

        // Reload post2 as well
        var originalData2 = Buffer.from(post2.data);
        post2.releaseData();
        post2.reloadData(chunk2);
        assert.equal(post2.segmentIndex, 43, "post2.segmentIndex must be preserved on reload");
        assert.equal(post2.data.toString("hex"), originalData2.toString("hex"), "Reloaded bytes must match original byte-for-byte");

        done();
    });

    it("SegmentIndexAllocator monotonically increments and skips forbidden bytes 0x0A/0x0D", function(done) {
        // Start near 0x09
        var allocator = new encryption.SegmentIndexAllocator(0x09);
        assert.equal(allocator.next(), 0x09);
        // Next would be 0x0A (forbidden), then 0x0D (forbidden), so next permitted is 0x0B
        assert.equal(allocator.next(), 0x0b);
        assert.equal(allocator.next(), 0x0c);
        // Next would be 0x0D (forbidden), so next is 0x0E
        assert.equal(allocator.next(), 0x0e);
        done();
    });

    it("Unencrypted uploads remain 100% untouched and standard yEnc", function(done) {
        var plaintext = Buffer.from("Hello, standard unencrypted yEnc Usenet article!12");
        assert.equal(plaintext.length, 50);
        var encoder = new MultiEncoder("unencrypted.txt", 50, 100, new Date("2026-01-01T00:00:00Z"));
        encoder.setHeaders({
            Subject: null
        }, "", " yEnc (1/1) 50");
        var post = encoder.generate(plaintext, null);
        assert.equal(post.segmentIndex, null);
        assert.equal(post.tag, null);

        var headerEnd = post.data.indexOf("\r\n\r\n");
        var body = bufferSlice.call(post.data, headerEnd + 4);

        // Line 1 MUST start with literal =ybegin
        assert.ok(body.toString("ascii").startsWith("=ybegin "), "Unencrypted article MUST start with =ybegin");
        assert.ok(body.indexOf("=yencryption") === -1, "Unencrypted article MUST NOT contain =yencryption");

        // Direct yEnc decode recovers plaintext directly
        var lines = body.toString("latin1").split("\r\n").filter(function(l) { return l.length > 0 && l !== "."; });
        assert.ok(lines[0].startsWith("=ybegin "));
        assert.ok(lines[1].startsWith("=ypart "));
        assert.ok(lines[lines.length - 1].startsWith("=yend "));
        var dataLines = lines.slice(2, lines.length - 1);
        var dataBuf = Buffer.from(dataLines.join("\r\n") + "\r\n", "latin1");
        var decoded = y.decode(dataBuf);
        assert.equal(decoded.toString("utf8"), plaintext.toString("utf8"));
        done();
    });

    it("UploadManager sets subject prefix [1/1] - when encryptPassword is provided even for 1 file", function(done) {
        var um = new UploadManager({
            encryptPassword: "secret-password",
            useBufferPool: false,
            servers: []
        }, function() {});

        assert.ok(um.encryptionSession, "encryptionSession must be instantiated on UploadManager");
        assert.equal(typeof um.encryptionSession.masterKey, "object");

        var file = {
            num: 1,
            name: "singlefile.mkv",
            size: 50,
            collection: "c1"
        };

        var readCalled = false;
        var fakeStream = {
            read: function(size, cb) {
                if (readCalled) {
                    cb(null, Buffer.alloc(0));
                } else {
                    readCalled = true;
                    cb(null, Buffer.alloc(50, 0x5a));
                }
            }
        };

        var postInspected = false;
        um.uploader.addPost = function(post, cbNext, cbDone) {
            var headers = post._getHeadersStr();
            assert.ok(headers.indexOf("Subject: [1/1] - \"singlefile.mkv\" yEnc (1/1) 50") !== -1,
                "Subject must have [1/1] - prefix when encryption is active: " + headers);
            postInspected = true;
            cbNext();
            cbDone(null);
        };

        um.addFile(file, 1, { Subject: null }, fakeStream, function(err) {
            assert.ifError(err);
            assert.ok(postInspected, "post must have been inspected");
            done();
        });
    });

    it("UploadManager without encryptPassword does NOT add [1/1] - prefix for 1 file", function(done) {
        var um = new UploadManager({
            useBufferPool: false,
            servers: []
        }, function() {});

        assert.equal(um.encryptionSession, null);

        var file = {
            num: 1,
            name: "singlefile.mkv",
            size: 50,
            collection: "c1"
        };

        var readCalled = false;
        var fakeStream = {
            read: function(size, cb) {
                if (readCalled) {
                    cb(null, Buffer.alloc(0));
                } else {
                    readCalled = true;
                    cb(null, Buffer.alloc(50, 0x5a));
                }
            }
        };

        var postInspected = false;
        um.uploader.addPost = function(post, cbNext, cbDone) {
            var headers = post._getHeadersStr();
            assert.ok(headers.indexOf("Subject: \"singlefile.mkv\" yEnc (1/1) 50") !== -1,
                "Unencrypted single file must not have [1/1] - prefix: " + headers);
            postInspected = true;
            cbNext();
            cbDone(null);
        };

        um.addFile(file, 1, { Subject: null }, fakeStream, function(err) {
            assert.ifError(err);
            assert.ok(postInspected, "post must have been inspected");
            done();
        });
    });
});

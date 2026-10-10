"use strict";

var assert = require('assert');
var path = require('path');

var cryptoCore = require('../lib/crypto');
var ff1 = require('../lib/ff1');

var vectorsDir = path.resolve(__dirname, 'test-vectors');
var fs = require('fs');
var manifest = JSON.parse(fs.readFileSync(path.join(vectorsDir, 'manifest.json'), 'utf8'));
var argonVectors = require(path.join(vectorsDir, 'argon2id.json'));
var nonceVectors = require(path.join(vectorsDir, 'nonce_tweak.json'));
var bodyVectors = require(path.join(vectorsDir, 'body_encryption.json'));
var controlVectors = require(path.join(vectorsDir, 'control_line_encryption.json'));

// the canonical fixture set pinned by manifest.json (byte-identical copies of
// the reference standards repository's vectors)
var VECTOR_FILES = [
	'argon2id.json',
	'body_encryption.json',
	'control_line_encryption.json',
	'index_allocation.json',
	'malformed_inputs.json',
	'nonce_tweak.json',
	'nzb_segment_identity.json'
];

function hex(value) {
	return Buffer.from(value).toString('hex');
}

describe('yEnc encryption crypto', function() {
	this.timeout(30000);

	it('manifest sha256 sync: every vendored fixture matches its pinned hash', function() {
		assert.equal(manifest.standard_version, '1.2', 'fixture set must be v1.2');
		assert.deepEqual(
			Object.keys(manifest.files).sort(),
			VECTOR_FILES.slice().sort(),
			'manifest must list exactly the canonical 7 vector files'
		);
		VECTOR_FILES.forEach(function(file) {
			var expected = manifest.files[file].sha256;
			assert.ok(expected, 'manifest entry missing sha256 for ' + file);
			var hash = require('crypto').createHash('sha256')
				.update(fs.readFileSync(path.join(vectorsDir, file)))
				.digest('hex');
			assert.equal(hash, expected, 'sha256 drift for ' + file);
		});
	});

	it('matches every canonical Argon2id vector', async function() {
		for(var i = 0; i < argonVectors.vectors.length; i++) {
			var vector = argonVectors.vectors[i];
			var key = await cryptoCore.deriveKey(vector.password, Buffer.from(vector.salt_hex, 'hex'));
			assert.equal(hex(key), vector.expected_key_hex, vector.id);
		}
	});

	it('matches canonical body nonce and control key/tweak vectors', function() {
		nonceVectors.body_nonce_vectors.forEach(function(vector) {
			var nonce = cryptoCore.deriveBodyNonce(Buffer.from(vector.key_hex, 'hex'), vector.segment_index);
			assert.equal(hex(nonce), vector.expected_nonce_hex, vector.id);
		});
		nonceVectors.control_tweak_vectors.forEach(function(vector) {
			var masterKey = Buffer.from(vector.master_key_hex, 'hex');
			assert.equal(hex(cryptoCore.deriveControlKey(masterKey)), vector.enc_key_hex, vector.id + ' key');
			assert.equal(
				hex(cryptoCore.deriveControlTweak(masterKey, vector.segment_index, vector.line_index)),
				vector.expected_tweak_hex,
				vector.id + ' tweak'
			);
		});
	});

	it('matches canonical XChaCha20-Poly1305 vectors', function() {
		bodyVectors.vectors.forEach(function(vector) {
			var result = cryptoCore.encryptBody(
				Buffer.from(vector.plaintext_hex, 'hex'),
				Buffer.from(vector.derived_key_hex, 'hex'),
				vector.segment_index
			);
			assert.equal(hex(result.nonce), vector.derived_nonce_hex, vector.id + ' nonce');
			assert.equal(hex(result.ciphertext), vector.expected_ciphertext_hex, vector.id + ' ciphertext');
			assert.equal(hex(result.tag), vector.expected_tag_hex, vector.id + ' tag');
			var formattedIndex = vector.segment_index.toString(16).padStart(8, '0');
			assert.equal(formattedIndex, vector.expected_index_hex, vector.id + ' index_hex');
			var expectedLine = '=yencryption cipher=XChaCha20-Poly1305 salt=' + vector.salt_hex +
				' index=' + formattedIndex +
				' tag=' + hex(result.tag);
			assert.equal(expectedLine, vector.expected_yencryption_line, vector.id + ' yencryption_line');
		});
	});

	it('matches canonical Radix 253 FF1 vectors and validates 20-byte Line 1 expansion', function() {
		controlVectors.vectors.forEach(function(vector) {
			if(!vector.plaintext_line) return;
			var masterKey = Buffer.from(
				nonceVectors.control_tweak_vectors[0].master_key_hex,
				'hex'
			);
			var plaintext = Buffer.from(vector.plaintext_line, 'ascii');
			var salt = Buffer.from(vector.salt_hex, 'hex');
			var wire = ff1.encryptControlLine(
				plaintext,
				masterKey,
				vector.segment_index,
				vector.line_index,
				salt
			);
			assert.equal(hex(wire), vector.expected_wire_hex, vector.id);
			if(vector.line_index === 1) {
				assert.equal(wire.length, plaintext.length + 20, vector.id + ' length');
				assert.equal(wire.subarray(0, 16).toString('hex'), vector.salt_hex, vector.id + ' salt');
				assert.equal(wire.subarray(16, 20).readUInt32BE(0), vector.segment_index, vector.id + ' segmentIndex');
			} else {
				assert.equal(wire.length, plaintext.length, vector.id + ' length');
			}
		});
	});

	it('encrypts only control lines while preserving line endings and data', function() {
		['control-vec-07-full-article-4-lines', 'control-vec-08-full-article-54-lines'].forEach(function(vecId) {
			var vector = controlVectors.vectors.filter(function(item) {
				return item.id === vecId;
			})[0];
			if(!vector) return;
			var masterKey = Buffer.from(nonceVectors.control_tweak_vectors[0].master_key_hex, 'hex');
			var input = Buffer.from(vector.input_lines.join('\r\n') + '\r\n', 'ascii');
			var expected = Buffer.concat(vector.expected_wire_lines_hex.map(function(line) {
				return Buffer.concat([Buffer.from(line, 'hex'), Buffer.from('\r\n', 'ascii')]);
			}));
			var encrypted = ff1.encryptControlLines(
				input,
				masterKey,
				vector.segment_index,
				Buffer.from(vector.salt_hex, 'hex')
			);
			assert.deepEqual(encrypted, expected, vecId);
		});
	});

	it('uses one alphabet-safe salt for body and control-line encryption', async function() {
		var salt = cryptoCore.generateEncryptionSalt();
		assert.equal(salt.length, 16);
		salt.forEach(function(value) {
			assert.doesNotThrow(function() { ff1.byteToNumeral(value); });
		});
		var keys = await cryptoCore.deriveKeys('test123', salt);
		assert.equal(keys.masterKey.length, 32);
		assert.equal(keys.bodyKey.length, 32);
		assert.equal(keys.controlKey.length, 32);
		assert.deepEqual(keys.bodyKey, keys.masterKey);
		assert.deepEqual(keys.controlKey, cryptoCore.deriveControlKey(keys.masterKey));
	});

	it('rejects stale zero-based and uint64 segment assumptions', function() {
		var key = Buffer.alloc(32);
		assert.throws(function() { cryptoCore.deriveBodyNonce(key, 0); }, /1 to 4294967295/);
		assert.throws(function() { cryptoCore.deriveBodyNonce(key, 4294967296); }, /1 to 4294967295/);
		assert.throws(function() { cryptoCore.deriveControlTweak(key, 1, 0); }, /1 to 4294967295/);
	});

	it('validates 16-byte salt and uint32 range for Line 1 bootstrap prefix', function() {
		var masterKey = Buffer.alloc(32, 1);
		var validSalt = Buffer.alloc(16, 5);
		var line = Buffer.from('=ybegin part=1 total=1 line=128 size=123 name=test', 'ascii');
		// Valid Line 1
		var wire = ff1.encryptControlLine(line, masterKey, 1, 1, validSalt);
		assert.equal(wire.length, line.length + 20);
		// Salt length must be exactly 16
		assert.throws(function() { ff1.encryptControlLine(line, masterKey, 1, 1, Buffer.alloc(15)); }, /Line 1 requires the 16-byte encryption salt/);
		assert.throws(function() { ff1.encryptControlLine(line, masterKey, 1, 1, null); }, /Line 1 requires the 16-byte encryption salt/);
		// Salt must be within Radix 253 alphabet (no 0, 10, 13)
		var badSalt = Buffer.from(validSalt);
		badSalt[0] = 0;
		assert.throws(function() { ff1.encryptControlLine(line, masterKey, 1, 1, badSalt); }, /byte outside the Radix 253 alphabet/);
		// Segment index must be valid uint32 >= 1
		assert.throws(function() { ff1.encryptControlLine(line, masterKey, 0, 1, validSalt); }, /1 to 4294967295/);
		assert.throws(function() { ff1.encryptControlLine(line, masterKey, 4294967296, 1, validSalt); }, /1 to 4294967295/);
	});

	it('skips CR-02 forbidden segmentIndex bytes when allocating indices', function() {
		// CR-02: uint32_be(segmentIndex) bytes 0x0A/0x0D would split Line 1 on the wire.
		// assign-and-advance semantics: counter initialized at 0, first article gets 1.
		assert.equal(cryptoCore.nextSafeSegmentIndex(0), 1, 'first article receives index 1');

		// canonical index_allocation.json (VEC-07) skip vectors
		var indexVectors = require(path.join(vectorsDir, 'index_allocation.json')).vectors;
		indexVectors.forEach(function(vector) {
			assert.equal(cryptoCore.nextSafeSegmentIndex(vector.candidate_index - 1), vector.expected_assigned_index, vector.id);
		});

		// contiguous run across the 265..270 span: 265 -> 267 (266 skipped) -> 268 -> 270 (269 skipped) -> 271
		var span = [];
		var idx = 264;
		for(var i = 0; i < 7; i++) {
			idx = cryptoCore.nextSafeSegmentIndex(idx);
			span.push(idx);
		}
		assert.deepEqual(span, [265, 267, 268, 270, 271, 272, 273], '265..270 span skips 266 and 269');

		assert(cryptoCore.hasForbiddenSegmentIndexByte(10));
		assert(cryptoCore.hasForbiddenSegmentIndexByte(13));
		assert(cryptoCore.hasForbiddenSegmentIndexByte(266));
		assert(cryptoCore.hasForbiddenSegmentIndexByte(269));
		assert(!cryptoCore.hasForbiddenSegmentIndexByte(11));
		assert(!cryptoCore.hasForbiddenSegmentIndexByte(270));
		// a forbidden byte in any of the four positions triggers the skip
		assert(cryptoCore.hasForbiddenSegmentIndexByte(0x0A000000));
		assert(cryptoCore.hasForbiddenSegmentIndexByte(0x000D0000));
	});

	it('rejects forbidden delimiter bytes in segmentIndex when encrypting Line 1', function() {
		var masterKey = Buffer.alloc(32, 1);
		var validSalt = Buffer.alloc(16, 1);
		var line = Buffer.from('=ybegin part=1 total=1 line=128 size=1000 name=test.bin');
		assert.throws(function() {
			ff1.encryptControlLine(line, masterKey, 10, 1, validSalt);
		}, /forbidden delimiter bytes/);
		assert.throws(function() {
			ff1.encryptControlLine(line, masterKey, 266, 1, validSalt);
		}, /forbidden delimiter bytes/);
	});

	it('exhausts segmentIndex space with an error instead of wrapping to zero', function() {
		assert.throws(function() {
			cryptoCore.nextSafeSegmentIndex(0xFFFFFFFF);
		}, /segmentIndex space exhausted/);
		// the last permitted index is still assignable
		assert.equal(cryptoCore.nextSafeSegmentIndex(0xFFFFFFFE), 0xFFFFFFFF);
	});
});

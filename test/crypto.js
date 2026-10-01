"use strict";

var assert = require('assert');
var path = require('path');

var cryptoCore = require('../lib/crypto');
var ff1 = require('../lib/ff1');

var vectorsDir = path.resolve(__dirname, 'test-vectors');
var argonVectors = require(path.join(vectorsDir, 'argon2id.json'));
var nonceVectors = require(path.join(vectorsDir, 'nonce_tweak.json'));
var bodyVectors = require(path.join(vectorsDir, 'body_encryption.json'));
var controlVectors = require(path.join(vectorsDir, 'control_line_encryption.json'));

function hex(value) {
	return Buffer.from(value).toString('hex');
}

describe('yEnc encryption crypto', function() {
	this.timeout(30000);

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
});

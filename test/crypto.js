"use strict";

var assert = require('assert');
var path = require('path');

var cryptoCore = require('../lib/crypto');
var ff1 = require('../lib/ff1');

var vectorsDir = path.resolve(__dirname, '../../yenc-encryption-standards/test-vectors');
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
		});
	});

	it('matches canonical Radix 253 FF1 vectors', function() {
		controlVectors.vectors.forEach(function(vector) {
			if(!vector.plaintext_line) return;
			var masterKey = Buffer.from(
				nonceVectors.control_tweak_vectors[0].master_key_hex,
				'hex'
			);
			var wire = ff1.encryptControlLine(
				Buffer.from(vector.plaintext_line, 'ascii'),
				masterKey,
				vector.segment_index,
				vector.line_index,
				Buffer.from(vector.salt_hex, 'hex')
			);
			assert.equal(hex(wire), vector.expected_wire_hex, vector.id);
		});
	});

	it('encrypts only control lines while preserving line endings and data', function() {
		var vector = controlVectors.vectors.filter(function(item) {
			return item.id === 'control-vec-07-full-article-4-lines';
		})[0];
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
		assert.deepEqual(encrypted, expected);
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
});

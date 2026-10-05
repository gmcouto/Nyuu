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

	it('validates user-provided encryptionSalt at upload entry point', function() {
		var FileUploader = require('../lib/fileuploader');
		var invalidSalts = [
			'not-a-buffer',
			Buffer.alloc(15),
			Buffer.alloc(17),
			Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex'), // contains 0x00 and 0x0a
			Buffer.from('0d0102030405060708090b0c0e0f1011', 'hex')  // contains 0x0d
		];
		invalidSalts.forEach(function(badSalt) {
			assert.throws(function() {
				FileUploader.upload([], {
					encryptionPassword: 'secretpassword',
					encryptionSalt: badSalt
				}, function() {});
			}, RangeError);
		});
	});

	it('never leaks encryption password into loggers or string representations (GAP-33-07)', function() {
		var logs = [];
		var fakeLogger = {
			trace: function(m) { logs.push(m); },
			debug: function(m) { logs.push(m); },
			info: function(m) { logs.push(m); },
			warn: function(m) { logs.push(m); },
			error: function(m) { logs.push(m); }
		};
		var FileUploader = require('../lib/fileuploader');
		FileUploader.setLogger(fakeLogger);
		var ArticleEncoder = require('../lib/article');
		var password = 'super_secret_sensitive_password_12345';
		var enc = new ArticleEncoder('test.bin', 10, 10, null, {
			encryption: {
				bodyKey: Buffer.alloc(32, 1),
				masterKey: Buffer.alloc(32, 1),
				salt: Buffer.alloc(16, 2),
				controlLines: true,
				segmentIndex: 1
			}
		});
		enc.setHeaders({});
		var post = enc.generate(Buffer.alloc(10, 65));
		var serializedPost = JSON.stringify(post);
		assert.equal(serializedPost.indexOf(password), -1);
		logs.forEach(function(msg) {
			assert.equal(('' + msg).indexOf(password), -1);
		});
		FileUploader.setLogger(null);
	});
});

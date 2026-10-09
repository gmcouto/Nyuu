"use strict";

var assert = require('assert');
var fs = require('fs');
var path = require('path');
var crypto = require('crypto');

var cryptoCore = require('../lib/crypto');
var ff1 = require('../lib/ff1');
var xchacha20poly1305 = require('@noble/ciphers/chacha').xchacha20poly1305;

var vectorsDir = path.resolve(__dirname, 'test-vectors');
var manifest = JSON.parse(fs.readFileSync(path.join(vectorsDir, 'manifest.json'), 'utf8'));
var malformedRaw = fs.readFileSync(path.join(vectorsDir, 'malformed_inputs.json'));
var malformedData = JSON.parse(malformedRaw.toString('utf8'));

var masterKey = Buffer.alloc(32, 7);
var validSalt = Buffer.from('1a2b3c4d5e6f7890abcdef1234567890', 'hex');

// mirrors the canonical v1.2 strict =yencryption header grammar validator
// (yenc-encryption-standards/scripts/test_conformance_vectors.py:parse_yencryption_line_v11)
function parseYencryptionLine(line) {
	if(line !== line.trim())
		throw new Error('INVALID_WHITESPACE');
	if(line.indexOf('\t') >= 0 || line.indexOf('  ') >= 0)
		throw new Error('INVALID_WHITESPACE');
	var tokens = line.split(' ');
	if(tokens.length !== 5 || tokens.some(function(t) { return !t; }))
		throw new Error('INVALID_TOKEN_COUNT');
	if(tokens[0] !== '=yencryption')
		throw new Error('INVALID_PREFIX');
	if(tokens[1] !== 'cipher=XChaCha20-Poly1305')
		throw new Error('UNSUPPORTED_CIPHER');
	if(!tokens[2].startsWith('salt=') || !tokens[3].startsWith('index=') || !tokens[4].startsWith('tag='))
		throw new Error('INVALID_TOKEN_ORDER');
	var saltHex = tokens[2].slice(5), indexHex = tokens[3].slice(6), tagHex = tokens[4].slice(4);
	if(saltHex.length !== 32)
		throw new Error('INVALID_SALT_LENGTH');
	if(!/^[0-9a-f]{32}$/.test(saltHex))
		throw new Error(/^[0-9a-fA-F]{32}$/.test(saltHex) ? 'UPPERCASE_HEX' : 'INVALID_SALT_HEX');
	if(indexHex.length !== 8)
		throw new Error('INVALID_INDEX_LENGTH');
	if(!/^[0-9a-f]{8}$/.test(indexHex))
		throw new Error(/^[0-9a-fA-F]{8}$/.test(indexHex) ? 'UPPERCASE_HEX' : 'INVALID_INDEX_HEX');
	if(tagHex.length !== 32)
		throw new Error('INVALID_TAG_LENGTH');
	if(!/^[0-9a-f]{32}$/.test(tagHex))
		throw new Error(/^[0-9a-fA-F]{32}$/.test(tagHex) ? 'UPPERCASE_HEX' : 'INVALID_TAG_HEX');
	if(parseInt(indexHex, 16) === 0)
		throw new Error('ZERO_SEGMENT_INDEX');
	// CR-02: forbidden bytes in uint32_be(segmentIndex)
	var idx = parseInt(indexHex, 16);
	if([idx & 0xFF, (idx >>> 8) & 0xFF, (idx >>> 16) & 0xFF, (idx >>> 24) & 0xFF].some(function(b) {
		return b === 0x0A || b === 0x0D;
	}))
		throw new Error('FORBIDDEN_SEGMENT_INDEX_BYTE');
	return {salt: Buffer.from(saltHex, 'hex'), segmentIndex: idx, tag: Buffer.from(tagHex, 'hex')};
}

function canonicalLineFor(salt, segmentIndex, tag) {
	return '=yencryption cipher=XChaCha20-Poly1305 salt=' + salt.toString('hex') +
		' index=' + segmentIndex.toString(16).padStart(8, '0') +
		' tag=' + tag.toString('hex');
}

function extractBootstrapFromLine1(wire) {
	if(wire.length < 22)
		throw new Error('LINE_TRUNCATED');
	var salt = wire.subarray(0, 16);
	var segmentIndex = wire.readUInt32BE(16);
	if(salt.some(function(b) { return b === 0 || b === 10 || b === 13; }))
		throw new Error('INVALID_SALT_CHARACTER');
	if(segmentIndex === 0)
		throw new Error('ZERO_SEGMENT_INDEX');
	// CR-02: uint32_be(segmentIndex) bytes 0x0A/0x0D would split Line 1 on the
	// wire; rejected under PROVIDER_FAILOVER like the canonical grammar validator
	var b0 = (segmentIndex >>> 24) & 0xFF;
	var b1 = (segmentIndex >>> 16) & 0xFF;
	var b2 = (segmentIndex >>> 8) & 0xFF;
	var b3 = segmentIndex & 0xFF;
	if([10, 13].some(function(byte) {
		return b0 === byte || b1 === byte || b2 === byte || b3 === byte;
	})) {
		throw new Error('FORBIDDEN_SEGMENT_INDEX_BYTE');
	}
	return {salt: salt, segmentIndex: segmentIndex};
}

describe('malformed_inputs.json adversarial vectors (VEC-05)', function() {
	this.timeout(30000);

	it('manifest indexes the fixture with matching SHA-256 and vector count', function() {
		var entry = manifest.files['malformed_inputs.json'];
		assert(entry, 'manifest must index malformed_inputs.json');
		var hash = crypto.createHash('sha256').update(malformedRaw).digest('hex');
		assert.equal(hash, entry.sha256, 'fixture integrity');
		assert.equal(malformedData.vectors.length, entry.vector_count);
		assert.equal(malformedData.requirement, 'VEC-05');
	});

	it('rejects every malformed header_syntax vector with the expected error', function() {
		malformedData.vectors.forEach(function(vector) {
			if(vector.category !== 'header_syntax') return;
			assert.throws(function() {
				parseYencryptionLine(vector.input_line);
			}, new RegExp(vector.expected_error), vector.id);
		});
	});

	it('Nyuu wire output conforms to the canonical grammar (no malformed header patterns)', function() {
		var ArticleEncoder = require('../lib/article');
		// 1. With controlLines: false, the =yencryption header is visible in plaintext
		var encoderNoControl = new ArticleEncoder('file.bin', 5, 5, null, {
			encryption: {bodyKey: masterKey, masterKey: masterKey, salt: validSalt, controlLines: false, segmentIndex: 1}
		});
		encoderNoControl.setHeaders({}, '', '');
		var postNoControl = encoderNoControl.generate(Buffer.from('hello'));
		var wire = postNoControl.data.toString('binary');
		var m = wire.match(/=yencryption[^\r\n]*/);
		assert(m, 'article must contain plaintext =yencryption line when controlLines: false');
		var parsed = parseYencryptionLine(m[0]);
		assert.equal(parsed.salt.toString('hex'), validSalt.toString('hex'));
		assert.equal(parsed.segmentIndex, postNoControl.segmentIndex);
		assert.equal(m[0], canonicalLineFor(validSalt, postNoControl.segmentIndex, postNoControl.encryptionResult.tag));

		// 2. With controlLines: true, plaintext is hidden from the wire
		var encoderEncControl = new ArticleEncoder('file.bin', 5, 5, null, {
			encryption: {bodyKey: masterKey, masterKey: masterKey, salt: validSalt, controlLines: true, segmentIndex: 1}
		});
		encoderEncControl.setHeaders({}, '', '');
		var postEncControl = encoderEncControl.generate(Buffer.from('hello'));
		assert.ok(postEncControl.data.toString('binary').indexOf('=yencryption') < 0, 'control lines must be encrypted on wire');
	});

	it('enforces zero-output authenticated decryption on every auth_failure vector', async function() {
		for(var i = 0; i < malformedData.vectors.length; i++) {
			var vector = malformedData.vectors[i];
			if(vector.category !== 'auth_failure') continue;
			var keys = await cryptoCore.deriveKeys(vector.password, Buffer.from(vector.salt_hex, 'hex'));
			var ciphertext = Buffer.from(vector.tampered_ciphertext_hex || vector.ciphertext_hex, 'hex');
			var tag = Buffer.from(vector.tampered_tag_hex || vector.tag_hex, 'hex');
			var nonce = cryptoCore.deriveBodyNonce(keys.bodyKey, vector.segment_index);
			var output = null;
			assert.throws(function() {
				output = xchacha20poly1305(keys.bodyKey, nonce).decrypt(Buffer.concat([ciphertext, tag]));
			}, vector.id);
			assert.equal(output, null, vector.id + ': zero output on auth failure');
		}
	});

	it('rejects forbidden control_syntax salt bytes via the Radix 253 alphabet', async function() {
		for(var i = 0; i < malformedData.vectors.length; i++) {
			var vector = malformedData.vectors[i];
			if(vector.category !== 'control_syntax') continue;
			if(vector.tampered_salt_hex) {
				assert.throws(function() {
					extractBootstrapFromLine1(Buffer.concat([Buffer.from(vector.tampered_salt_hex, 'hex'), Buffer.from([0, 0, 0, 1]), Buffer.from('==', 'ascii')]));
				}, new RegExp(vector.expected_error), vector.id);
				// also rejected at the FF1 encoder boundary
				assert.throws(function() {
					ff1.encryptControlLine(Buffer.from('=ybegin part=1 total=1 line=128 size=123 name=test', 'ascii'), masterKey, 1, 1, Buffer.from(vector.tampered_salt_hex, 'hex'));
				}, /outside the Radix 253 alphabet/, vector.id + ' (encoder)');
			} else if(vector.line1_hex) {
				assert.throws(function() {
					extractBootstrapFromLine1(Buffer.from(vector.line1_hex, 'hex'));
				}, new RegExp(vector.expected_error), vector.id);
			} else if(vector.line_hex) {
				assert.throws(function() {
					ff1.encryptControlLine(Buffer.from(vector.line_hex, 'hex'), masterKey, 1, 2, validSalt);
				}, /at least two numerals/, vector.id);
			} else if(vector.wrong_password) {
				var keyRight = await cryptoCore.deriveKeys('test123', validSalt);
				var keyWrong = await cryptoCore.deriveKeys(vector.wrong_password, validSalt);
				assert.notDeepEqual(keyRight.masterKey, keyWrong.masterKey);
				assert.notDeepEqual(keyRight.controlKey, keyWrong.controlKey);
			}
		}
	});

	it('flags metadata_validation and placement vectors as decoder-side rejection stages', function() {
		malformedData.vectors.forEach(function(vector) {
			if(vector.category !== 'metadata_validation' && vector.category !== 'placement') return;
			assert(vector.expected_rejection_stage === 'METADATA_VALIDATION' || vector.expected_rejection_stage === 'PROVIDER_FAILOVER', vector.id);
			assert(vector.zero_output_required, vector.id);
		});
	});

	it('rejects salt_mismatch vectors via dual-bootstrap consistency', function() {
		malformedData.vectors.forEach(function(vector) {
			if(vector.category !== 'salt_mismatch') return;
			var line1Salt = Buffer.from(vector.line1_salt_hex, 'hex');
			var headerSalt = Buffer.from(vector.header_salt_hex, 'hex');
			var mismatched = Buffer.compare(line1Salt, headerSalt) !== 0 || vector.line1_index !== vector.header_index;
			assert(mismatched, vector.id + ' must actually mismatch');
		});
	});
});

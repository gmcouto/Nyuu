"use strict";

var assert = require('assert');
var fs = require('fs');
var path = require('path');
var crypto = require('crypto');

var ff1 = require('../lib/ff1');
var ArticleEncoder = require('../lib/article');

var vectorsDir = path.resolve(__dirname, 'test-vectors');
var manifest = JSON.parse(fs.readFileSync(path.join(vectorsDir, 'manifest.json'), 'utf8'));
var malformedRaw = fs.readFileSync(path.join(vectorsDir, 'malformed_inputs.json'));
var malformedData = JSON.parse(malformedRaw.toString('utf8'));

var masterKey = Buffer.alloc(32, 7);
var validSalt = Buffer.from('1a2b3c4d5e6f7890abcdef1234567890', 'hex');

describe('malformed_inputs.json adversarial vectors (VEC-05)', function() {
	it('manifest indexes the fixture with matching SHA-256 and vector count', function() {
		var entry = manifest.files['malformed_inputs.json'];
		assert(entry, 'manifest must index malformed_inputs.json');
		var hash = crypto.createHash('sha256').update(malformedRaw).digest('hex');
		assert.equal(hash, entry.sha256, 'fixture integrity');
		assert.equal(malformedData.vectors.length, entry.vector_count);
		assert.equal(malformedData.requirement, 'VEC-05');
	});

	it('Nyuu wire output conforms to the canonical grammar (no malformed header patterns)', function() {
		// combined mode encrypts all control lines: the =yencryption header is hidden from the wire
		var encoder = new ArticleEncoder('file.bin', 5, 5, null, {
			encryption: {bodyKey: masterKey, masterKey: masterKey, salt: validSalt, segmentIndex: 1}
		});
		encoder.setHeaders({}, '', '');
		var post = encoder.generate(Buffer.from('hello'));
		assert.ok(post.data.toString('binary').indexOf('=yencryption') < 0, 'control lines must be encrypted on wire');
	});

	it('rejects forbidden control_syntax salt bytes via the Radix 253 alphabet', function() {
		malformedData.vectors.forEach(function(vector) {
			if(vector.category !== 'control_syntax') return;
			if(vector.tampered_salt_hex) {
				assert.throws(function() {
					ff1.encryptControlLine(
						Buffer.from('=ybegin part=1 total=1 line=128 size=123 name=test', 'ascii'),
						masterKey,
						1,
						1,
						Buffer.from(vector.tampered_salt_hex, 'hex')
					);
				}, /outside the Radix 253 alphabet/, vector.id + ' (encoder)');
			} else if(vector.line_hex) {
				assert.throws(function() {
					ff1.encryptControlLine(Buffer.from(vector.line_hex, 'hex'), masterKey, 1, 2, validSalt);
				}, /at least two numerals/, vector.id);
			}
		});
	});
});

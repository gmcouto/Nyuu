"use strict";

var assert = require("assert");
var ArticleEncoder = require('../lib/article');
var NZBGenerator = require('../lib/nzb');
var ff1 = require('../lib/ff1');
// Exercise individual lines through the production block API.
function encryptControlLine(line, key, segmentIndex, lineIndex, salt) {
	var prefix = Buffer.from('=ybegin name=test\r\n' + '\r\n'.repeat(Math.max(0, lineIndex - 2)));
	if(lineIndex === 1) prefix = Buffer.alloc(0);
	var block = Buffer.concat([prefix, line, Buffer.from('\r\n')]);
	var wire = ff1.encryptControlLines(block, key, segmentIndex, salt);
	return wire.subarray(wire.length - line.length - (lineIndex === 1 ? 20 : 0) - 2, wire.length - 2);
}


describe('Encrypted upload pipeline', function() {
	it('verifies combined default encryption with Line 1 bootstrap prefix and dual-bootstrap agreement', function() {
		var output = [];
		var nzb = new NZBGenerator({yenc_encrypted: 'true', password: 'test123'}, function(value, encoding) {
			output.push(Buffer.from(value, encoding));
		}, true, 'utf8');
		var salt = Buffer.from('0102030405060708090b0c0e0f101112', 'hex');
		var key = Buffer.alloc(32, 7);
		var segmentIndex = 1;

		var encoder = new ArticleEncoder('file.bin', 5, 5, null, {
			encryption: {
				key: key,
				salt: salt,
				segmentIndex: segmentIndex
			}
		});
		encoder.setHeaders({}, '', '');
		var post = encoder.generate(Buffer.from('hello'));
		// the whole-file CRC is of plaintext, so the final ciphertext part omits it
		assert.notEqual(post.crcFrag.indexOf(' pcrc32='), -1);
		assert.equal(post.crcFrag.indexOf(' crc32='), -1);
		nzb.file('file.bin (1/1)', 'poster', ['alt.test'], 1);
		nzb.addSegment(post.postLen, 'article@example.com');
		nzb.end();

		var wire = post.data.toString('binary');
		var xml = Buffer.concat(output).toString('utf8');

		// 1. Line 1 20-byte bootstrap prefix
		var line1Prefix = post.data.subarray(post.postPos, post.postPos + 20);
		var prefixSalt = line1Prefix.subarray(0, 16);
		var prefixSegmentIndex = line1Prefix.readUInt32BE(16);
		assert.equal(prefixSalt.toString('hex'), salt.toString('hex'));
		assert.equal(prefixSegmentIndex, segmentIndex);

		// 2. Control lines and body payload are encrypted (no plaintext on wire)
		assert.ok(wire.indexOf('=ybegin') < 0);
		assert.ok(wire.indexOf('=yencryption') < 0);
		assert.ok(wire.indexOf('hello') < 0);

		// 3. Dual-bootstrap agreement between Line 1 prefix and =yencryption header
		var expectedYencLine = '=yencryption cipher=XChaCha20-Poly1305 salt=' + prefixSalt.toString('hex') +
			' index=' + prefixSegmentIndex.toString(16).padStart(8, '0') +
			' tag=' + post.encryptionResult.tag.toString('hex');
		var encryptedYencLine = encryptControlLine(Buffer.from(expectedYencLine, 'ascii'), key, segmentIndex, 3, salt);

		var bodyBuf = post.data.subarray(post.postPos);
		var lines = [];
		var start = 0;
		for(var i = 0; i < bodyBuf.length; i++) {
			if(bodyBuf[i] === 10) {
				var end = (i > start && bodyBuf[i - 1] === 13) ? i - 1 : i;
				lines.push(bodyBuf.subarray(start, end));
				start = i + 1;
			}
		}
		assert.equal(lines[2].toString('hex'), encryptedYencLine.toString('hex'));

		// 4. NZB metadata and plain NZB 1.1 segment assertions
		assert.match(xml, /meta type="yenc_encrypted">true/);
		assert.match(xml, /meta type="password">test123/);
		var segmentTags = xml.match(/<segment [^>]*>/g) || [];
		assert.equal(segmentTags.length, 1);
		segmentTags.forEach(function(tag) {
			assert.match(tag, /^<segment bytes="\d+" number="\d+">$/);
		});
	});

	it('sets encryption metadata when opts.nzb is a factory function', function(done) {
		var fileuploader = require('../lib/fileuploader');
		var createdNzbOpts = null;
		var nzbFactory = function() {
			createdNzbOpts = {
				writeTo: function() {},
				metaData: {}
			};
			return ['custom_nzb', createdNzbOpts];
		};
		var opts = {
			encryptionEnabled: true,
			encryptionPassword: 'secretpassword',
			nzb: nzbFactory
		};
		fileuploader.upload([], opts, function() {
			assert.equal(typeof opts.nzb, 'function');
			var res = opts.nzb('arg1', 'arg2');
			assert.ok(res);
			assert.equal(res[1].metaData.yenc_encrypted, 'true');
			assert.equal(res[1].metaData.password, 'secretpassword');
			done();
		});
	});

	it('overrides a user-supplied false yenc_encrypted marker when encryption is enabled', function(done) {
		var fileuploader = require('../lib/fileuploader');
		var opts = {
			encryptionEnabled: true,
			encryptionPassword: 'secretpassword',
			nzb: {
				metaData: {
					yenc_encrypted: 'false'
				}
			}
		};
		fileuploader.upload([], opts, function(err) {
			assert.equal(err && err.message, 'No files to process');
			assert.equal(opts.nzb.metaData.yenc_encrypted, 'true');
			// assert on the GENERATED NZB, not just the input object
			var output = [];
			var nzb = new NZBGenerator(opts.nzb.metaData, function(value, encoding) {
				output.push(Buffer.from(value, encoding));
			}, true, 'utf8');
			nzb.file('file.bin (1/1)', 'poster', ['alt.test'], 1);
			nzb.addSegment(5, 'article@example.com');
			nzb.end();
			var xml = Buffer.concat(output).toString('utf8');
			assert.match(xml, /<meta type="yenc_encrypted">true<\/meta>/);
			assert.ok(xml.indexOf('yenc_encrypted">false') < 0, 'contradictory false marker must not appear');
			assert.equal(xml.match(/yenc_encrypted/g).length, 1);
			assert.match(xml, /<meta type="password">secretpassword<\/meta>/);
			done();
		});
	});

	describe('Archive password conflict rejection', function() {
		var fileuploader = require('../lib/fileuploader');

		it('rejects conflicting archive password in object nzb before posting', function(done) {
			var opts = {
				encryptionEnabled: true,
				encryptionPassword: 'transport-pw',
				nzb: {
					metaData: {
						password: 'archive-pw'
					}
				}
			};
			fileuploader.upload([], opts, function(err) {
				assert.ok(err, 'must return an error for conflicting password');
				assert.match(err.message, /conflicts with encryption password/);
				done();
			});
		});

		it('rejects conflicting array archive password in object nzb before posting', function(done) {
			var opts = {
				encryptionEnabled: true,
				encryptionPassword: 'transport-pw',
				nzb: {
					metaData: {
						password: ['archive-pw']
					}
				}
			};
			fileuploader.upload([], opts, function(err) {
				assert.ok(err, 'must return an error for conflicting password');
				assert.match(err.message, /conflicts with encryption password/);
				done();
			});
		});

		it('rejects conflicting archive password in factory function nzb', function(done) {
			var nzbFactory = function() {
				return ['custom_nzb', {metaData: {password: 'archive-pw'}}];
			};
			var opts = {
				encryptionEnabled: true,
				encryptionPassword: 'transport-pw',
				nzb: nzbFactory
			};
			fileuploader.upload([], opts, function() {
				assert.throws(function() {
					opts.nzb('arg1', 'arg2');
				}, /conflicts with encryption password/);
				done();
			});
		});

		it('accepts matching archive password in object nzb', function(done) {
			var opts = {
				encryptionEnabled: true,
				encryptionPassword: 'same-pw',
				nzb: {
					metaData: {
						password: 'same-pw'
					}
				}
			};
			fileuploader.upload([], opts, function(err) {
				assert.equal(err && err.message, 'No files to process');
				assert.equal(opts.nzb.metaData.yenc_encrypted, 'true');
				assert.equal(opts.nzb.metaData.password, 'same-pw');
				done();
			});
		});

		it('accepts matching array archive password in object nzb', function(done) {
			var opts = {
				encryptionEnabled: true,
				encryptionPassword: 'same-pw',
				nzb: {
					metaData: {
						password: ['same-pw']
					}
				}
			};
			fileuploader.upload([], opts, function(err) {
				assert.equal(err && err.message, 'No files to process');
				assert.equal(opts.nzb.metaData.yenc_encrypted, 'true');
				assert.equal(opts.nzb.metaData.password, 'same-pw');
				done();
			});
		});

		it('leaves unencrypted archive password untouched', function(done) {
			var opts = {
				nzb: {
					metaData: {
						password: 'my-archive-pw'
					}
				}
			};
			fileuploader.upload([], opts, function(err) {
				assert.equal(err && err.message, 'No files to process');
				assert.equal(opts.nzb.metaData.password, 'my-archive-pw');
				assert.strictEqual(opts.nzb.metaData.yenc_encrypted, undefined);
				done();
			});
		});
	});

	describe('CLI encryption flag and option precedence', function() {
		var child_process = require('child_process');
		var path = require('path');
		var binNyuu = path.resolve(__dirname, '../bin/nyuu.js');
		var os = require('os');
		var fs = require('fs');
		var tmpDir, notty;

		before(function() {
			tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nyuu-test-'));
			notty = path.join(tmpDir, 'notty.json');
			fs.writeFileSync(notty, JSON.stringify({colorize: false}));
		});
		after(function() {
			fs.rmSync(tmpDir, {recursive: true, force: true});
		});

		it('fails when --encrypt is given without a password', function(done) {
			child_process.execFile(process.execPath, [binNyuu, '-C', notty, '--encrypt'], function(err, stdout, stderr) {
				assert.ok(err, 'should fail with non-zero exit code');
				assert.match(stderr, /--encrypt-password.*required/);
				done();
			});
		});

		it('leaves archive-password validation to the uploader library', function(done) {
			child_process.execFile(process.execPath, [binNyuu, '-C', notty, '--encrypt-password', 'tpw', '--nzb-password', 'rarpw'], function(err, stdout, stderr) {
				assert.ok(err, 'missing input file should fail first');
				assert.doesNotMatch(stderr, /conflicts with encryption password/);
				assert.match(stderr, /Must supply at least one input file/);
				done();
			});
		});

		it('succeeds option validation when --nzb-password matches --encrypt-password', function(done) {
			child_process.execFile(process.execPath, [binNyuu, '-C', notty, '--encrypt-password', 'same', '--nzb-password', 'same'], function(err, stdout, stderr) {
				assert.doesNotMatch(stderr, /conflicts with encryption password/);
				assert.match(stderr, /Must supply at least one input file/);
				done();
			});
		});

		it('implicitly enables encryption when only --encrypt-password is provided', function(done) {
			child_process.execFile(process.execPath, [binNyuu, '-C', notty, '--encrypt-password', 'secret'], function(err, stdout, stderr) {
				assert.doesNotMatch(stderr, /--encrypt-password.*required/);
				assert.match(stderr, /Must supply at least one input file/);
				done();
			});
		});

		it('--no-encrypt disables encryption even if --encrypt-password is provided', function(done) {
			child_process.execFile(process.execPath, [binNyuu, '-C', notty, '--encrypt-password', 'secret', '--no-encrypt'], function(err, stdout, stderr) {
				assert.match(stderr, /Must supply at least one input file/);
				done();
			});
		});
	});
});

describe('Encrypted upload subject and metadata', function() {
	// the [N/M] prefix follows the ordinary multi-file presentation rule;
	// encryption does not alter subjects
	function runFileUpload(opts, fileNumTotal, checkSubject, cb) {
		var UploadManager = require('../lib/uploadmgr');
		var um = new UploadManager(Object.assign({useBufferPool: false, servers: []}, opts), function() {});
		var file = {num: 1, name: 'file.mkv', size: 50, collection: 'c1'};
		var readCalled = false;
		var fakeStream = {
			read: function(size, cbRead) {
				if(readCalled) {
					cbRead(null, Buffer.alloc(0));
				} else {
					readCalled = true;
					cbRead(null, Buffer.alloc(50, 0x5a));
				}
			}
		};
		um.uploader.addPost = function(post, cbNext, cbDone) {
			checkSubject(post._getHeadersStr());
			cbNext();
			cbDone(null);
		};
		um.addFile(file, fileNumTotal, {Subject: null}, fakeStream, function(err) {
			assert.ifError(err);
			cb();
		});
	}

	it('does not set [1/1] - subject prefix for single-file upload (encrypted or unencrypted)', function(done) {
		var cryptoCore = require('../lib/crypto');
		var salt = cryptoCore.generateEncryptionSalt();
		cryptoCore.deriveKey('test123', salt).then(function(key) {
			runFileUpload({
				encryption: {
					key: key,
					salt: salt
				}
			}, 1, function(headers) {
				assert.match(headers, /Subject: "file\.mkv" yEnc \(1\/1\) 50/,
					'encrypted single file must not have [1/1] - prefix: ' + headers);
			}, function() {
				runFileUpload({}, 1, function(headers) {
					assert.match(headers, /Subject: "file\.mkv" yEnc \(1\/1\) 50/,
						'unencrypted single file must not have [1/1] - prefix: ' + headers);
				}, done);
			});
		}).catch(done);
	});

	it('sets [1/2] - subject prefix for multi-file upload (encrypted or unencrypted)', function(done) {
		var cryptoCore = require('../lib/crypto');
		var salt = cryptoCore.generateEncryptionSalt();
		cryptoCore.deriveKey('test123', salt).then(function(key) {
			runFileUpload({
				encryption: {
					key: key,
					salt: salt
				}
			}, 2, function(headers) {
				assert.match(headers, /Subject: \[1\/2\] - "file\.mkv" yEnc \(1\/1\) 50/);
			}, done);
		}).catch(done);
	});
});

"use strict";

var assert = require("assert");
var ArticleEncoder = require('../lib/article');
var NZBGenerator = require('../lib/nzb');
var ff1 = require('../lib/ff1');

describe('Encrypted upload pipeline', function() {
	it('verifies combined default encryption with Line 1 bootstrap prefix and dual-bootstrap agreement', function() {
		var output = [];
		var nzb = new NZBGenerator({yenc_encrypted: 'true', password: 'test123'}, function(value, encoding) {
			output.push(Buffer.from(value, encoding));
		}, true, 'utf8');
		var salt = Buffer.from('0102030405060708090b0c0e0f101112', 'hex');
		var masterKey = Buffer.alloc(32, 7);
		var bodyKey = Buffer.alloc(32, 7);
		var segmentIndex = 1;

		var encoder = new ArticleEncoder('file.bin', 5, 5, null, {
			encryption: {
				bodyKey: bodyKey,
				masterKey: masterKey,
				salt: salt,
				controlLines: true,
				segmentIndex: segmentIndex
			}
		});
		encoder.setHeaders({}, '', '');
		var post = encoder.generate(Buffer.from('hello'));
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
		var encryptedYencLine = ff1.encryptControlLine(Buffer.from(expectedYencLine, 'ascii'), masterKey, segmentIndex, 3, salt);

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

	it('rejects body-only encryption attempts (combined-only wire mode)', function() {
		// v1 exposes only the combined wire mode: controlLines:false must be
		// rejected at generation time by the ArticleEncoder itself
		var salt = Buffer.from('0102030405060708090b0c0e0f101112', 'hex');
		var encOpts = {
			bodyKey: Buffer.alloc(32, 7),
			masterKey: Buffer.alloc(32, 7),
			salt: salt,
			controlLines: false,
			segmentIndex: 1
		};
		assert.throws(function() {
			var encoder = new ArticleEncoder('file.bin', 5, 5, null, {encryption: Object.assign({}, encOpts)});
			encoder.setHeaders({}, '', '');
			encoder.generate(Buffer.from('hello'));
		}, /Combined-only wire mode/);

		var encoder = new ArticleEncoder('file.bin', 5, 5, null, {encryption: Object.assign({}, encOpts, {controlLines: true})});
		encoder.setHeaders({}, '', '');
		assert.throws(function() {
			// a runtime flip of the flag must not leak a plaintext =yencryption line either
			encoder.encryption.controlLines = false;
			encoder.generate(Buffer.from('hello'));
		}, /Combined-only wire mode/);
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
			assert.equal(opts.nzb.metaData.yenc_encrypted, 'true');
			assert.equal(opts.nzb.metaData.password, 'secretpassword');
			var res = opts.nzb('arg1', 'arg2');
			assert.ok(res);
			assert.equal(res[1].metaData.yenc_encrypted, 'true');
			assert.equal(res[1].metaData.password, 'secretpassword');
			done();
		});
	});
});

describe('Encrypted single-file subject prefix', function() {
	// the [N/M] prefix is required whenever encryption is used, even for
	// single-file posts (the NZB subject identifies the release as encrypted)
	function runSingleFileUpload(opts, checkSubject, cb) {
		var UploadManager = require('../lib/uploadmgr');
		var um = new UploadManager(Object.assign({useBufferPool: false, servers: []}, opts), function() {});
		var file = {num: 1, name: 'singlefile.mkv', size: 50, collection: 'c1'};
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
		um.addFile(file, 1, {Subject: null}, fakeStream, function(err) {
			assert.ifError(err);
			cb();
		});
	}

	it('sets [1/1] - subject prefix for a single-file encrypted upload', function(done) {
		var cryptoCore = require('../lib/crypto');
		var salt = cryptoCore.generateEncryptionSalt();
		cryptoCore.deriveKeys('test123', salt).then(function(keys) {
			runSingleFileUpload({
				encryption: {
					bodyKey: keys.bodyKey,
					controlKey: keys.controlKey,
					masterKey: keys.masterKey,
					salt: salt,
					controlLines: true
				}
			}, function(headers) {
				assert.match(headers, /Subject: \[1\/1\] - "singlefile\.mkv" yEnc \(1\/1\) 50/,
					'Subject must have [1/1] - prefix when encryption is active: ' + headers);
			}, done);
		}).catch(done);
	});

	it('does not set [1/1] - subject prefix for a single-file unencrypted upload', function(done) {
		runSingleFileUpload({}, function(headers) {
			assert.match(headers, /Subject: "singlefile\.mkv" yEnc \(1\/1\) 50/,
				'unencrypted single file must not have [1/1] - prefix: ' + headers);
		}, done);
	});
});

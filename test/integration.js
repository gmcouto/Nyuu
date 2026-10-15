"use strict";

var assert = require("assert");
var Readable = require('stream').Readable;
var ArticleEncoder = require('../lib/article');
var NZBGenerator = require('../lib/nzb');
var ff1 = require('../lib/ff1');
var cryptoUtil = require('../lib/crypto');
var config = require('../config');
var fileuploader = require('../lib/fileuploader');

// Exercise individual lines through the production block API.
function encryptControlLine(line, key, segmentIndex, lineIndex, salt) {
	var prefix = Buffer.from('=ybegin name=test\r\n' + '\r\n'.repeat(Math.max(0, lineIndex - 2)));
	if(lineIndex === 1) prefix = Buffer.alloc(0);
	var block = Buffer.concat([prefix, line, Buffer.from('\r\n')]);
	var wire = ff1.encryptControlLines(block, key, segmentIndex, salt);
	return wire.subarray(wire.length - line.length - (lineIndex === 1 ? 20 : 0) - 2, wire.length - 2);
}

// In-memory transport sink: replaces only the final network queue
// (`lib/uploader`). fileuploader, UploadManager, stream readers, the
// segment-index allocator, article encoder, KDF and AEAD remain production
// code. No socket is opened.
function makeOfflineSink(captures) {
	function OfflineSink(opts, cb) { this.done = cb; }
	OfflineSink.prototype.addPost = function(post, readCb, postedCb) {
		captures.push({
			salt: post.parent.encryption ? Buffer.from(post.parent.encryption.salt) : null,
			key: post.parent.encryption ? Buffer.from(post.parent.encryption.key) : null,
			index: post.segmentIndex,
			ciphertext: post.encryptionResult ? Buffer.from(post.encryptionResult.ciphertext) : null,
			tag: post.encryptionResult ? Buffer.from(post.encryptionResult.tag) : null,
			data: Buffer.from(post.data)
		});
		postedCb(null);
		readCb(null);
	};
	OfflineSink.prototype.finished = function() { this.done(null); };
	OfflineSink.prototype.cancel = function(err) { this.done(err); };
	OfflineSink.setLogger = function() {};
	return OfflineSink;
}

// Installs a fresh OfflineSink as `lib/uploader` for the current test.
// `lib/uploadmgr` captures the Uploader constructor when it is first
// loaded, so the fileuploader -> uploadmgr -> uploader chain is
// re-required with the sink already in place. Returns a cleanup function
// that restores the original module entries.
function installOfflineSink(captures) {
	var paths = [
		require.resolve('../lib/fileuploader'),
		require.resolve('../lib/uploadmgr'),
		require.resolve('../lib/uploader')
	];
	var saved = paths.map(function(p) { return require.cache[p]; });
	var uploaderPath = require.resolve('../lib/uploader');
	paths.forEach(function(p) { delete require.cache[p]; });
	require.cache[uploaderPath] = {
		id: uploaderPath,
		filename: uploaderPath,
		loaded: true,
		exports: makeOfflineSink(captures)
	};
	fileuploader = require('../lib/fileuploader');
	return function() {
		paths.forEach(function(p, i) {
			if(saved[i]) require.cache[p] = saved[i];
			else delete require.cache[p];
		});
		fileuploader = require('../lib/fileuploader');
	};
}

// Writable stream sink that captures the emitted NZB XML.
function makeXmlCapture(capturesOut) {
	var chunks = [];
	capturesOut.push(chunks);
	return {
		writable: true,
		write: function(c) { chunks.push(Buffer.from(c)); return true; },
		end: function(cb) { if(cb) cb(); }
	};
}

function makeStream(name, text) {
	return [{name: name, size: text.length, stream: Readable.from([Buffer.from(text)])}];
}

function baseOpts(over) {
	return Object.assign({}, config, {
		encryptionEnabled: true,
		encryptionPassword: 'test123',
		useBufferPool: false,
		check: {},
		articleSize: 32,
		diskBufferSize: 1,
		postHeaders: {From: 'test@example.test', Newsgroups: 'alt.test'}
	}, over);
}

function startUpload(files, opts) {
	return new Promise(function(resolve, reject) {
		fileuploader.upload(files, opts, function(err) {
			if(err) reject(err); else resolve();
		});
	});
}

describe('Encrypted upload pipeline', function() {
	var cleanup = null;
	afterEach(function() {
		if(cleanup) {
			cleanup();
			cleanup = null;
		}
	});

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

	it('sets encryption metadata when opts.nzb is a factory function', function() {
		var captures = [];
		cleanup = installOfflineSink(captures);
		var xmlOutputs = [];
		var createdNzbOpts = null;
		var nzbFactory = function() {
			createdNzbOpts = {
				writeTo: function() { return makeXmlCapture(xmlOutputs); },
				metaData: {}
			};
			return ['custom_nzb', createdNzbOpts];
		};
		var opts = baseOpts({
			encryptionEnabled: true,
			encryptionPassword: 'secretpassword',
			nzb: nzbFactory
		});
		return startUpload(makeStream('file.bin', 'hello'), opts).then(function() {
			// caller factory identity is unchanged
			assert.strictEqual(opts.nzb, nzbFactory);
			// caller factory metadata is not mutated
			assert.deepStrictEqual(createdNzbOpts.metaData, {});
			assert.strictEqual(opts.encryption, undefined);
			// emitted NZB XML has the required metadata
			assert.equal(xmlOutputs.length, 1);
			var xml = Buffer.concat(xmlOutputs[0]).toString('utf8');
			assert.match(xml, /<meta type="yenc_encrypted">true<\/meta>/);
			assert.match(xml, /<meta type="password">secretpassword<\/meta>/);
		});
	});

	it('overrides a user-supplied false yenc_encrypted marker when encryption is enabled', function() {
		var captures = [];
		cleanup = installOfflineSink(captures);
		var xmlOutputs = [];
		var callerMeta = {
			yenc_encrypted: 'false'
		};
		var opts = baseOpts({
			encryptionEnabled: true,
			encryptionPassword: 'secretpassword',
			nzb: {
				writeTo: function() { return makeXmlCapture(xmlOutputs); },
				metaData: callerMeta
			}
		});
		return startUpload(makeStream('file.bin', 'hello'), opts).then(function() {
			// caller's metaData must not be mutated
			assert.equal(callerMeta.yenc_encrypted, 'false');
			assert.strictEqual(opts.encryption, undefined);
			// emitted NZB XML carries the authoritative marker and password
			assert.equal(xmlOutputs.length, 1);
			var xml = Buffer.concat(xmlOutputs[0]).toString('utf8');
			assert.match(xml, /<meta type="yenc_encrypted">true<\/meta>/);
			assert.ok(xml.indexOf('yenc_encrypted">false') < 0, 'contradictory false marker must not appear');
			assert.equal(xml.match(/yenc_encrypted/g).length, 1);
			assert.match(xml, /<meta type="password">secretpassword<\/meta>/);
		});
	});

	it('encryption password overwrites archive password without error when both are set', function() {
		var captures = [];
		cleanup = installOfflineSink(captures);
		var xmlOutputs = [];
		var callerMeta = {
			password: 'archive-pw'
		};
		var opts = baseOpts({
			encryptionEnabled: true,
			encryptionPassword: 'transport-pw',
			nzb: {
				writeTo: function() { return makeXmlCapture(xmlOutputs); },
				metaData: callerMeta
			}
		});
		return startUpload(makeStream('file.bin', 'hello'), opts).then(function() {
			// caller's metaData must not be mutated
			assert.equal(callerMeta.password, 'archive-pw');
			assert.equal(callerMeta.yenc_encrypted, undefined);
			assert.strictEqual(opts.encryption, undefined);
			// emitted NZB XML: encryption password is authoritative
			assert.equal(xmlOutputs.length, 1);
			var xml = Buffer.concat(xmlOutputs[0]).toString('utf8');
			assert.match(xml, /<meta type="yenc_encrypted">true<\/meta>/);
			assert.match(xml, /<meta type="password">transport-pw<\/meta>/);
			assert.ok(xml.indexOf('archive-pw') < 0, 'archive password must not appear in generated XML');
			assert.equal(xml.match(/<meta type="password">/g).length, 1);
		});
	});

	describe('encrypted upload state isolation', function() {
		this.timeout(30000);

		it('reused caller options produce distinct salts and derived nonces, each starting at index 1', function() {
			var captures = [];
			cleanup = installOfflineSink(captures);
			var opts = baseOpts();
			return startUpload(makeStream('same.bin', 'AAAAA'), opts).then(function() {
				return startUpload(makeStream('same.bin', 'BBBBB'), opts);
			}).then(function() {
				assert.equal(captures.length, 2);
				// each invocation starts its own upload session at index 1
				assert.equal(captures[0].index, 1);
				assert.equal(captures[1].index, 1);
				// fresh random per-upload salt for each invocation
				assert.ok(!captures[0].salt.equals(captures[1].salt), 'salts must differ across uploads');
				// keys must differ (derived from distinct salts)
				assert.ok(!captures[0].key.equals(captures[1].key), 'derived keys must differ across uploads');
				// derived body nonces must differ (nonce = HMAC(key, segmentIndex);
				// a fresh salt/key at the same index must yield a different nonce)
				var nonce0 = cryptoUtil.deriveBodyNonce(captures[0].key, captures[0].index);
				var nonce1 = cryptoUtil.deriveBodyNonce(captures[1].key, captures[1].index);
				assert.ok(!nonce0.equals(nonce1), 'derived nonces must differ across uploads');
				// ciphertext XOR does not reveal plaintext XOR
				var xor = Buffer.alloc(5);
				for(var i = 0; i < 5; i++) xor[i] = captures[0].ciphertext[i] ^ captures[1].ciphertext[i];
				var plainXor = Buffer.alloc(5, 'A'.charCodeAt(0) ^ 'B'.charCodeAt(0));
				assert.ok(!xor.equals(plainXor), 'ciphertext XOR must not reveal plaintext XOR');
				// caller's options object must not be mutated with invocation-owned
				// encryption state
				assert.strictEqual(opts.encryption, undefined);
			});
		});

		it('reused caller options with a changed second password authenticate with that password', function() {
			var captures = [];
			cleanup = installOfflineSink(captures);
			var opts = baseOpts();
			var xchacha20poly1305 = require('@noble/ciphers/chacha').xchacha20poly1305;
			return startUpload(makeStream('same.bin', 'AAAAA'), opts).then(function() {
				opts.encryptionPassword = 'second-password';
				return startUpload(makeStream('same.bin', 'BBBBB'), opts);
			}).then(function() {
				assert.equal(captures.length, 2);
				assert.ok(!captures[0].key.equals(captures[1].key), 'changed password must derive a new key');
				// the second upload's ciphertext must authenticate and decrypt with
				// the NEW password
				var aad = cryptoUtil.buildBodyAad(1, 1, 5, Buffer.from('same.bin', 'utf8'));
				var sealed = Buffer.concat([captures[1].ciphertext, captures[1].tag]);
				var nonce = cryptoUtil.deriveBodyNonce(captures[1].key, captures[1].index);
				var plain = Buffer.from(xchacha20poly1305(captures[1].key, nonce, aad).decrypt(sealed));
				assert.equal(plain.toString(), 'BBBBB');
				// the OLD password's key must fail authentication on the new upload
				return cryptoUtil.deriveKey('test123', captures[1].salt).then(function(oldKey) {
					var oldNonce = cryptoUtil.deriveBodyNonce(oldKey, captures[1].index);
					assert.throws(function() {
						xchacha20poly1305(oldKey, oldNonce, aad).decrypt(sealed);
					}, 'old password must not authenticate the second upload');
				});
			});
		});

		it('reused caller options with encryption disabled on second call emits ordinary output with no generated marker', function() {
			var captures = [];
			cleanup = installOfflineSink(captures);
			var xmlOutputs = [];
			var opts = baseOpts({
				nzb: {
					writeTo: function() { return makeXmlCapture(xmlOutputs); },
					metaData: {}
				}
			});
			return startUpload(makeStream('same.bin', 'AAAAA'), opts).then(function() {
				assert.equal(captures.length, 1);
				assert.ok(captures[0].salt, 'first upload must be encrypted');
				opts.encryptionEnabled = false;
				return startUpload(makeStream('same.bin', 'BBBBB'), opts);
			}).then(function() {
				assert.equal(captures.length, 2, 'second upload must complete');
				assert.strictEqual(captures[1].salt, null, 'second upload must not encrypt');
				// ordinary yEnc output, no encryption
				var body2 = captures[1].data.toString('ascii');
				assert.ok(body2.indexOf('=ybegin') >= 0, 'ordinary yEnc header present');
				assert.ok(body2.indexOf('name=same.bin') >= 0, 'ordinary name present in =ybegin');
				assert.ok(body2.indexOf('=yencryption') < 0, 'no generated =yencryption marker');
				// the second upload's NZB XML must not carry generated encryption metadata
				assert.equal(xmlOutputs.length, 2);
				var xml2 = Buffer.concat(xmlOutputs[1]).toString('utf8');
				assert.ok(xml2.indexOf('yenc_encrypted') < 0, 'disabled-encryption reuse must not emit generated marker');
				assert.ok(xml2.indexOf('<meta type="password">') < 0, 'no generated password meta');
				// while the first upload's XML DID carry it
				var xml1 = Buffer.concat(xmlOutputs[0]).toString('utf8');
				assert.match(xml1, /<meta type="yenc_encrypted">true<\/meta>/);
				assert.match(xml1, /<meta type="password">test123<\/meta>/);
			});
		});

		it('object-form nzb config: caller object and metaData are not mutated; generated XML carries metadata', function() {
			var captures = [];
			cleanup = installOfflineSink(captures);
			var xmlOutputs = [];
			var callerMeta = {custom: 'value'};
			var callerNzb = {
				writeTo: function() { return makeXmlCapture(xmlOutputs); },
				metaData: callerMeta
			};
			var opts = baseOpts({nzb: callerNzb});
			return startUpload(makeStream('same.bin', 'AAAAA'), opts).then(function() {
				assert.equal(captures.length, 1);
				// caller's object identity and contents untouched
				assert.strictEqual(opts.nzb, callerNzb);
				assert.strictEqual(opts.nzb.metaData, callerMeta);
				assert.equal(callerMeta.yenc_encrypted, undefined);
				assert.equal(callerMeta.password, undefined);
				// generated XML carries the metadata
				var xml = Buffer.concat(xmlOutputs[0]).toString('utf8');
				assert.match(xml, /<meta type="custom">value<\/meta>/);
				assert.match(xml, /<meta type="yenc_encrypted">true<\/meta>/);
				assert.match(xml, /<meta type="password">test123<\/meta>/);
			});
		});

		it('factory-form nzb: caller factory and its returned identity/metadata are unchanged; generated XML carries metadata', function() {
			var captures = [];
			cleanup = installOfflineSink(captures);
			var xmlOutputs = [];
			var factoryCalls = 0;
			var factoryReturned = null;
			var factoryNzb = function() {
				factoryCalls++;
				factoryReturned = ['nzb-id-' + factoryCalls, {
					writeTo: function() { return makeXmlCapture(xmlOutputs); },
					metaData: {custom: 'value'}
				}];
				return factoryReturned;
			};
			var opts = baseOpts({nzb: factoryNzb});
			return startUpload(makeStream('same.bin', 'AAAAA'), opts).then(function() {
				assert.equal(captures.length, 1);
				// caller's factory function identity unchanged
				assert.strictEqual(opts.nzb, factoryNzb);
				assert.equal(factoryCalls, 1);
				// caller's returned object must not be mutated: re-invoke the
				// factory and verify the fresh metaData has no generated fields
				var fresh = factoryNzb();
				assert.strictEqual(fresh, factoryReturned);
				assert.equal(fresh[1].metaData.yenc_encrypted, undefined);
				assert.equal(fresh[1].metaData.password, undefined);
				// generated XML carries the metadata
				var xml = Buffer.concat(xmlOutputs[0]).toString('utf8');
				assert.match(xml, /<meta type="custom">value<\/meta>/);
				assert.match(xml, /<meta type="yenc_encrypted">true<\/meta>/);
				assert.match(xml, /<meta type="password">test123<\/meta>/);
			});
		});

		it('preserves caller-supplied low-level encryption context unchanged', function() {
			var captures = [];
			cleanup = installOfflineSink(captures);
			var suppliedKey = Buffer.alloc(32, 9);
			var suppliedSalt = cryptoUtil.generateEncryptionSalt();
			var suppliedContext = {
				key: suppliedKey,
				salt: suppliedSalt
			};
			var opts = baseOpts({
				encryption: suppliedContext
			});
			return startUpload(makeStream('same.bin', 'AAAAA'), opts).then(function() {
				assert.equal(captures.length, 1);
				// the supplied key and salt were used directly
				assert.ok(captures[0].key.equals(suppliedKey));
				assert.ok(captures[0].salt.equals(suppliedSalt));
				// caller's supplied object reference is preserved
				assert.strictEqual(opts.encryption, suppliedContext);
			});
		});

		it('emitted encryption password is authoritative over an emitted archive password', function() {
			var captures = [];
			cleanup = installOfflineSink(captures);
			var xmlOutputs = [];
			var opts = baseOpts({
				encryptionPassword: 'transport-pw',
				nzb: {
					writeTo: function() { return makeXmlCapture(xmlOutputs); },
					metaData: {password: 'archive-pw'}
				}
			});
			return startUpload(makeStream('same.bin', 'AAAAA'), opts).then(function() {
				assert.equal(captures.length, 1);
				// caller's metaData untouched
				assert.equal(opts.nzb.metaData.password, 'archive-pw');
				// generated XML: the transport password wins
				var xml = Buffer.concat(xmlOutputs[0]).toString('utf8');
				assert.match(xml, /<meta type="password">transport-pw<\/meta>/);
				assert.ok(xml.indexOf('archive-pw') < 0, 'archive password must not appear in emitted XML');
				assert.equal(xml.match(/<meta type="password">/g).length, 1);
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

		var NNTPServer = require('./_nntpsrv');
		var rawPostPath;

		before(function() {
			tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nyuu-test-'));
			notty = path.join(tmpDir, 'notty.json');
			fs.writeFileSync(notty, JSON.stringify({colorize: false}));
			rawPostPath = path.join(tmpDir, 'rawpost.bin');
			fs.writeFileSync(rawPostPath, 'Message-ID: <test@msg.id>\r\nSubject: test\r\nFrom: test\r\nNewsgroups: rifles\r\n\r\n=ybegin line=128 size=4 name=test\r\ntest\r\n=yend size=4\r\n.\r\n');
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

		it('implicitly enables encryption when only --encrypt-password is provided', function(done) {
			child_process.execFile(process.execPath, [binNyuu, '-C', notty, '--encrypt-password', 'secret'], function(err, stdout, stderr) {
				assert.doesNotMatch(stderr, /--encrypt-password.*required/);
				assert.match(stderr, /Must supply at least one input file/);
				done();
			});
		});

		// helper: spins up a local NNTP listener and returns {server, port}
		// tracking inbound connections; used to prove raw+encryption rejections
		// happen before any network activity.
		var makeListeningServer = function(cb) {
			var connections = 0;
			var server = new NNTPServer();
			server.onConnect(function() {
				connections++;
			});
			server.listen(0, function() {
				cb(null, server, server.address().port, function() { return connections; });
			});
		};

		it('rejects --input-raw-posts with --encrypt-password before any connection (NY-NEXT-2)', function(done) {
			makeListeningServer(function(err, server, port, getConnections) {
				if(err) return done(err);
				child_process.execFile(process.execPath, [binNyuu, '-C', notty, '-h', '127.0.0.1', '-P', port, '--input-raw-posts', '--encrypt-password', 'secret', rawPostPath], function(err2, stdout, stderr) {
					server.close(function() {
						assert.ok(err2, 'should fail with non-zero exit code');
						assert.match(stderr, /Encryption is not supported with `--input-raw-posts`/i, 'early diagnostic expected, got: ' + stderr);
						assert.strictEqual(getConnections(), 0, 'zero connection attempts expected');
						done();
					});
				});
			});
		});

		it('rejects --input-raw-posts with --encrypt before any connection (NY-NEXT-2)', function(done) {
			makeListeningServer(function(err, server, port, getConnections) {
				if(err) return done(err);
				child_process.execFile(process.execPath, [binNyuu, '-C', notty, '-h', '127.0.0.1', '-P', port, '--input-raw-posts', '--encrypt', '--encrypt-password', 'secret', rawPostPath], function(err2, stdout, stderr) {
					server.close(function() {
						assert.ok(err2, 'should fail with non-zero exit code');
						assert.match(stderr, /Encryption is not supported with `--input-raw-posts`/i, 'early diagnostic expected, got: ' + stderr);
						assert.strictEqual(getConnections(), 0, 'zero connection attempts expected');
						done();
					});
				});
			});
		});

		it('rejects config-enabled encryption with --input-raw-posts before any connection (NY-NEXT-2)', function(done) {
			makeListeningServer(function(err, server, port, getConnections) {
				if(err) return done(err);
				var cfgPath = path.join(tmpDir, 'raw-enc-config.json');
				fs.writeFileSync(cfgPath, JSON.stringify({
					colorize: false,
					'encrypt-password': 'secret'
				}));
				child_process.execFile(process.execPath, [binNyuu, '-C', cfgPath, '-h', '127.0.0.1', '-P', port, '--input-raw-posts', rawPostPath], function(err2, stdout, stderr) {
					server.close(function() {
						fs.unlinkSync(cfgPath);
						assert.ok(err2, 'should fail with non-zero exit code');
						assert.match(stderr, /Encryption is not supported with `--input-raw-posts`/i, 'early diagnostic expected, got: ' + stderr);
						assert.strictEqual(getConnections(), 0, 'zero connection attempts expected');
						done();
					});
				});
			});
		});

		it('explicit --no-encrypt overrides config-enabled encryption for --input-raw-posts', function(done) {
			makeListeningServer(function(err, server, port, getConnections) {
				if(err) return done(err);
				var cfgPath = path.join(tmpDir, 'raw-enc-config.json');
				fs.writeFileSync(cfgPath, JSON.stringify({
					colorize: false,
					'encrypt-password': 'secret'
				}));
				child_process.execFile(process.execPath, [binNyuu, '-C', cfgPath, '-h', '127.0.0.1', '-P', port, '--input-raw-posts', '--no-encrypt', rawPostPath], function(err2, stdout, stderr) {
					server.close(function() {
						fs.unlinkSync(cfgPath);
						assert.ifError(err2);
						assert.doesNotMatch(stderr, /Encryption is not supported with `--input-raw-posts`/i);
						assert.ok(getConnections() > 0, 'expected actual connection attempts in pass-through raw mode');
						done();
					});
				});
			});
		});

		it('already-encrypted raw input repost without encryption flags remains pass-through', function(done) {
			makeListeningServer(function(err, server, port, getConnections) {
				if(err) return done(err);
				child_process.execFile(process.execPath, [binNyuu, '-C', notty, '-h', '127.0.0.1', '-P', port, '--input-raw-posts', rawPostPath], function(err2, stdout, stderr) {
					server.close(function() {
						assert.ifError(err2);
						assert.doesNotMatch(stderr, /Encryption is not supported with `--input-raw-posts`/i);
						assert.ok(getConnections() > 0, 'expected actual connection attempts in pass-through raw mode');
						done();
					});
				});
			});
		});
	});
});

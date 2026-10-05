"use strict";

var assert = require("assert");
var ArticleEncoder = require('../lib/article');
var NZBGenerator = require('../lib/nzb');

describe('Encrypted upload pipeline', function() {
	it('keeps segment identity and encryption metadata aligned', function() {
		var output = [];
		var nzb = new NZBGenerator({yenc_encrypted: 'true', password: 'test123'}, function(value, encoding) {
			output.push(Buffer.from(value, encoding));
		}, true, 'utf8');
		var encoder = new ArticleEncoder('file.bin', 5, 5, null, {
			encryption: {
				bodyKey: Buffer.alloc(32, 7),
				masterKey: Buffer.alloc(32, 7),
				salt: Buffer.from('0102030405060708090b0c0e0f101112', 'hex'),
				controlLines: false,
				segmentIndex: 1
			}
		});
		encoder.setHeaders({}, '', '');
		var post = encoder.generate(Buffer.from('hello'));
		nzb.file('file.bin (1/1)', 'poster', ['alt.test'], 1);
		nzb.addSegment(post.postLen, 'article@example.com', post.segmentIndex);
		nzb.end();
		var wire = post.data.toString('ascii');
		var xml = Buffer.concat(output).toString('utf8');
		assert.match(wire, /=yencryption cipher=XChaCha20-Poly1305 salt=[0-9a-f]{32} tag=[0-9a-f]{32}/);
		assert.doesNotMatch(wire, /hello/);
		assert.match(xml, /meta type="yenc_encrypted">true/);
		assert.match(xml, /meta type="password">test123/);
		assert.match(xml, /segmentIndex="1"/);
	});

	it('propagates encryption metadata to tokenized function opts.nzb outputs', function(done) {
		var FileUploader = require('../lib/fileuploader');
		var UploadManager = require('../lib/uploadmgr');
		var nzbOpts = { metaData: {}, overrides: {}, writeTo: function() {} };
		var nzbFn = function(fileNum, totalFiles, name) {
			var opts = { writeTo: nzbOpts.writeTo };
			for(var k in nzbOpts) opts[k] = nzbOpts[k];
			return [name + '.nzb', opts];
		};

		var uploaderOpts = {
			encryptionPassword: 'SecretPassword123',
			encryptionEnabled: true,
			nzb: nzbFn,
			servers: []
		};

		FileUploader.upload([], uploaderOpts, function() {});
		var mgr = new UploadManager(uploaderOpts, function() {});
		mgr.setupNzbs({ test: { num: 1, name: 'test.bin', size: 10, collection: 'c1' } }, { c1: 1 });
		assert.ok(mgr.nzbs['test.bin.nzb']);
		assert.equal(mgr.nzbs['test.bin.nzb'].create.metaData.yenc_encrypted, 'true');
		assert.equal(mgr.nzbs['test.bin.nzb'].create.metaData.password, 'SecretPassword123');
		done();
	});

	it('completes full end-to-end encrypted upload via FileUploader and in-process NNTP server (GAP-33-01)', function(done) {
		this.timeout(10000);
		var path = require('path');
		var Writable = require('stream').Writable;
		var NNTPServer = require('./_nntpsrv');
		var FileUploader = require('../lib/fileuploader');
		var deepMerge = require('../lib/util').deepMerge;

		var server = new NNTPServer({});
		server.listen(0, function() {
			var port = server.address().port;
			var nzbChunks = [];
			var nzbStream = new Writable({
				write: function(chunk, encoding, cb) {
					nzbChunks.push(Buffer.from(chunk));
					cb();
				}
			});

			var clientOpts = {
				server: {
					connect: { host: '127.0.0.1', port: port, highWaterMark: 0, rejectUnauthorized: false },
					secure: false, user: 'test', password: 'pwd',
					timeout: 2000, connTimeout: 2000, postTimeout: 2000,
					postConnections: 1, checkConnections: 0
				},
				check: { delay: 10, recheckDelay: 10, tries: 0, postRetries: 0 },
				articleSize: 768000,
				subdirs: 'keep',
				subdirNameTransform: function(f) { return f; },
				fileNameTransform: function(f) { return path.basename(f); },
				postHeaders: {
					Subject: null,
					From: 'Nyuu <nyuu@example.com>',
					Newsgroups: 'rifles',
					Date: (new Date()).toISOString()
				},
				nzb: {
					writeTo: function() { return nzbStream; },
					writeOpts: { flags: 'w', encoding: 'utf8' },
					minify: false,
					compression: '',
					metaData: { client: 'Nyuu' }
				},
				encryptionEnabled: true,
				encryptionPassword: 'E2E_Test_Password'
			};

			var mergedOpts = {};
			deepMerge(mergedOpts, require('../config'));
			deepMerge(mergedOpts, clientOpts);
			mergedOpts.servers = [mergedOpts.server];

			var filePath = path.join(__dirname, '10bytes.txt');
			FileUploader.upload([filePath], mergedOpts, function(err) {
				server.close(function() {
					assert.ifError(err);
					assert.equal(Object.keys(server.posts.rifles).length, 1);
					var post = server.posts.rifles[0];
					var body = post._msg;
					assert.ok(body.length > 0);
					var bodyStr = body.toString('binary');
					assert.ok(bodyStr.indexOf('=ybegin') < 0, 'Plaintext =ybegin should not be present');
					var nzbXml = Buffer.concat(nzbChunks).toString('utf8');
					assert.match(nzbXml, /<meta type="yenc_encrypted">true<\/meta>/);
					assert.match(nzbXml, /<meta type="password">E2E_Test_Password<\/meta>/);
					assert.match(nzbXml, /segmentIndex="1"/);
					done();
				});
			});
		});
	});

	it('allocates contiguous 1-based segmentIndex across multi-file and multipart uploads (GAP-33-03)', function(done) {
		this.timeout(10000);
		var path = require('path');
		var Writable = require('stream').Writable;
		var NNTPServer = require('./_nntpsrv');
		var FileUploader = require('../lib/fileuploader');
		var deepMerge = require('../lib/util').deepMerge;

		var server = new NNTPServer({});
		server.listen(0, function() {
			var port = server.address().port;
			var nzbChunks = [];
			var nzbStream = new Writable({
				write: function(chunk, encoding, cb) {
					nzbChunks.push(Buffer.from(chunk));
					cb();
				}
			});

			var clientOpts = {
				server: {
					connect: { host: '127.0.0.1', port: port, highWaterMark: 0, rejectUnauthorized: false },
					secure: false, user: 'test', password: 'pwd',
					timeout: 2000, connTimeout: 2000, postTimeout: 2000,
					postConnections: 1, checkConnections: 0
				},
				check: { delay: 10, recheckDelay: 10, tries: 0, postRetries: 0 },
				articleSize: 50, // 10bytes.txt (10B) -> 1 part; dummypost.bin (100B) -> 2 parts. Total = 3 parts
				subdirs: 'keep',
				subdirNameTransform: function(f) { return f; },
				fileNameTransform: function(f) { return path.basename(f); },
				postHeaders: {
					Subject: null,
					From: 'Nyuu <nyuu@example.com>',
					Newsgroups: 'rifles',
					Date: (new Date()).toISOString()
				},
				nzb: {
					writeTo: function() { return nzbStream; },
					writeOpts: { flags: 'w', encoding: 'utf8' },
					minify: false,
					compression: '',
					metaData: { client: 'Nyuu' }
				},
				encryptionEnabled: true,
				encryptionPassword: 'ContiguousIndexPassword'
			};

			var mergedOpts = {};
			deepMerge(mergedOpts, require('../config'));
			deepMerge(mergedOpts, clientOpts);
			mergedOpts.servers = [mergedOpts.server];

			var files = [path.join(__dirname, '10bytes.txt'), path.join(__dirname, 'dummypost.bin')];
			FileUploader.upload(files, mergedOpts, function(err) {
				server.close(function() {
					assert.ifError(err);
					assert.equal(server.posts.rifles.length, 3);
					var nzbXml = Buffer.concat(nzbChunks).toString('utf8');
					assert.match(nzbXml, /segmentIndex="1"/);
					assert.match(nzbXml, /segmentIndex="2"/);
					assert.match(nzbXml, /segmentIndex="3"/);
					assert.doesNotMatch(nzbXml, /segmentIndex="0"/);
					assert.doesNotMatch(nzbXml, /segmentIndex="4"/);
					done();
				});
			});
		});
	});

	it('re-encrypts and reposts with preserved segmentIndex and salt on check-missing repost (GAP-33-05)', function(done) {
		this.timeout(10000);
		var path = require('path');
		var Writable = require('stream').Writable;
		var NNTPServer = require('./_nntpsrv');
		var FileUploader = require('../lib/fileuploader');
		var deepMerge = require('../lib/util').deepMerge;

		var server = new NNTPServer({});
		var droppedPost = null;
		server.onPostHook = function(post) {
			droppedPost = post;
			return true; // drop first post to simulate missing post on NNTP server
		};

		server.listen(0, function() {
			var port = server.address().port;
			var nzbStream = new Writable({
				write: function(chunk, encoding, cb) { cb(); }
			});

			var clientOpts = {
				server: {
					connect: { host: '127.0.0.1', port: port, highWaterMark: 0, rejectUnauthorized: false },
					secure: false, user: 'test', password: 'pwd',
					timeout: 2000, connTimeout: 2000, postTimeout: 2000,
					postConnections: 1, checkConnections: 1
				},
				check: {
					delay: 10,
					recheckDelay: 10,
					tries: 1,
					postRetries: 1,
					queueCache: 0 // force reload from disk
				},
				articleSize: 768000,
				subdirs: 'keep',
				subdirNameTransform: function(f) { return f; },
				fileNameTransform: function(f) { return path.basename(f); },
				postHeaders: {
					Subject: null,
					From: 'Nyuu <nyuu@example.com>',
					Newsgroups: 'rifles',
					Date: (new Date()).toISOString()
				},
				nzb: {
					writeTo: function() { return nzbStream; },
					writeOpts: { flags: 'w', encoding: 'utf8' },
					minify: false,
					compression: '',
					metaData: { client: 'Nyuu' }
				},
				encryptionEnabled: true,
				encryptionPassword: 'RepostTestPassword'
			};

			var mergedOpts = {};
			deepMerge(mergedOpts, require('../config'));
			deepMerge(mergedOpts, clientOpts);
			mergedOpts.servers = [mergedOpts.server];

			var filePath = path.join(__dirname, '10bytes.txt');
			FileUploader.upload([filePath], mergedOpts, function(err) {
				server.close(function() {
					assert.ifError(err);
					assert.ok(droppedPost, 'First post should have been caught and dropped');
					assert.equal(server.posts.rifles.length, 1, 'Server should have received the reposted post');
					var reposted = server.posts.rifles[0];
					assert.notEqual(reposted.messageId, droppedPost.messageId, 'Repost must have fresh randomized Message-ID');
					// Check that salt (first 16 bytes of line 1) is identical
					var droppedBuf = Buffer.from(droppedPost._msg, 'binary');
					var repostedBuf = Buffer.from(reposted._msg, 'binary');
					var droppedSalt = droppedBuf.subarray(0, 16);
					var repostedSalt = repostedBuf.subarray(0, 16);
					assert.equal(droppedSalt.toString('hex'), repostedSalt.toString('hex'), 'Salt must be preserved across repost');
					done();
				});
			});
		});
	});
});

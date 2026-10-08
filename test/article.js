"use strict";

var assert = require("assert");

var MultiEncoder = require('../lib/article');
var BufferPool = require('../lib/bufferpool');
var bufferSlice = Buffer.prototype.readBigInt64BE ? Buffer.prototype.subarray : Buffer.prototype.slice;
var toBuffer = (Buffer.alloc ? Buffer.from : Buffer);

describe('Article', function() {

// TODO: test case of header exceeding line length??

var simpleCheck = function(pool) {
	var a = new MultiEncoder('some\nfile', 6, 3);
	assert.equal(a.filename, 'some\nfile');
	assert.ok(a.line_size);
	
	var s;
	
	a.setHeaders({
		Subject: 'first post!',
		From: function(filename, filesize, part, parts, post) {
			assert.equal(filename, 'some\nfile');
			assert.equal(filesize, 6);
			assert.equal(part, 1);
			assert.equal(parts, 2);
			assert.equal(post.rawSize, 3);
			return 'fromfield';
		}
	});
	var a1Headers = {};
	var a1 = a.generate(toBuffer('abc'), pool, a1Headers);
	assert.equal(a1.part, 1);
	s = a1.data.toString();
	
	var headers = bufferSlice.call(a1.data, 0, a1.postPos).toString();
	
	// first part should not have a crc32 (but may have a pcrc32)
	assert(!s.match(/[^p]crc32=/));
	assert(s.match(/name=somefile/));
	assert.notEqual(headers.indexOf('first post!'), -1);
	assert.equal(a1Headers.subject, 'first post!');
	assert.notEqual(headers.indexOf('fromfield'), -1);
	assert.equal(a1Headers.from, 'fromfield');
	
	// TODO: consider parsing data and checking everything
	
	a.setHeaders({
		'X-Test': '',
		'Message-ID': function(filename, filesize, part, parts, post) {
			assert.equal(filename, 'some\nfile');
			assert.equal(filesize, 6);
			assert.equal(part, 2);
			assert.equal(parts, 2);
			assert.equal(post.rawSize, 3);
			return 'test\u0080msgid';
		},
		missing: function() { return null; }
	});
	var a2Headers = {};
	var a2 = a.generate(toBuffer('def'), pool, a2Headers);
	assert.equal(a2.part, 2);
	s = a2.data.toString();
	headers = bufferSlice.call(a2.data, 0, a2.postPos).toString();
	
	// check a2 has a crc32
	assert.notEqual(s.indexOf('crc32='), -1);
	assert.notEqual(headers.indexOf('X-Test:'), -1);
	assert.equal(a2Headers['x-test'], '');
	assert(!a2Headers.subject); // since we didn't supply one
	assert(!('missing' in a2Headers));
	assert.equal(a2.messageId, 'test.msgid'); // Unicode character should be replaced
	
	assert.equal(a.pos, 6);
	
	// test release+reload
	var oldData = toBuffer(a1.data);
	a1.releaseData();
	a1.reloadData(toBuffer('abc'));
	assert.equal(oldData.toString('hex'), a1.data.toString('hex'));
	
	oldData = toBuffer(a2.data);
	a2.releaseData();
	a2.reloadData(toBuffer('def'));
	assert.equal(oldData.toString('hex'), a2.data.toString('hex'));
};

it('basic unpooled post test', function(done) {
	simpleCheck();
	done();
});
it('basic (small) pooled post test', function(done) {
	simpleCheck(new BufferPool(1));
	done();
});
it('basic (large) pooled post test', function(done) {
	simpleCheck(new BufferPool(4096));
	done();
});

it('encrypts body and control lines before yEnc encoding', function() {
	var key = Buffer.alloc(32, 7);
	var salt = Buffer.from('0102030405060708090b0c0e0f101112', 'hex');
	var a = new MultiEncoder('file', 6, 6, null, {
		encryption: {bodyKey: key, masterKey: key, salt: salt, controlLines: true, segmentIndex: 1}
	});
	a.setHeaders({});
	var post = a.generate(toBuffer('secret'));
	var wire = post.data.toString('binary');
	assert.equal(post.inputLen, 6);
	assert.equal(post.wireLen, post.inputLen);
	assert.equal(post.segmentIndex, 1);
	assert.equal(post.data.subarray(post.postPos, post.postPos + 16).toString('hex'), salt.toString('hex'));
	assert.equal(post.data.subarray(post.postPos + 16, post.postPos + 20).readUInt32BE(0), 1);
	assert.ok(wire.indexOf('=ybegin') < 0);
	assert.ok(wire.indexOf('=yencryption') < 0);
	assert.ok(post.postLen > post.postPos);
});

it('emits canonical 5-token =yencryption line when controlLines is false', function() {
	var key = Buffer.alloc(32, 7);
	var salt = Buffer.from('0102030405060708090b0c0e0f101112', 'hex');
	[null, new BufferPool(4096)].forEach(function(pool) {
		var a = new MultiEncoder('file', 6, 6, null, {
			encryption: {bodyKey: key, masterKey: key, salt: salt, controlLines: false, segmentIndex: 1}
		});
		a.setHeaders({});
		var post = a.generate(toBuffer('secret'), pool);
		var wire = post.data.toString('ascii');
		assert.match(wire, /=yencryption cipher=XChaCha20-Poly1305 salt=[0-9a-f]{32} index=[0-9a-f]{8} tag=[0-9a-f]{32}/);
		var m = wire.match(/=yencryption cipher=XChaCha20-Poly1305 salt=([0-9a-f]{32}) index=([0-9a-f]{8}) tag=([0-9a-f]{32})/);
		assert.equal(m[1], salt.toString('hex'));
		assert.equal(m[2], '00000001');
		assert.equal(m[3], post.encryption.tag.toString('hex'));
	});
});

it('re-encrypts plaintext on reloadData without length mismatch or plaintext leak', function() {
	var key = Buffer.alloc(32, 7);
	var salt = Buffer.from('0102030405060708090b0c0e0f101112', 'hex');
	[true, false].forEach(function(controlLines) {
		[null, new BufferPool(4096)].forEach(function(pool) {
			var a = new MultiEncoder('file', 500, 500, null, {
				encryption: {bodyKey: key, masterKey: key, salt: salt, controlLines: controlLines, segmentIndex: 1}
			});
			a.setHeaders({});
			var plain = Buffer.alloc(500, 0);
			var post = a.generate(plain, pool);
			var oldData = Buffer.from(post.data);
			var oldTag = Buffer.from(post.encryption.tag);
			post.releaseData();
			assert.equal(post.data, null);
			post.reloadData(plain);
			assert.ok(post.data);
			assert.equal(oldData.toString('hex'), post.data.toString('hex'));
			assert.equal(oldTag.toString('hex'), post.encryption.tag.toString('hex'));
		});
	});
});

it('pooled post grows undersized pooled buffer on reloadData instead of silently truncating article', function() {
	var key = Buffer.alloc(32, 7);
	var salt = Buffer.from('0102030405060708090b0c0e0f101112', 'hex');
	// build an oversized post once to learn its exact wire length
	var a = new MultiEncoder('f', 600, 600, null, {
		encryption: {bodyKey: key, masterKey: key, salt: salt, controlLines: false, segmentIndex: 1}
	});
	a.setHeaders({});
	var reference = a.generate(Buffer.alloc(600));
	var expectedLen = reference.postPos + reference.postLen;

	// reload path hands the post a pooled buffer that is smaller than the body:
	// the post must be grown, never silently clipped by Buffer.copy
	var tinyPool = new BufferPool(expectedLen - 100);
	tinyPool.put(Buffer.alloc(expectedLen - 100));
	var a2 = new MultiEncoder('f', 600, 600, null, {
		encryption: {bodyKey: key, masterKey: key, salt: salt, controlLines: false, segmentIndex: 1}
	});
	a2.setHeaders({});
	var post = a2.generate(Buffer.alloc(600), tinyPool);
	var goodData = Buffer.from(post.data);
	post.releaseData();
	// ensure the pool hands back an undersized buffer on reload
	tinyPool.pool = [Buffer.alloc(expectedLen - 100)];
	post.reloadData(Buffer.alloc(600));
	assert.equal(post.data.length, expectedLen);
	assert.equal(post.data.toString('hex'), goodData.toString('hex'));
	// the full body must be intact: final yend terminator present at the very end
	assert(post.data.toString('ascii').endsWith('\r\n.\r\n'));
	// the =yencryption header line is present and atomic (controlLines: false path)
	assert.match(post.data.toString('ascii'), /=yencryption cipher=XChaCha20-Poly1305 salt=[0-9a-f]{32} index=[0-9a-f]{8} tag=[0-9a-f]{32}\r\n/);
});

it('pooled post survives undersized pool buffer with control-line encryption', function() {
	var key = Buffer.alloc(32, 7);
	var salt = Buffer.from('0102030405060708090b0c0e0f101112', 'hex');
	var a = new MultiEncoder('f', 600, 600, null, {
		encryption: {bodyKey: key, masterKey: key, salt: salt, controlLines: true, segmentIndex: 1}
	});
	a.setHeaders({});
	var reference = a.generate(Buffer.alloc(600));
	var expectedLen = reference.postPos + reference.postLen;

	var tinyPool = new BufferPool(expectedLen - 100);
	tinyPool.put(Buffer.alloc(expectedLen - 100));
	var a2 = new MultiEncoder('f', 600, 600, null, {
		encryption: {bodyKey: key, masterKey: key, salt: salt, controlLines: true, segmentIndex: 1}
	});
	a2.setHeaders({});
	var post = a2.generate(Buffer.alloc(600), tinyPool);
	assert.equal(post.data.length, expectedLen);
	// Line 1 bootstrap prefix bytes are the FF1-encrypted control line's salt+index, unsplit and intact
	assert.equal(post.data.subarray(post.postPos, post.postPos + 16).toString('hex'), salt.toString('hex'));
	assert.equal(post.data.subarray(post.postPos + 16, post.postPos + 20).readUInt32BE(0), 1);
});

it('failed unpooled reloadData leaves no stale body state for subsequent reloads', function() {
	var a = new MultiEncoder('test.bin', 10, 10);
	a.setHeaders({});
	var p = a.generate(toBuffer('0123456789'));
	var good = toBuffer(p.data);
	p.releaseData();
	assert.equal(p.data, null);
	// a wrong-length reload must throw without corrupting state
	assert.throws(function() {
		p.reloadData(toBuffer('0123456789extra'));
	}, /Article length mismatch encountered/);
	// bufs must not have accumulated a stale encoded body — the prefix is the
	// full header framing (all headers + blank line), not just the Message-ID
	assert.equal(p.bufs.length, p._headerBufs.length);
	assert.equal(p.bufs[p.bufs.length - 1].toString(), '\r\n');
	// a correct reload must then produce the byte-identical original article
	p.reloadData(toBuffer('0123456789'));
	assert.equal(p.data.toString('hex'), good.toString('hex'));
});

it('unpooled releaseData is idempotent across multiple calls', function() {
	var a = new MultiEncoder('test.bin', 10, 10);
	a.setHeaders({Subject: 'test sub', From: 'test@example.com'});
	var p = a.generate(toBuffer('0123456789'));
	var origHeaderLen = p._headerBufs.length;
	p.releaseData();
	assert.equal(p.data, null);
	assert.equal(p.bufs.length, origHeaderLen);
	p.releaseData();
	assert.equal(p.data, null);
	assert.equal(p.bufs.length, origHeaderLen);
	p.reloadData(toBuffer('0123456789'));
	assert.notEqual(p.data, null);
	assert.notEqual(p.data.toString().indexOf('Subject: test sub'), -1);
});

it('unpooled getHeader and stripHeader work after releaseData', function() {
	var a = new MultiEncoder('test.bin', 10, 10);
	a.setHeaders({Subject: 'my-subject', 'X-Custom': 'custom-val'});
	var p = a.generate(toBuffer('0123456789'));
	p.releaseData();
	assert.equal(p.getHeader('subject'), 'my-subject');
	assert.equal(p.getHeader('x-custom'), 'custom-val');
	assert.equal(p.stripHeader('nonexistent'), false);
	assert.equal(p.stripHeader('x-custom'), true);
	assert.equal(p.getHeader('x-custom'), false);
	p.reloadData(toBuffer('0123456789'));
	assert.equal(p.data.toString().indexOf('X-Custom'), -1);
	assert.notEqual(p.data.toString().indexOf('Subject: my-subject'), -1);
});

it('randomizeMessageID updates _headerBufs so reloadData does not revert message ID', function() {
	var a = new MultiEncoder('test.bin', 10, 10);
	a.setHeaders({Subject: 'id test'});
	var p = a.generate(toBuffer('0123456789'));
	var origId = p.messageId;
	var newId = p.randomizeMessageID();
	assert.notEqual(newId, origId);
	assert.equal(p.messageId, newId);
	p.releaseData();
	p.reloadData(toBuffer('0123456789'));
	assert.equal(p.messageId, newId);
	assert.notEqual(p.data.toString().indexOf('Message-ID: <' + newId + '>'), -1);
	assert.equal(p.data.toString().indexOf('Message-ID: <' + origId + '>'), -1);
});

it('PooledPost should synchronize _headerStr on randomizeMessageID and stripHeader after releaseData', function() {
	var a = new MultiEncoder('testfile', 6, 6);
	a.setHeaders({
		Subject: 'Test Subject',
		From: 'poster@example.com',
		'X-Removable': 'remove-me'
	});
	var pool = new BufferPool(4096, 2);
	var input = toBuffer('abcdef');
	var p = a.generate(input, pool);
	var origId = p.messageId;

	// Release data buffer to trigger _headerStr caching
	p.releaseData();
	assert.equal(p.data, null);
	assert.ok(p._headerStr);
	assert.notEqual(p._headerStr.indexOf('X-Removable: remove-me'), -1);

	// Randomize message ID while released
	var newId = p.randomizeMessageID();
	assert.notEqual(newId, origId);
	assert.notEqual(p._headerStr.indexOf('Message-ID: <' + newId + '>'), -1);
	assert.equal(p._headerStr.indexOf('Message-ID: <' + origId + '>'), -1);

	// Strip header while released
	assert.ok(p.stripHeader('X-Removable'));
	assert.equal(p._headerStr.indexOf('X-Removable'), -1);

	// Reload data and ensure it succeeds with synchronized header
	p.reloadData(input);
	assert.ok(p.data);
	var postStr = p.data.toString();
	assert.notEqual(postStr.indexOf('Message-ID: <' + newId + '>'), -1);
	assert.equal(postStr.indexOf('Message-ID: <' + origId + '>'), -1);
	assert.equal(postStr.indexOf('X-Removable'), -1);
});

it('empty file test', function(done) {
	var a = new MultiEncoder('file', 0, 1);
	assert.equal(a.parts, 1);
	assert.equal(a.size, 0);
	a.setHeaders({});
	var a1 = a.generate(toBuffer(''));
	
	assert.equal(a1.part, 1);
	assert.equal(a1.inputLen, 0);
	var postData = a1.data.toString();
	assert.notEqual(postData.indexOf(' crc32=00000000'), -1);
	assert.notEqual(postData.indexOf(' pcrc32=00000000'), -1);
	assert.notEqual(postData.indexOf(' size=0 '), -1);
	
	done();
});

it('should throw if sent too many parts', function(done) {
	var a = new MultiEncoder('file', 6, 6);
	a.setHeaders({});
	var a1 = a.generate(toBuffer('aabbcc'));
	
	assert.equal(a1.part, 1);
	assert.notEqual(a1.data.toString().indexOf('crc32='), -1);
	
	assert.throws(function() {
		a.generate(toBuffer('b'));
	}, Error);
	done();
});
it('should throw if sent too much data', function(done) {
	var a = new MultiEncoder('file', 3, 2);
	a.setHeaders({});
	a.generate(toBuffer('aa'));
	assert.throws(function() {
		a.generate(toBuffer('bb'));
	}, Error);
	done();
});
it('should throw if sent data isn\'t expected amount', function(done) {
	var a = new MultiEncoder('file', 5, 3);
	a.setHeaders({});
	a.generate(toBuffer('aa'));
	assert.throws(function() {
		a.generate(toBuffer('bb'));
	}, Error);
	done();
});

// TODO: test Post.* stuff?
// TODO: check message IDs
// TODO: test raw posts

});

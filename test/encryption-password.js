"use strict";

var assert = require('assert');
var path = require('path');

var fileUploader = require('../lib/fileuploader');
var NZBGenerator = require('../lib/nzb');

// Body Std §4 (v1.2): encryption passwords are written into the NZB as
// <meta type="password">, so they must be XML 1.0 representable. Each rejected
// case must fail before key derivation or any NNTP work, so the upload callback
// is reached on the next tick with no server configured.
var MISSING_FILE = path.join(__dirname, 'does-not-exist', 'nope.bin');

function uploadWithPassword(password, cb) {
	fileUploader.upload([MISSING_FILE], {
		encryptionEnabled: true,
		encryptionPassword: password,
		fileNameTransform: function(name) { return name; },
		subdirs: 'skip',
		skipSymlinks: false,
		check: {}
	}, cb);
}

function expectRejected(password, done) {
	var secret = typeof password == 'string' ? password : null;
	uploadWithPassword(password, function(err) {
		try {
			assert(err instanceof Error, 'expected an error');
			assert(/XML 1\.0|UTF-8/.test(err.message), 'unexpected message: ' + err.message);
			if(secret) assert(err.message.indexOf(secret) === -1, 'error echoes the password');
			done();
		} catch(e) {
			done(e);
		}
	});
}

describe('encryption password XML 1.0 representability (NY-1)', function() {
	this.timeout(30000);

	it('rejects U+0001 (control character outside XML 1.0)', function(done) {
		expectRejected('pass\u0001word', done);
	});

	it('rejects U+FFFE (noncharacter outside XML 1.0)', function(done) {
		expectRejected('pass\uFFFEword', done);
	});

	it('rejects a lone high surrogate', function(done) {
		expectRejected('pass\uD83Dword', done);
	});

	it('rejects a lone low surrogate', function(done) {
		expectRejected('pass\uDE00word', done);
	});

	it('rejects a byte password that is not valid UTF-8', function(done) {
		expectRejected(Buffer.from([0x70, 0x61, 0xff, 0x73]), done);
	});

	it('rejects a byte password encoding a surrogate (CESU-style, invalid UTF-8)', function(done) {
		expectRejected(Buffer.from([0x70, 0xed, 0xa0, 0xbd]), done);
	});

	it('accepts an emoji password and proceeds past validation', function(done) {
		// the stat of the missing file fails after key derivation; the failure
		// must not be a password error
		uploadWithPassword('p😀ss', function(err) {
			try {
				assert(err instanceof Error);
				assert(!/XML 1\.0|UTF-8|password/.test(err.message), 'password rejected: ' + err.message);
				done();
			} catch(e) {
				done(e);
			}
		});
	});

	it('accepts a password with &<>"\' and writes it XML-escaped into the NZB meta', function(done) {
		var password = 'a&<>"\'b';
		uploadWithPassword(password, function(err) {
			try {
				assert(err instanceof Error);
				assert(!/XML 1\.0|UTF-8/.test(err.message), 'password rejected: ' + err.message);
			} catch(e) {
				return done(e);
			}
			// the same metaData shape fileuploader injects into the NZB head
			var data = [];
			var nzb = new NZBGenerator({ yenc_encrypted: 'true', password: password }, function(blob) {
				data.push(Buffer.from(blob));
			}, true, 'utf8', true);
			nzb.end();
			var xml = Buffer.concat(data).toString('utf8');
			try {
				assert(xml.indexOf('<meta type="password">a&amp;&lt;&gt;&quot;\'b</meta>') !== -1, xml);
				done();
			} catch(e) {
				done(e);
			}
		});
	});

	// Round 2 (reviewer finding 1): the NZB must parse back to the exact password.
	// Parsing uses Python's expat (a conforming XML 1.0 parser). Node has no built-in
	// XML parser and nyuu has no XML dependency, so the parser runs as a subprocess.
	// The skip only happens when python3 is not installed.
	var PARSE_META_SCRIPT = [
		'import sys, json, xml.etree.ElementTree as ET',
		'root = ET.fromstring(sys.stdin.buffer.read())',
		'out = [e.text or "" for e in root.iter() if e.tag.split("}")[-1] == "meta" and e.get("type") == "password"]',
		'sys.stdout.write(json.dumps(out))'
	].join('\n');

	function encryptedNzbXml(password) {
		var data = [];
		var nzb = new NZBGenerator({ yenc_encrypted: 'true', password: password }, function(blob) {
			data.push(Buffer.from(blob));
		}, true, 'utf8', true);
		nzb.end();
		return Buffer.concat(data);
	}

	function parsePasswordMetas(xmlBuffer) {
		var stdout = require('child_process').execFileSync('python3', ['-I', '-c', PARSE_META_SCRIPT], {
			input: xmlBuffer
		});
		return JSON.parse(stdout.toString('utf8'));
	}

	it('writes a raw CR in the encryption password as &#xD; and parses back exactly', function() {
		var xml = encryptedNzbXml('x\ry').toString('utf8');
		assert(xml.indexOf('<meta type="password">x&#xD;y</meta>') !== -1, xml);
		assert.strictEqual(xml.indexOf('\r'), -1, 'raw CR must not appear in the NZB');
		var parsed;
		try {
			parsed = parsePasswordMetas(encryptedNzbXml('x\ry'));
		} catch(e) {
			if(e.code === 'ENOENT') return this.skip();
			throw e;
		}
		assert.deepStrictEqual(parsed, ['x\ry']);
	});

	it('round-trips LF, TAB, markup characters and CRLF through the NZB meta', function() {
		var passwords = ['x\ny', 'a\tb', 'a&<>"\'b', 'p\r\n\tq', 'p😀ss\uFEFF', '\uFFFD\uE000'];
		var parsed = [];
		try {
			passwords.forEach(function(pw) {
				parsed.push(parsePasswordMetas(encryptedNzbXml(pw))[0]);
			});
		} catch(e) {
			if(e.code === 'ENOENT') return this.skip();
			throw e;
		}
		assert.deepStrictEqual(parsed, passwords);
	});

	it('leaves ordinary (unencrypted) meta CR output unchanged', function() {
		var data = [];
		var nzb = new NZBGenerator({ password: 'archive\rpw' }, function(blob) {
			data.push(Buffer.from(blob));
		}, true, 'utf8');
		nzb.end();
		var xml = Buffer.concat(data).toString('utf8');
		assert(xml.indexOf('<meta type="password">archive\rpw</meta>') !== -1, 'plain meta must not be altered');
	});

	// NY-F4: a user-supplied yenc_encrypted meta without encryption is an ordinary
	// meta; the CR escape follows the explicit `encrypted` flag, not the meta.
	it('writes a manual yenc_encrypted meta without encryption as before (raw CR)', function() {
		var data = [];
		var nzb = new NZBGenerator({ yenc_encrypted: 'true', password: 'a\rb' }, function(blob) {
			data.push(Buffer.from(blob));
		}, true, 'utf8');
		nzb.end();
		var xml = Buffer.concat(data).toString('utf8');
		assert(xml.indexOf('<meta type="password">a\rb</meta>') !== -1, 'raw CR must be kept without encryption');
		assert.strictEqual(xml.indexOf('&#xD;'), -1, 'no CR escape without encryption');
	});
});

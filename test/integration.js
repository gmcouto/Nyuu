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
});

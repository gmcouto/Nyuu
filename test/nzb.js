"use strict";

var assert = require("assert");
var Newbz = require('../lib/nzb');
var toBuffer = (Buffer.alloc ? Buffer.from : Buffer);

describe('NZB Generator', function() {
	it('should basically work', function() {
		var data = [];
		var nzb = new Newbz(
			{
				yenc_encrypted: 'true',
				password: 'test123',
				'testing & stuffing around' : 'test value',
				another_tag : '"hello world"'
			},
			function(blob, encoding) {
				data.push(toBuffer(blob, encoding));
			},
			true,
			'utf8'
		);
		
		nzb.file(
			'i_am_insane.jpg',
			'A <Poster>',
			['alt.binaries.test', 'tildes suck&&&&', '"made up group"'],
			null
		);
		nzb.addSegment(123, 'blabla@test.test');
		nzb.addSegment(111, 'invalid<name>@place');
		nzb.file(
			'Silly&File',
			'A <Poster>',
			['alt.binaries.test', 'tildes suck&&&&', '"made up group"'],
			null
		);
		// this file is invalid as it has no segments, but I cbf checking this case
		nzb.end();
		
		data = Buffer.concat(data).toString();
		
		if(!data.indexOf('<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">'))
			throw new Error('Missing NZB tag');
		if(!data.indexOf('<meta type="yenc_encrypted">true</meta>'))
			throw new Error('Missing encryption meta tag');
		if(!data.indexOf('<meta type="password">test123</meta>'))
			throw new Error('Missing password meta tag');
		if(!data.indexOf('<meta type="testing &amp; stuffing around">test value</meta>'))
			throw new Error('Missing 1st meta tag');
		if(!data.indexOf('<meta type="another_tag">&quot;hello world&quot;</meta>'))
			throw new Error('Missing 2nd meta tag');
		if(!data.indexOf('poster="A &lt;Poster&gt;"'))
			throw new Error('Missing poster attrib');
		if(!data.indexOf('subject="Silly&amp;File (1/1)"'))
			throw new Error('Missing subject attrib');
		if(!data.indexOf('<group>&quot;made up group&quot;</group>'))
			throw new Error('Missing particular group');
		if(!data.indexOf(' number="2"'))
			throw new Error('Missing 2nd segment');
		assert.equal(data.indexOf('segmentIndex='), -1);
		assert.doesNotMatch(data, /segmentIndex/);
		assert.match(data, /<segment bytes="123" number="1">blabla@test\.test<\/segment>/);
		assert.match(data, /<segment bytes="111" number="2">invalid&lt;name&gt;@place<\/segment>/);
		if(!data.indexOf('invalid&lt;name&gt;@place'))
			throw new Error('Missing 2nd segment ID');
		if(!data.indexOf('</file><file '))
			throw new Error('Missing file start/end');
		if(!data.indexOf('</nzb>'))
			throw new Error('Missing NZB close tag');
		
		// doesn't seem to be any problems otherwise...
		
		
		// test wholeFile
		// this is a copy/paste from above
		var data2 = [];
		nzb = new Newbz(
			{
				yenc_encrypted: 'true',
				password: 'test123',
				'testing & stuffing around' : 'test value',
				another_tag : '"hello world"'
			},
			function(blob, encoding) {
				data2.push(toBuffer(blob, encoding));
			},
			true,
			'utf8'
		);
		
		nzb.wholeFile(
			'i_am_insane.jpg',
			'A <Poster>',
			['alt.binaries.test', 'tildes suck&&&&', '"made up group"'],
			null,
			[
				[123, 'blabla@test.test'],
				[111, 'invalid<name>@place']
			]
		);
		nzb.wholeFile(
			'Silly&File',
			'A <Poster>',
			['alt.binaries.test', 'tildes suck&&&&', '"made up group"'],
			null,
			[]
		);
		// this file is invalid as it has no segments, but I cbf checking this case
		nzb.end();
		
		data2 = Buffer.concat(data2).toString();
		
		assert.equal(data, data2);
	});

	it('emits clean standard NZB 1.1 XML without segmentIndex in buffered mode', function() {
		var NZBBuffered = require('../lib/nzbbuffer');
		var data = [];
		var nzb = new NZBBuffered(
			{
				yenc_encrypted: 'true',
				password: 'test123'
			},
			function(blob, encoding) {
				data.push(toBuffer(blob, encoding));
			},
			true,
			'utf8'
		);
		var file = nzb.file('test.bin', 'poster', ['alt.binaries.test'], 2, null);
		file.set(0, 100, 'msg1@test');
		file.set(1, 200, 'msg2@test');
		nzb.end();

		var xml = Buffer.concat(data).toString();
		assert.equal(xml.indexOf('segmentIndex='), -1);
		assert.doesNotMatch(xml, /segmentIndex/);
		assert.match(xml, /<segment bytes="100" number="1">msg1@test<\/segment>/);
		assert.match(xml, /<segment bytes="200" number="2">msg2@test<\/segment>/);
		assert.match(xml, /<meta type="yenc_encrypted">true<\/meta>/);
		assert.match(xml, /<meta type="password">test123<\/meta>/);
	});
});

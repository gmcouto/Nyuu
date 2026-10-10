"use strict";

var y = require('yencode');
var cryptoUtil = require('./crypto');
var ff1 = require('./ff1');

var RE_BADCHAR = /[\r\n\0]/g;
var RE_BADMSGIDCHAR = /[^\u0020-\u007F]/g;
var AR_CRC = [0,0,0,0];

var BUFFER_ENLARGE_SPACE = 4096; // minimum amount of extra padding to give when enlarging buffers
var MAX_NAME_LENGTH = 1024; // maximum byte length of the yEnc 'name' header (used for filenames); although filenames with paths can be quite long, we need to keep in mind that yEnc typically has a per-line length limit of around 128 bytes

var toBuffer = Buffer.alloc ? Buffer.from : Buffer;
var NEWLINE = toBuffer('\r\n', 'ascii');
var bufferSlice = Buffer.prototype.readBigInt64BE ? Buffer.prototype.subarray : Buffer.prototype.slice;

var resizeBuffer = function(size, src, srcLen) {
	var buf = (Buffer.allocUnsafe || Buffer)(size);
	src.copy(buf, 0, 0, srcLen);
	return buf;
};

// TODO: should we switch to single article mode if only 1 part?
function MultiEncoder(filename, size, articleSize, timestamp, opts) {
	if(!opts) opts = {};
	this.size = size;
	this.parts = Math.max(1, Math.ceil(size / articleSize));
	this.line_size = opts.line_size || 128;
	this.timestamp = timestamp;
	this.encoding = opts.encoding || 'utf8';
	this.encryption = opts.encryption || null;
	
	this.part = 0;
	this.pos = 0;
	this.crc = toBuffer(AR_CRC);
	
	this.filename = filename;
	if(opts.name !== undefined && opts.name !== null) {
		if(typeof opts.name == 'function')
			filename = opts.name(filename, size, 1, this.parts);
		else
			filename = opts.name;
	}
	filename = filename.replace(RE_BADCHAR, '');
	var yiPre = ' total='+this.parts+' line='+this.line_size+' size='+size+' name=', yiSuf = '\r\n=ypart begin=';
	this.yInfo = (Buffer.allocUnsafe || Buffer)(Buffer.byteLength(yiPre + yiSuf, this.encoding) + MAX_NAME_LENGTH);
	var p = this.yInfo.write(yiPre, 0, this.yInfo.length, this.encoding);
	p += this.yInfo.write(filename, p, MAX_NAME_LENGTH, this.encoding);
	p += this.yInfo.write(yiSuf, p, this.yInfo.length-p, this.encoding);
	this.yInfo = bufferSlice.call(this.yInfo, 0, p);
	
	this.maxPostSize = y.maxSize(articleSize + (this.encryption ? 16 : 0), this.line_size)
		+ (this.encryption ? 256 : 0)
		+ 75 /* size of fixed strings (incl final CRC) assuming ASCII or similar encoding */
		+ this.yInfo.length
		+ ((this.parts+'').length *2)
		+ ((size+'').length *3);
}
MultiEncoder.prototype = {
	headers: null,
	subjectPre: '', // default subject parameters
	subjectPost: '',
	messageIdFn: null,
	setHeaders: function(headers, defSubjectPre, defSubjectPost) {
		this.headers = {};
		this.messageIdFn = null;
		for(var h in headers) {
			var v = headers[h];
			var hl = h.toLowerCase();
			if(typeof v == 'function')
				this.headers[h] = v.bind(null, this.filename, this.size);
			else if(hl == 'subject' && v === null) {
				this.subjectPre = defSubjectPre.replace(RE_BADCHAR, '');
				this.subjectPost = defSubjectPost.replace(RE_BADCHAR, '');
				this.headers[h] = v;
			} else if(v)
				this.headers[h] = v.replace(RE_BADCHAR, '');
			else {
				if(hl == 'date' && this.timestamp)
					this.headers[h] = this.timestamp.toUTCString();
				else
					this.headers[h] = v;
			}
			
			// handle Message-ID header specially
			if(hl == 'message-id') {
				if(typeof v == 'function')
					this.messageIdFn = this.headers[h];
				else if(v) // a constant Message-ID isn't really sensical, but we'll allow it
					this.messageIdFn = (function() { return this; }).bind(v);
				delete this.headers[h];
			}
		}
	},
	// if caller wants the generated headers, pass an empty object as grabHeaders
	generate: function(data, pool, grabHeaders) {
		this.part++;
		if(this.part > this.parts)
			throw new Error('Exceeded number of specified yEnc parts');
		var end = this.pos + data.length;
		if(end > this.size)
			throw new Error('Exceeded total file size');
		
		var wireData = data;
		var encryption = this.encryption;
		var encryptionResult;
		if(encryption) {
			if(!encryption.bodyKey || !encryption.salt)
				throw new Error('Encryption keys are not initialized');
			encryptionResult = cryptoUtil.encryptBody(data, encryption.bodyKey, encryption.segmentIndex);
			wireData = encryptionResult.ciphertext;
		}
		var crc = y.crc32(wireData);
		var fullCrc = ' pcrc32=' + crc.toString('hex');
		this.crc = y.crc32_combine(this.crc, crc, wireData.length);
		if(this.part == this.parts) {
			// final part treated slightly differently
			if(end != this.size)
				throw new Error('File size doesn\'t match total data length');
			fullCrc += ' crc32='+this.crc.toString('hex');
		}
		
		var post = pool ? new PooledPost(this, pool) : new UnpooledPost(this);
		post.rawSize = data.length;
		post.segmentIndex = encryption ? encryption.segmentIndex : null;
		post.encryption = encryptionResult;
		post.encryptionConfig = encryption ? {masterKey: encryption.masterKey, salt: Buffer.from(encryption.salt), controlLines: encryption.controlLines, bodyKey: encryption.bodyKey} : null;
		if(this.messageIdFn)
			post.createMessageId = this.createMessageId.bind(this, this.part, this.parts);
		post.messageId = post.createMessageId(post);
		
		var headers = {};
		for(var h in this.headers) {
			var v = this.headers[h];
			var hl = h.toLowerCase();
			if(hl == 'subject' && v === null) {
				// default subject
				v = this.subjectPre + this.part + this.subjectPost;
			} else {
				if(typeof v == 'function') {
					v = v(this.part, this.parts, post);
					if(v === null || v === undefined) continue;
					if(typeof v == 'string')
						v = v.replace(RE_BADCHAR, '');
				}
				
				if(hl == 'date' && !v)
					v = (new Date(post.genTime)).toUTCString();
			}
			
			headers[h] = v;
			if(grabHeaders) grabHeaders[hl] = v;
		}
		post._setHeaders(headers);
		
		post._setData(wireData, this.part, this.pos, fullCrc, encryptionResult, data.length);
		
		this.pos = end;
		return post;
	},
	createMessageId: function(part, parts, post) {
		return (''+this.messageIdFn.call(post, part, parts, post)).replace(RE_BADMSGIDCHAR, '.');
	}
};

// pessimistic maximum size of an encoded article
// does not consider the effect of ENCODING, but assumes that it's sane
MultiEncoder.maxSize = function(size, line_size) {
	return 213 + MAX_NAME_LENGTH + y.maxSize(size, line_size);
	/* the above is derived from:
	return
		  13 // '=ybegin part='
		+ 10 // len(2^32)
		+  7 // ' total='
		+ 10 // len(2^32)
		+  6 // ' line='
		+  4 // thousands of chars/line
		+  6 // ' size='
		+ 16 // len(2^53)
		+  6 // ' name='
		+  2 // '\r\n'
		+ 13 // '=ypart begin='
		+ 16 // len(2^53)
		+  5 // ' end='
		+ 16 // len(2^53)
		+  2 // '\r\n'
		+ y.maxSize(size, line_size)
		+ 13 // '\r\n=yend size='
		+ 16 // len(2^53)
		+  6 // ' part='
		+ 10 // len(2^32)
		+  8 // ' pcrc32='
		+  8 // len(hex(crc32))
		+  7 // ' crc32='
		+  8 // len(hex(crc32))
		+  5 // '\r\n.\r\n'
	;
	*/
};

MultiEncoder.fromBuffer = function(buf, encoding) {
	return new RawPost(buf, encoding);
};


function Post(parent) {
	this.parent = parent;
	this.genTime = parent.timestamp ? parent.timestamp.getTime() : Date.now();
}
Post.prototype = {
	genTime: null,
	rawSize: 0,
	// WARNING: do NOT return non-ASCII characters from this function!
	createMessageId: function(post) {
		var timestamp = ''+this.genTime;
		// fix the timestamp length to 13 chars - only an issue with wonky clocks
		timestamp = '0000000000000'.substring(timestamp.length) + timestamp.slice(-13);
		return String.fromCharCode(
			65 + Math.random()*26,
			97 + Math.random()*26,
			65 + Math.random()*26,
			97 + Math.random()*26,
			65 + Math.random()*26,
			97 + Math.random()*26,
			65 + Math.random()*26,
			97 + Math.random()*26,
			65 + Math.random()*26,
			97 + Math.random()*26,
			65 + Math.random()*26,
			97 + Math.random()*26,
			65 + Math.random()*26,
			97 + Math.random()*26,
			65 + Math.random()*26,
			97 + Math.random()*26,
			65 + Math.random()*26,
			97 + Math.random()*26,
			65 + Math.random()*26,
			97 + Math.random()*26,
			65 + Math.random()*26,
			97 + Math.random()*26,
			65 + Math.random()*26,
			97 + Math.random()*26
		) + '-' + timestamp + '@nyuu';
	},
	
	pos: null,
	part: null,
	crcFrag: null,
	data: null,
	postLen: null,
	postPos: 0,
	
	reload: null, // overwrite this with a function defining how to reload the post into memory
	
	keepMessageId: false,
	_msgIdOffset: 13, /* 'Message-ID: <'.length */
	
	_setData: function(data, part, pos, crcFrag, encryptionResult, plaintextLength) {
		this.part = part;
		this.pos = pos;
		this.crcFrag = crcFrag;
		this.inputLen = plaintextLength === undefined ? data.length : plaintextLength;
		this.wireLen = data.length;
		this.encryptionResult = encryptionResult || null;
		this.segmentIndex = this.parent.encryption ? this.parent.encryption.segmentIndex : null;
	},
	
	randomizeMessageID: function() {
		var newId = this.createMessageId(this);
		// NOTE: this won't work if createMessageId returns non-ASCII characters; such cases are not supported
		if(newId.length > this.messageId.length)
			newId = newId.substring(0, this.messageId.length);
		else if(newId.length < this.messageId.length)
			newId = newId + '-' + this.messageId.substring(newId.length + 1).replace(/@/g, '-');
		if(this.data)
			this.data.write(newId, this._msgIdOffset, this.parent.encoding);
		if(this._headerBufs && this._headerBufs.length > 0) {
			for(var i = 0; i < this._headerBufs.length; i++) {
				if(bufferFind(this._headerBufs[i], 'Message-ID: <', this.parent.encoding) === 0) {
					this._headerBufs[i].write(newId, this._msgIdOffset, this.parent.encoding);
					break;
				}
			}
		}
		if(this._headerStr) {
			this._headerStr = this._headerStr.replace('Message-ID: <' + this.messageId + '>', 'Message-ID: <' + newId + '>');
		}
		return this.messageId = newId;
	},
	
	_getHeadersStr: function() {
		if(!this.data) return null;
		return bufferSlice.call(this.data, 0, this.postPos).toString(this.parent.encoding);
	},
	
	// NOTE: getHeader and stripHeader won't work for the first header (i.e. Message-ID)
	getHeader: function(str) {
		var headers = this._getHeadersStr();
		if(!headers) return null;
		var m = headers.match(new RegExp('\r\n' + str.toLowerCase() + ': *(.*?)\r\n', 'i'));
		if(m) return m[1];
		return false;
	},
	
	// strips a header from a materialized post
	// this is only used as a workaround for some servers rejecting posts but allowing them through if a header is removed
	stripHeader: function(str) {
		// convert post's headers back to a string to find indexes to chop off
		var headers = this._getHeadersStr();
		if(!headers) return false;
		headers = headers.toLowerCase();
		var charFrom = headers.indexOf('\r\n' + str.toLowerCase() + ':');
		if(charFrom < 0) return false;
		var charTo = headers.indexOf('\r\n', charFrom+2);
		
		if(charFrom < 0 || charTo < 0 || charFrom >= charTo) return false; // should never occur, but just in case...
		
		// account for character encodings
		var byteLen = Buffer.byteLength(headers.substring(charFrom, charTo), this.parent.encoding);
		var byteFrom = Buffer.byteLength(headers.substring(0, charFrom), this.parent.encoding);
		var byteTo = byteFrom + byteLen;
		
		// move data down in buffer
		if(this.data) {
			this.data.copy(this.data, byteFrom, byteTo);
			this.postPos -= byteTo-byteFrom;
			this.data = bufferSlice.call(this.data, 0, this.postPos + this.postLen);
		} else {
			this.postPos -= byteTo-byteFrom;
		}
		if(this._headerBufs) {
			var prefix = '\r\n' + str.toLowerCase() + ':';
			for(var i = 0; i < this._headerBufs.length; i++) {
				var line = '\r\n' + this._headerBufs[i].toString(this.parent.encoding).toLowerCase();
				if(line.indexOf(prefix) === 0) {
					this._headerBufs.splice(i, 1);
					break;
				}
			}
			if(this.bufs) {
				var bodyBuf = (this.data && this.bufs.length > this._headerBufs.length) ? this.bufs[this.bufs.length - 1] : null;
				this.bufs = this._headerBufs.slice();
				if(bodyBuf) this.bufs.push(bodyBuf);
			}
		}
		if(this._headerStr) {
			this._headerStr = this._headerStr.substring(0, charFrom) + this._headerStr.substring(charTo);
		}
		
		return true;
	},
	
	releaseData: function() {
		this.release();
	},
	release: function() {
		this.data = null;
	}
};


function PooledPost(parent, pool) {
	Post.call(this, parent);
	this.pool = pool;
}
PooledPost.prototype = Object.create(Post.prototype);
PooledPost.prototype.pool = null;
PooledPost.prototype.buf = null;
PooledPost.prototype._headerStr = null;
PooledPost.prototype._setHeaders = function(headers) {
	this.buf = this.pool.get();
	while(1) {
		this.postPos = this.buf.write('Message-ID: <' + this.messageId + '>\r\n', 0, this.parent.encoding);
		for(var h in headers) {
			if(headers[h] === null || headers[h] === undefined) continue;
			this.postPos += this.buf.write(h + ': ' + headers[h] + '\r\n', this.postPos, this.parent.encoding);
		}
		this.postPos += NEWLINE.length;
		if(this.postPos >= this.buf.length) {
			// likely overflowed, try again
			this.buf = (Buffer.allocUnsafe || Buffer)(this.postPos + Math.max(this.buf.length, BUFFER_ENLARGE_SPACE));
			this.postPos = 0;
			continue;
		}
		NEWLINE.copy(this.buf, this.postPos-NEWLINE.length);
		break;
	}
};
PooledPost.prototype._writeData = function(data) {
	if(!this.encryptionConfig) {
		var bufPos = this.postPos;
		bufPos += this.buf.write('=ybegin part='+this.part, bufPos, this.parent.encoding);
		this.parent.yInfo.copy(this.buf, bufPos);
		bufPos += this.parent.yInfo.length;
		bufPos += this.buf.write(( this.pos+1 )+' end='+(this.pos + data.length)+'\r\n', bufPos, this.parent.encoding);
		bufPos += y.encodeTo(data, bufferSlice.call(this.buf, bufPos), this.parent.line_size);
		bufPos += this.buf.write('\r\n=yend size='+data.length+' part='+this.part+this.crcFrag+'\r\n.\r\n', bufPos, this.parent.encoding);
		
		this.data = bufferSlice.call(this.buf, 0, bufPos);
		return bufPos - this.postPos;
	}
	var body = [
		toBuffer('=ybegin part='+this.part, this.parent.encoding),
		this.parent.yInfo,
		toBuffer(( this.pos+1 )+' end='+(this.pos + data.length)+'\r\n', this.parent.encoding),
		this.encryptionResult ? toBuffer('=yencryption cipher=XChaCha20-Poly1305 salt='+this.encryptionConfig.salt.toString('hex')+' index='+this.segmentIndex.toString(16).padStart(8, '0')+' tag='+this.encryptionResult.tag.toString('hex')+'\r\n', this.parent.encoding) : null,
		y.encode(data, this.parent.line_size),
		toBuffer((data.length === 0 ? '' : '\r\n') + '=yend size=' + data.length + ' part=' + this.part + this.crcFrag + '\r\n.\r\n', this.parent.encoding)
	].filter(function(value) { return value !== null; });
	body = Buffer.concat(body);
	// v1 wire mode is combined-only: control-line encryption cannot be disabled
	// (locked out here too, since MultiEncoder can be constructed directly)
	if(!this.encryptionConfig.controlLines)
		throw new Error('Combined-only wire mode: encrypted uploads must enable control-line encryption');
	body = ff1.encryptControlLines(body, this.encryptionConfig.masterKey, this.segmentIndex, this.encryptionConfig.salt);
	if(this.buf.length < this.postPos + body.length)
		this.buf = resizeBuffer(this.postPos + body.length, this.buf, this.postPos);
	body.copy(this.buf, this.postPos);
	this.data = bufferSlice.call(this.buf, 0, this.postPos + body.length);
	return body.length;
};
PooledPost.prototype._setData = function(data, part, pos, crcFrag) {
	Post.prototype._setData.apply(this, arguments);
	
	var bufPos = this.postPos;
	var minSpace = bufPos + this.parent.maxPostSize;
	// ensure we have enough space
	if(this.buf.length < minSpace)
		this.buf = resizeBuffer(minSpace, this.buf, bufPos);
	// newly created buffers should be at least this size
	if(this.pool.size < minSpace)
		this.pool.size = minSpace + BUFFER_ENLARGE_SPACE;
	
	this.postLen = this._writeData(data);
};
PooledPost.prototype.release = function() {
	if(this.buf) {
		this.pool.put(this.buf);
		this.buf = null;
	}
	Post.prototype.release.call(this);
};
PooledPost.prototype._getHeadersStr = function() {
	if(!this.data && this._headerStr)
		return this._headerStr;
	return Post.prototype._getHeadersStr.call(this);
};
PooledPost.prototype.releaseData = function() {
	this._headerStr = this._getHeadersStr();
	this.release();
};
PooledPost.prototype.reloadData = function(data) {
	if(this.inputLen != data.length)
		throw new Error('Supplied buffer is of incorrect length');
	this.buf = this.pool.get();
	if(this.postPos != this.buf.write(this._headerStr, 0, this.parent.encoding))
		throw new Error('Header length mismatch encountered');
	var wireData = data;
	if(this.encryptionConfig) {
		var bodyKey = this.encryptionConfig.bodyKey || (this.parent && this.parent.encryption && this.parent.encryption.bodyKey);
		var encRes = cryptoUtil.encryptBody(data, bodyKey, this.segmentIndex);
		this.encryptionResult = encRes;
		this.encryption = encRes;
		wireData = encRes.ciphertext;
	}
	if(this.postLen != this._writeData(wireData))
		throw new Error('Article length mismatch encountered');
	
	this._headerStr = null;
};

function UnpooledPost(parent) {
	Post.call(this, parent);
}
UnpooledPost.prototype = Object.create(Post.prototype);
UnpooledPost.prototype.bufs = null;
UnpooledPost.prototype._addHeader = function(data) {
	var d = toBuffer(data + '\r\n', this.parent.encoding);
	this.postPos += d.length;
	this.bufs.push(d);
};
UnpooledPost.prototype._setHeaders = function(headers) {
	this.bufs = [];
	this._addHeader('Message-ID: <' + this.messageId + '>');
	for(var h in headers) {
		this._addHeader(h + ': ' + headers[h]);
	}
	this.bufs.push(NEWLINE);
	this.postPos += NEWLINE.length;
	// IN-05-R4: snapshot the full header framing (all headers + blank-line
	// separator) so failure/reload paths can restore a well-formed article
	// prefix rather than collapsing to the Message-ID header alone.
	this._headerBufs = this.bufs.slice();
};
UnpooledPost.prototype._writeData = function(data) {
	var body = [
		toBuffer('=ybegin part='+this.part, this.parent.encoding),
		this.parent.yInfo,
		toBuffer(( this.pos+1 )+' end='+(this.pos + data.length)+'\r\n', this.parent.encoding),
		this.encryptionResult ? toBuffer('=yencryption cipher=XChaCha20-Poly1305 salt='+this.encryptionConfig.salt.toString('hex')+' index='+this.segmentIndex.toString(16).padStart(8, '0')+' tag='+this.encryptionResult.tag.toString('hex')+'\r\n', this.parent.encoding) : null,
		y.encode(data, this.parent.line_size),
		toBuffer((data.length === 0 ? '' : '\r\n') + '=yend size=' + data.length + ' part=' + this.part + this.crcFrag + '\r\n.\r\n', this.parent.encoding)
	].filter(function(value) { return value !== null; });
	var encoded = Buffer.concat(body);
	// v1 wire mode is combined-only: control-line encryption cannot be disabled
	// (locked out here too, since MultiEncoder can be constructed directly)
	if(this.encryptionConfig && !this.encryptionConfig.controlLines)
		throw new Error('Combined-only wire mode: encrypted uploads must enable control-line encryption');
	if(this.encryptionConfig)
		encoded = ff1.encryptControlLines(encoded, this.encryptionConfig.masterKey, this.segmentIndex, this.encryptionConfig.salt);
	// on re-writes (reload path), collapse bufs to the full header prefix first so
	// a failed reload cannot accumulate stale bodies (IN-05-R4)
	if(this.bufs && this.bufs.length > 1 && this.data)
		this.bufs = this._headerBufs.slice();
	this.bufs.push(encoded);
	this.data = Buffer.concat(this.bufs);
	return this.data.length - this.postPos;
};
UnpooledPost.prototype._setData = function(data, part, pos, crcFrag) {
	Post.prototype._setData.apply(this, arguments);
	
	this.postLen = this._writeData(data);
};
UnpooledPost.prototype._getHeadersStr = function() {
	if(!this.data) {
		var bufs = this._headerBufs || this.bufs;
		if(bufs)
			return Buffer.concat(bufs).toString(this.parent.encoding);
		return null;
	}
	return Post.prototype._getHeadersStr.call(this);
};
UnpooledPost.prototype.releaseData = function() {
	if(!this.data) return;
	// IN-05-R4: keep the full header prefix (headers + blank line), not just
	// the Message-ID, so re-materialized retries are well-formed articles.
	if(this._headerBufs) {
		this.bufs = this._headerBufs.slice();
	} else if(this.bufs) {
		this._headerBufs = this.bufs.slice(0, this.bufs.length - 1);
		this.bufs = this._headerBufs.slice();
	}
	this.release();
};
UnpooledPost.prototype.reloadData = function(data) {
	var wireData = data;
	if(this.encryptionConfig) {
		var bodyKey = this.encryptionConfig.bodyKey || (this.parent && this.parent.encryption && this.parent.encryption.bodyKey);
		var encRes = cryptoUtil.encryptBody(data, bodyKey, this.segmentIndex);
		this.encryptionResult = encRes;
		this.encryption = encRes;
		wireData = encRes.ciphertext;
	}
	var writtenLen;
	try {
		writtenLen = this._writeData(wireData);
	} catch(err) {
		if(this.bufs && this.bufs.length > 1) this.bufs = this._headerBufs.slice();
		this.data = null;
		throw err;
	}
	if(this.postLen != writtenLen) {
		if(this.bufs && this.bufs.length > 1) this.bufs = this._headerBufs.slice();
		this.data = null;
		throw new Error('Article length mismatch encountered');
	}
};


var bufferFind;
if(Buffer.prototype.indexOf)
	bufferFind = function(buf, search, encoding) {
		return buf.indexOf(search, encoding);
	};
else
	bufferFind = function(buf, search, encoding) {
		if(!Buffer.isBuffer(search))
			search = toBuffer(search, encoding);
		if(search.length == 0) return 0;
		if(search.length > buf.length) return -1;
		
		for(var i = 0; i < buf.length - search.length + 1; i++) {
			var match = true;
			for(var j = 0; j < search.length; j++) {
				if(buf[i+j] != search[j]) {
					match = false;
					break;
				}
			}
			if(match) return i;
		}
		return -1;
	};


var crypto;

// similar to Post, but constructed from a buffer
// TODO: consider making encoding 'binary' everywhere (can't do for now, due to messageId)
function RawPost(data, encoding) {
	var headers = {};
	
	this.data = this.buf = data;
	this.postPos = bufferFind(data, '\r\n\r\n', 'binary');
	if(this.postPos <= 0) throw new Error('Could not parse post');
	
	var hdr = bufferSlice.call(data, 0, this.postPos).toString(encoding).split('\r\n');
	this.postPos += 4; // '\r\n\r\n'.length
	
	var self = this;
	var p = 0;
	hdr.forEach(function(h) {
		var m = h.match(/^(.*?)(\: *)(.*)$/);
		if(!m || !m[1])
			throw new Error('Invalid header line: "' + h + '"');
		var k = m[1].trim().toLowerCase(),
		    v = m[3].trim();
		headers[k] = v;
		if(k == 'message-id') {
			self._msgIdOffset = p + Buffer.byteLength(m[1] + m[2], encoding);
		}
		p += Buffer.byteLength(h, encoding) + 2;
	});
	
	var m;
	if(!headers['message-id'] || !(m = headers['message-id'].match(/^<(.+)>$/)))
		throw new Error('Post lacks a valid Message-ID header!');
	// TODO: repair things if given a really short message ID (e.g. 3 bytes long)
	this.messageId = m[1];
	// TODO: above line can be problematic if non-ASCII characters received
	self._msgIdOffset++; // go past first <
	
	if(headers.date)
		this.genTime = (new Date(headers.date)).getTime();
	else
		this.genTime = Date.now();
	
	// TODO: set post.inputLen?
	
	this.data = this.buf;
	this.postLen = data.length - this.postPos;
	this.keepMessageId = true;
	this.parent = {encoding: encoding};
}
RawPost.prototype = Object.create(Post.prototype);

RawPost.prototype.reloadData = function(data) {
	this.data = data;
	if(this.postLen != data.length - this.postPos)
		throw new Error('Article length mismatch encountered');
};

module.exports = MultiEncoder;

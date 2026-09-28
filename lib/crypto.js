"use strict";

var crypto = require('crypto');
var argon2id = require('hash-wasm').argon2id;
var xchacha20poly1305 = require('@noble/ciphers/chacha').xchacha20poly1305;

var BODY_NONCE_PREFIX = Buffer.from('yenc-body nonce', 'ascii');
var CONTROL_KEY_PREFIX = Buffer.from('yenc-control key', 'ascii');
var CONTROL_TWEAK_PREFIX = Buffer.from('yenc-control tweak', 'ascii');
var MAX_UINT32 = 0xffffffff;

function checkBuffer(value, length, name) {
	if(!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
		throw new TypeError(name + ' must be a byte buffer');
	if(length !== undefined && value.length !== length)
		throw new RangeError(name + ' must be exactly ' + length + ' bytes');
	return Buffer.from(value);
}

function checkIndex(value, name) {
	if(!Number.isSafeInteger(value) || value < 1 || value > MAX_UINT32)
		throw new RangeError(name + ' must be an integer from 1 to 4294967295');
	return value;
}

function uint32Be(value, name) {
	var result = Buffer.allocUnsafe(4);
	result.writeUInt32BE(checkIndex(value, name), 0);
	return result;
}

function generateSalt() {
	return crypto.randomBytes(16);
}

function generateEncryptionSalt() {
	var salt;
	do {
		salt = generateSalt();
	} while(Array.prototype.some.call(salt, function(value) {
		return value === 0 || value === 10 || value === 13;
	}));
	return salt;
}

async function deriveKey(password, salt) {
	if(typeof password != 'string' && !Buffer.isBuffer(password) && !(password instanceof Uint8Array))
		throw new TypeError('password must be a string or byte buffer');
	if(password.length === 0)
		throw new RangeError('password must not be empty');
	salt = checkBuffer(salt, 16, 'salt');
	var result = await argon2id({
		password: password,
		salt: salt,
		iterations: 1,
		memorySize: 65536,
		parallelism: 4,
		hashLength: 32,
		outputType: 'binary'
	});
	return Buffer.from(result);
}

function deriveBodyNonce(key, segmentIndex) {
	key = checkBuffer(key, 32, 'key');
	var input = Buffer.concat([BODY_NONCE_PREFIX, uint32Be(segmentIndex, 'segmentIndex')]);
	return crypto.createHmac('sha256', key).update(input).digest().subarray(0, 24);
}

function deriveControlKey(masterKey) {
	masterKey = checkBuffer(masterKey, 32, 'masterKey');
	return crypto.createHmac('sha256', masterKey).update(CONTROL_KEY_PREFIX).digest();
}

function deriveControlTweak(masterKey, segmentIndex, lineIndex) {
	masterKey = checkBuffer(masterKey, 32, 'masterKey');
	var input = Buffer.concat([
		CONTROL_TWEAK_PREFIX,
		uint32Be(segmentIndex, 'segmentIndex'),
		uint32Be(lineIndex, 'lineIndex')
	]);
	return crypto.createHmac('sha256', masterKey).update(input).digest().subarray(0, 8);
}

async function deriveKeys(password, salt) {
	var masterKey = await deriveKey(password, salt);
	return {
		bodyKey: Buffer.from(masterKey),
		controlKey: deriveControlKey(masterKey),
		masterKey: masterKey
	};
}

function encryptBody(plaintext, key, segmentIndex) {
	plaintext = checkBuffer(plaintext, undefined, 'plaintext');
	key = checkBuffer(key, 32, 'key');
	var nonce = deriveBodyNonce(key, segmentIndex);
	var sealed = Buffer.from(xchacha20poly1305(key, nonce).encrypt(plaintext));
	return {
		ciphertext: sealed.subarray(0, sealed.length - 16),
		tag: sealed.subarray(sealed.length - 16),
		nonce: nonce
	};
}

module.exports = {
	deriveBodyNonce: deriveBodyNonce,
	deriveControlKey: deriveControlKey,
	deriveControlTweak: deriveControlTweak,
	deriveKey: deriveKey,
	deriveKeys: deriveKeys,
	encryptBody: encryptBody,
	generateEncryptionSalt: generateEncryptionSalt,
	generateSalt: generateSalt
};

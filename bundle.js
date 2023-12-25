(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
const bip39 = require('bip39');
const bitcoin = require('bitcoinjs-lib');
},{"bip39":45,"bitcoinjs-lib":66}],2:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.output = exports.exists = exports.hash = exports.bytes = exports.bool = exports.number = void 0;
function number(n) {
    if (!Number.isSafeInteger(n) || n < 0)
        throw new Error(`Wrong positive integer: ${n}`);
}
exports.number = number;
function bool(b) {
    if (typeof b !== 'boolean')
        throw new Error(`Expected boolean, not ${b}`);
}
exports.bool = bool;
// copied from utils
function isBytes(a) {
    return (a instanceof Uint8Array ||
        (a != null && typeof a === 'object' && a.constructor.name === 'Uint8Array'));
}
function bytes(b, ...lengths) {
    if (!isBytes(b))
        throw new Error('Expected Uint8Array');
    if (lengths.length > 0 && !lengths.includes(b.length))
        throw new Error(`Expected Uint8Array of length ${lengths}, not of length=${b.length}`);
}
exports.bytes = bytes;
function hash(hash) {
    if (typeof hash !== 'function' || typeof hash.create !== 'function')
        throw new Error('Hash should be wrapped by utils.wrapConstructor');
    number(hash.outputLen);
    number(hash.blockLen);
}
exports.hash = hash;
function exists(instance, checkFinished = true) {
    if (instance.destroyed)
        throw new Error('Hash instance has been destroyed');
    if (checkFinished && instance.finished)
        throw new Error('Hash#digest() has already been called');
}
exports.exists = exists;
function output(out, instance) {
    bytes(out);
    const min = instance.outputLen;
    if (out.length < min) {
        throw new Error(`digestInto() expects output buffer of length at least ${min}`);
    }
}
exports.output = output;
const assert = { number, bool, bytes, hash, exists, output };
exports.default = assert;

},{}],3:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SHA2 = void 0;
const _assert_js_1 = require("./_assert.js");
const utils_js_1 = require("./utils.js");
// Polyfill for Safari 14
function setBigUint64(view, byteOffset, value, isLE) {
    if (typeof view.setBigUint64 === 'function')
        return view.setBigUint64(byteOffset, value, isLE);
    const _32n = BigInt(32);
    const _u32_max = BigInt(0xffffffff);
    const wh = Number((value >> _32n) & _u32_max);
    const wl = Number(value & _u32_max);
    const h = isLE ? 4 : 0;
    const l = isLE ? 0 : 4;
    view.setUint32(byteOffset + h, wh, isLE);
    view.setUint32(byteOffset + l, wl, isLE);
}
// Base SHA2 class (RFC 6234)
class SHA2 extends utils_js_1.Hash {
    constructor(blockLen, outputLen, padOffset, isLE) {
        super();
        this.blockLen = blockLen;
        this.outputLen = outputLen;
        this.padOffset = padOffset;
        this.isLE = isLE;
        this.finished = false;
        this.length = 0;
        this.pos = 0;
        this.destroyed = false;
        this.buffer = new Uint8Array(blockLen);
        this.view = (0, utils_js_1.createView)(this.buffer);
    }
    update(data) {
        (0, _assert_js_1.exists)(this);
        const { view, buffer, blockLen } = this;
        data = (0, utils_js_1.toBytes)(data);
        const len = data.length;
        for (let pos = 0; pos < len;) {
            const take = Math.min(blockLen - this.pos, len - pos);
            // Fast path: we have at least one block in input, cast it to view and process
            if (take === blockLen) {
                const dataView = (0, utils_js_1.createView)(data);
                for (; blockLen <= len - pos; pos += blockLen)
                    this.process(dataView, pos);
                continue;
            }
            buffer.set(data.subarray(pos, pos + take), this.pos);
            this.pos += take;
            pos += take;
            if (this.pos === blockLen) {
                this.process(view, 0);
                this.pos = 0;
            }
        }
        this.length += data.length;
        this.roundClean();
        return this;
    }
    digestInto(out) {
        (0, _assert_js_1.exists)(this);
        (0, _assert_js_1.output)(out, this);
        this.finished = true;
        // Padding
        // We can avoid allocation of buffer for padding completely if it
        // was previously not allocated here. But it won't change performance.
        const { buffer, view, blockLen, isLE } = this;
        let { pos } = this;
        // append the bit '1' to the message
        buffer[pos++] = 0b10000000;
        this.buffer.subarray(pos).fill(0);
        // we have less than padOffset left in buffer, so we cannot put length in current block, need process it and pad again
        if (this.padOffset > blockLen - pos) {
            this.process(view, 0);
            pos = 0;
        }
        // Pad until full block byte with zeros
        for (let i = pos; i < blockLen; i++)
            buffer[i] = 0;
        // Note: sha512 requires length to be 128bit integer, but length in JS will overflow before that
        // You need to write around 2 exabytes (u64_max / 8 / (1024**6)) for this to happen.
        // So we just write lowest 64 bits of that value.
        setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE);
        this.process(view, 0);
        const oview = (0, utils_js_1.createView)(out);
        const len = this.outputLen;
        // NOTE: we do division by 4 later, which should be fused in single op with modulo by JIT
        if (len % 4)
            throw new Error('_sha2: outputLen should be aligned to 32bit');
        const outLen = len / 4;
        const state = this.get();
        if (outLen > state.length)
            throw new Error('_sha2: outputLen bigger than state');
        for (let i = 0; i < outLen; i++)
            oview.setUint32(4 * i, state[i], isLE);
    }
    digest() {
        const { buffer, outputLen } = this;
        this.digestInto(buffer);
        const res = buffer.slice(0, outputLen);
        this.destroy();
        return res;
    }
    _cloneInto(to) {
        to || (to = new this.constructor());
        to.set(...this.get());
        const { blockLen, buffer, length, finished, destroyed, pos } = this;
        to.length = length;
        to.pos = pos;
        to.finished = finished;
        to.destroyed = destroyed;
        if (length % blockLen)
            to.buffer.set(buffer);
        return to;
    }
}
exports.SHA2 = SHA2;

},{"./_assert.js":2,"./utils.js":12}],4:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.add5L = exports.add5H = exports.add4H = exports.add4L = exports.add3H = exports.add3L = exports.add = exports.rotlBL = exports.rotlBH = exports.rotlSL = exports.rotlSH = exports.rotr32L = exports.rotr32H = exports.rotrBL = exports.rotrBH = exports.rotrSL = exports.rotrSH = exports.shrSL = exports.shrSH = exports.toBig = exports.split = exports.fromBig = void 0;
const U32_MASK64 = /* @__PURE__ */ BigInt(2 ** 32 - 1);
const _32n = /* @__PURE__ */ BigInt(32);
// We are not using BigUint64Array, because they are extremely slow as per 2022
function fromBig(n, le = false) {
    if (le)
        return { h: Number(n & U32_MASK64), l: Number((n >> _32n) & U32_MASK64) };
    return { h: Number((n >> _32n) & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
}
exports.fromBig = fromBig;
function split(lst, le = false) {
    let Ah = new Uint32Array(lst.length);
    let Al = new Uint32Array(lst.length);
    for (let i = 0; i < lst.length; i++) {
        const { h, l } = fromBig(lst[i], le);
        [Ah[i], Al[i]] = [h, l];
    }
    return [Ah, Al];
}
exports.split = split;
const toBig = (h, l) => (BigInt(h >>> 0) << _32n) | BigInt(l >>> 0);
exports.toBig = toBig;
// for Shift in [0, 32)
const shrSH = (h, _l, s) => h >>> s;
exports.shrSH = shrSH;
const shrSL = (h, l, s) => (h << (32 - s)) | (l >>> s);
exports.shrSL = shrSL;
// Right rotate for Shift in [1, 32)
const rotrSH = (h, l, s) => (h >>> s) | (l << (32 - s));
exports.rotrSH = rotrSH;
const rotrSL = (h, l, s) => (h << (32 - s)) | (l >>> s);
exports.rotrSL = rotrSL;
// Right rotate for Shift in (32, 64), NOTE: 32 is special case.
const rotrBH = (h, l, s) => (h << (64 - s)) | (l >>> (s - 32));
exports.rotrBH = rotrBH;
const rotrBL = (h, l, s) => (h >>> (s - 32)) | (l << (64 - s));
exports.rotrBL = rotrBL;
// Right rotate for shift===32 (just swaps l&h)
const rotr32H = (_h, l) => l;
exports.rotr32H = rotr32H;
const rotr32L = (h, _l) => h;
exports.rotr32L = rotr32L;
// Left rotate for Shift in [1, 32)
const rotlSH = (h, l, s) => (h << s) | (l >>> (32 - s));
exports.rotlSH = rotlSH;
const rotlSL = (h, l, s) => (l << s) | (h >>> (32 - s));
exports.rotlSL = rotlSL;
// Left rotate for Shift in (32, 64), NOTE: 32 is special case.
const rotlBH = (h, l, s) => (l << (s - 32)) | (h >>> (64 - s));
exports.rotlBH = rotlBH;
const rotlBL = (h, l, s) => (h << (s - 32)) | (l >>> (64 - s));
exports.rotlBL = rotlBL;
// JS uses 32-bit signed integers for bitwise operations which means we cannot
// simple take carry out of low bit sum by shift, we need to use division.
function add(Ah, Al, Bh, Bl) {
    const l = (Al >>> 0) + (Bl >>> 0);
    return { h: (Ah + Bh + ((l / 2 ** 32) | 0)) | 0, l: l | 0 };
}
exports.add = add;
// Addition with more than 2 elements
const add3L = (Al, Bl, Cl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0);
exports.add3L = add3L;
const add3H = (low, Ah, Bh, Ch) => (Ah + Bh + Ch + ((low / 2 ** 32) | 0)) | 0;
exports.add3H = add3H;
const add4L = (Al, Bl, Cl, Dl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0);
exports.add4L = add4L;
const add4H = (low, Ah, Bh, Ch, Dh) => (Ah + Bh + Ch + Dh + ((low / 2 ** 32) | 0)) | 0;
exports.add4H = add4H;
const add5L = (Al, Bl, Cl, Dl, El) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0) + (El >>> 0);
exports.add5L = add5L;
const add5H = (low, Ah, Bh, Ch, Dh, Eh) => (Ah + Bh + Ch + Dh + Eh + ((low / 2 ** 32) | 0)) | 0;
exports.add5H = add5H;
// prettier-ignore
const u64 = {
    fromBig, split, toBig,
    shrSH, shrSL,
    rotrSH, rotrSL, rotrBH, rotrBL,
    rotr32H, rotr32L,
    rotlSH, rotlSL, rotlBH, rotlBL,
    add, add3L, add3H, add4L, add4H, add5H, add5L,
};
exports.default = u64;

},{}],5:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.crypto = void 0;
exports.crypto = typeof globalThis === 'object' && 'crypto' in globalThis ? globalThis.crypto : undefined;

},{}],6:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.hmac = exports.HMAC = void 0;
const _assert_js_1 = require("./_assert.js");
const utils_js_1 = require("./utils.js");
// HMAC (RFC 2104)
class HMAC extends utils_js_1.Hash {
    constructor(hash, _key) {
        super();
        this.finished = false;
        this.destroyed = false;
        (0, _assert_js_1.hash)(hash);
        const key = (0, utils_js_1.toBytes)(_key);
        this.iHash = hash.create();
        if (typeof this.iHash.update !== 'function')
            throw new Error('Expected instance of class which extends utils.Hash');
        this.blockLen = this.iHash.blockLen;
        this.outputLen = this.iHash.outputLen;
        const blockLen = this.blockLen;
        const pad = new Uint8Array(blockLen);
        // blockLen can be bigger than outputLen
        pad.set(key.length > blockLen ? hash.create().update(key).digest() : key);
        for (let i = 0; i < pad.length; i++)
            pad[i] ^= 0x36;
        this.iHash.update(pad);
        // By doing update (processing of first block) of outer hash here we can re-use it between multiple calls via clone
        this.oHash = hash.create();
        // Undo internal XOR && apply outer XOR
        for (let i = 0; i < pad.length; i++)
            pad[i] ^= 0x36 ^ 0x5c;
        this.oHash.update(pad);
        pad.fill(0);
    }
    update(buf) {
        (0, _assert_js_1.exists)(this);
        this.iHash.update(buf);
        return this;
    }
    digestInto(out) {
        (0, _assert_js_1.exists)(this);
        (0, _assert_js_1.bytes)(out, this.outputLen);
        this.finished = true;
        this.iHash.digestInto(out);
        this.oHash.update(out);
        this.oHash.digestInto(out);
        this.destroy();
    }
    digest() {
        const out = new Uint8Array(this.oHash.outputLen);
        this.digestInto(out);
        return out;
    }
    _cloneInto(to) {
        // Create new instance without calling constructor since key already in state and we don't know it.
        to || (to = Object.create(Object.getPrototypeOf(this), {}));
        const { oHash, iHash, finished, destroyed, blockLen, outputLen } = this;
        to = to;
        to.finished = finished;
        to.destroyed = destroyed;
        to.blockLen = blockLen;
        to.outputLen = outputLen;
        to.oHash = oHash._cloneInto(to.oHash);
        to.iHash = iHash._cloneInto(to.iHash);
        return to;
    }
    destroy() {
        this.destroyed = true;
        this.oHash.destroy();
        this.iHash.destroy();
    }
}
exports.HMAC = HMAC;
/**
 * HMAC: RFC2104 message authentication code.
 * @param hash - function that would be used e.g. sha256
 * @param key - message key
 * @param message - message data
 */
const hmac = (hash, key, message) => new HMAC(hash, key).update(message).digest();
exports.hmac = hmac;
exports.hmac.create = (hash, key) => new HMAC(hash, key);

},{"./_assert.js":2,"./utils.js":12}],7:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.pbkdf2Async = exports.pbkdf2 = void 0;
const _assert_js_1 = require("./_assert.js");
const hmac_js_1 = require("./hmac.js");
const utils_js_1 = require("./utils.js");
// Common prologue and epilogue for sync/async functions
function pbkdf2Init(hash, _password, _salt, _opts) {
    (0, _assert_js_1.hash)(hash);
    const opts = (0, utils_js_1.checkOpts)({ dkLen: 32, asyncTick: 10 }, _opts);
    const { c, dkLen, asyncTick } = opts;
    (0, _assert_js_1.number)(c);
    (0, _assert_js_1.number)(dkLen);
    (0, _assert_js_1.number)(asyncTick);
    if (c < 1)
        throw new Error('PBKDF2: iterations (c) should be >= 1');
    const password = (0, utils_js_1.toBytes)(_password);
    const salt = (0, utils_js_1.toBytes)(_salt);
    // DK = PBKDF2(PRF, Password, Salt, c, dkLen);
    const DK = new Uint8Array(dkLen);
    // U1 = PRF(Password, Salt + INT_32_BE(i))
    const PRF = hmac_js_1.hmac.create(hash, password);
    const PRFSalt = PRF._cloneInto().update(salt);
    return { c, dkLen, asyncTick, DK, PRF, PRFSalt };
}
function pbkdf2Output(PRF, PRFSalt, DK, prfW, u) {
    PRF.destroy();
    PRFSalt.destroy();
    if (prfW)
        prfW.destroy();
    u.fill(0);
    return DK;
}
/**
 * PBKDF2-HMAC: RFC 2898 key derivation function
 * @param hash - hash function that would be used e.g. sha256
 * @param password - password from which a derived key is generated
 * @param salt - cryptographic salt
 * @param opts - {c, dkLen} where c is work factor and dkLen is output message size
 */
function pbkdf2(hash, password, salt, opts) {
    const { c, dkLen, DK, PRF, PRFSalt } = pbkdf2Init(hash, password, salt, opts);
    let prfW; // Working copy
    const arr = new Uint8Array(4);
    const view = (0, utils_js_1.createView)(arr);
    const u = new Uint8Array(PRF.outputLen);
    // DK = T1 + T2 + ⋯ + Tdklen/hlen
    for (let ti = 1, pos = 0; pos < dkLen; ti++, pos += PRF.outputLen) {
        // Ti = F(Password, Salt, c, i)
        const Ti = DK.subarray(pos, pos + PRF.outputLen);
        view.setInt32(0, ti, false);
        // F(Password, Salt, c, i) = U1 ^ U2 ^ ⋯ ^ Uc
        // U1 = PRF(Password, Salt + INT_32_BE(i))
        (prfW = PRFSalt._cloneInto(prfW)).update(arr).digestInto(u);
        Ti.set(u.subarray(0, Ti.length));
        for (let ui = 1; ui < c; ui++) {
            // Uc = PRF(Password, Uc−1)
            PRF._cloneInto(prfW).update(u).digestInto(u);
            for (let i = 0; i < Ti.length; i++)
                Ti[i] ^= u[i];
        }
    }
    return pbkdf2Output(PRF, PRFSalt, DK, prfW, u);
}
exports.pbkdf2 = pbkdf2;
async function pbkdf2Async(hash, password, salt, opts) {
    const { c, dkLen, asyncTick, DK, PRF, PRFSalt } = pbkdf2Init(hash, password, salt, opts);
    let prfW; // Working copy
    const arr = new Uint8Array(4);
    const view = (0, utils_js_1.createView)(arr);
    const u = new Uint8Array(PRF.outputLen);
    // DK = T1 + T2 + ⋯ + Tdklen/hlen
    for (let ti = 1, pos = 0; pos < dkLen; ti++, pos += PRF.outputLen) {
        // Ti = F(Password, Salt, c, i)
        const Ti = DK.subarray(pos, pos + PRF.outputLen);
        view.setInt32(0, ti, false);
        // F(Password, Salt, c, i) = U1 ^ U2 ^ ⋯ ^ Uc
        // U1 = PRF(Password, Salt + INT_32_BE(i))
        (prfW = PRFSalt._cloneInto(prfW)).update(arr).digestInto(u);
        Ti.set(u.subarray(0, Ti.length));
        await (0, utils_js_1.asyncLoop)(c - 1, asyncTick, () => {
            // Uc = PRF(Password, Uc−1)
            PRF._cloneInto(prfW).update(u).digestInto(u);
            for (let i = 0; i < Ti.length; i++)
                Ti[i] ^= u[i];
        });
    }
    return pbkdf2Output(PRF, PRFSalt, DK, prfW, u);
}
exports.pbkdf2Async = pbkdf2Async;

},{"./_assert.js":2,"./hmac.js":6,"./utils.js":12}],8:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ripemd160 = exports.RIPEMD160 = void 0;
const _sha2_js_1 = require("./_sha2.js");
const utils_js_1 = require("./utils.js");
// https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
// https://homes.esat.kuleuven.be/~bosselae/ripemd160/pdf/AB-9601/AB-9601.pdf
const Rho = /* @__PURE__ */ new Uint8Array([7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8]);
const Id = /* @__PURE__ */ Uint8Array.from({ length: 16 }, (_, i) => i);
const Pi = /* @__PURE__ */ Id.map((i) => (9 * i + 5) % 16);
let idxL = [Id];
let idxR = [Pi];
for (let i = 0; i < 4; i++)
    for (let j of [idxL, idxR])
        j.push(j[i].map((k) => Rho[k]));
const shifts = /* @__PURE__ */ [
    [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8],
    [12, 13, 11, 15, 6, 9, 9, 7, 12, 15, 11, 13, 7, 8, 7, 7],
    [13, 15, 14, 11, 7, 7, 6, 8, 13, 14, 13, 12, 5, 5, 6, 9],
    [14, 11, 12, 14, 8, 6, 5, 5, 15, 12, 15, 14, 9, 9, 8, 6],
    [15, 12, 13, 13, 9, 5, 8, 6, 14, 11, 12, 11, 8, 6, 5, 5],
].map((i) => new Uint8Array(i));
const shiftsL = /* @__PURE__ */ idxL.map((idx, i) => idx.map((j) => shifts[i][j]));
const shiftsR = /* @__PURE__ */ idxR.map((idx, i) => idx.map((j) => shifts[i][j]));
const Kl = /* @__PURE__ */ new Uint32Array([
    0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e,
]);
const Kr = /* @__PURE__ */ new Uint32Array([
    0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000,
]);
// The rotate left (circular left shift) operation for uint32
const rotl = (word, shift) => (word << shift) | (word >>> (32 - shift));
// It's called f() in spec.
function f(group, x, y, z) {
    if (group === 0)
        return x ^ y ^ z;
    else if (group === 1)
        return (x & y) | (~x & z);
    else if (group === 2)
        return (x | ~y) ^ z;
    else if (group === 3)
        return (x & z) | (y & ~z);
    else
        return x ^ (y | ~z);
}
// Temporary buffer, not used to store anything between runs
const BUF = /* @__PURE__ */ new Uint32Array(16);
class RIPEMD160 extends _sha2_js_1.SHA2 {
    constructor() {
        super(64, 20, 8, true);
        this.h0 = 0x67452301 | 0;
        this.h1 = 0xefcdab89 | 0;
        this.h2 = 0x98badcfe | 0;
        this.h3 = 0x10325476 | 0;
        this.h4 = 0xc3d2e1f0 | 0;
    }
    get() {
        const { h0, h1, h2, h3, h4 } = this;
        return [h0, h1, h2, h3, h4];
    }
    set(h0, h1, h2, h3, h4) {
        this.h0 = h0 | 0;
        this.h1 = h1 | 0;
        this.h2 = h2 | 0;
        this.h3 = h3 | 0;
        this.h4 = h4 | 0;
    }
    process(view, offset) {
        for (let i = 0; i < 16; i++, offset += 4)
            BUF[i] = view.getUint32(offset, true);
        // prettier-ignore
        let al = this.h0 | 0, ar = al, bl = this.h1 | 0, br = bl, cl = this.h2 | 0, cr = cl, dl = this.h3 | 0, dr = dl, el = this.h4 | 0, er = el;
        // Instead of iterating 0 to 80, we split it into 5 groups
        // And use the groups in constants, functions, etc. Much simpler
        for (let group = 0; group < 5; group++) {
            const rGroup = 4 - group;
            const hbl = Kl[group], hbr = Kr[group]; // prettier-ignore
            const rl = idxL[group], rr = idxR[group]; // prettier-ignore
            const sl = shiftsL[group], sr = shiftsR[group]; // prettier-ignore
            for (let i = 0; i < 16; i++) {
                const tl = (rotl(al + f(group, bl, cl, dl) + BUF[rl[i]] + hbl, sl[i]) + el) | 0;
                al = el, el = dl, dl = rotl(cl, 10) | 0, cl = bl, bl = tl; // prettier-ignore
            }
            // 2 loops are 10% faster
            for (let i = 0; i < 16; i++) {
                const tr = (rotl(ar + f(rGroup, br, cr, dr) + BUF[rr[i]] + hbr, sr[i]) + er) | 0;
                ar = er, er = dr, dr = rotl(cr, 10) | 0, cr = br, br = tr; // prettier-ignore
            }
        }
        // Add the compressed chunk to the current hash value
        this.set((this.h1 + cl + dr) | 0, (this.h2 + dl + er) | 0, (this.h3 + el + ar) | 0, (this.h4 + al + br) | 0, (this.h0 + bl + cr) | 0);
    }
    roundClean() {
        BUF.fill(0);
    }
    destroy() {
        this.destroyed = true;
        this.buffer.fill(0);
        this.set(0, 0, 0, 0, 0);
    }
}
exports.RIPEMD160 = RIPEMD160;
/**
 * RIPEMD-160 - a hash function from 1990s.
 * @param message - msg that would be hashed
 */
exports.ripemd160 = (0, utils_js_1.wrapConstructor)(() => new RIPEMD160());

},{"./_sha2.js":3,"./utils.js":12}],9:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sha1 = void 0;
const _sha2_js_1 = require("./_sha2.js");
const utils_js_1 = require("./utils.js");
// SHA1 was cryptographically broken.
// It is still widely used in legacy apps. Don't use it for a new protocol.
// RFC 3174
const rotl = (word, shift) => (word << shift) | ((word >>> (32 - shift)) >>> 0);
// Choice: a ? b : c
const Chi = (a, b, c) => (a & b) ^ (~a & c);
// Majority function, true if any two inpust is true
const Maj = (a, b, c) => (a & b) ^ (a & c) ^ (b & c);
// Initial state
const IV = /* @__PURE__ */ new Uint32Array([
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
]);
// Temporary buffer, not used to store anything between runs
// Named this way because it matches specification.
const SHA1_W = /* @__PURE__ */ new Uint32Array(80);
class SHA1 extends _sha2_js_1.SHA2 {
    constructor() {
        super(64, 20, 8, false);
        this.A = IV[0] | 0;
        this.B = IV[1] | 0;
        this.C = IV[2] | 0;
        this.D = IV[3] | 0;
        this.E = IV[4] | 0;
    }
    get() {
        const { A, B, C, D, E } = this;
        return [A, B, C, D, E];
    }
    set(A, B, C, D, E) {
        this.A = A | 0;
        this.B = B | 0;
        this.C = C | 0;
        this.D = D | 0;
        this.E = E | 0;
    }
    process(view, offset) {
        for (let i = 0; i < 16; i++, offset += 4)
            SHA1_W[i] = view.getUint32(offset, false);
        for (let i = 16; i < 80; i++)
            SHA1_W[i] = rotl(SHA1_W[i - 3] ^ SHA1_W[i - 8] ^ SHA1_W[i - 14] ^ SHA1_W[i - 16], 1);
        // Compression function main loop, 80 rounds
        let { A, B, C, D, E } = this;
        for (let i = 0; i < 80; i++) {
            let F, K;
            if (i < 20) {
                F = Chi(B, C, D);
                K = 0x5a827999;
            }
            else if (i < 40) {
                F = B ^ C ^ D;
                K = 0x6ed9eba1;
            }
            else if (i < 60) {
                F = Maj(B, C, D);
                K = 0x8f1bbcdc;
            }
            else {
                F = B ^ C ^ D;
                K = 0xca62c1d6;
            }
            const T = (rotl(A, 5) + F + E + K + SHA1_W[i]) | 0;
            E = D;
            D = C;
            C = rotl(B, 30);
            B = A;
            A = T;
        }
        // Add the compressed chunk to the current hash value
        A = (A + this.A) | 0;
        B = (B + this.B) | 0;
        C = (C + this.C) | 0;
        D = (D + this.D) | 0;
        E = (E + this.E) | 0;
        this.set(A, B, C, D, E);
    }
    roundClean() {
        SHA1_W.fill(0);
    }
    destroy() {
        this.set(0, 0, 0, 0, 0);
        this.buffer.fill(0);
    }
}
exports.sha1 = (0, utils_js_1.wrapConstructor)(() => new SHA1());

},{"./_sha2.js":3,"./utils.js":12}],10:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sha224 = exports.sha256 = void 0;
const _sha2_js_1 = require("./_sha2.js");
const utils_js_1 = require("./utils.js");
// SHA2-256 need to try 2^128 hashes to execute birthday attack.
// BTC network is doing 2^67 hashes/sec as per early 2023.
// Choice: a ? b : c
const Chi = (a, b, c) => (a & b) ^ (~a & c);
// Majority function, true if any two inpust is true
const Maj = (a, b, c) => (a & b) ^ (a & c) ^ (b & c);
// Round constants:
// first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311)
// prettier-ignore
const SHA256_K = /* @__PURE__ */ new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);
// Initial state (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
// prettier-ignore
const IV = /* @__PURE__ */ new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]);
// Temporary buffer, not used to store anything between runs
// Named this way because it matches specification.
const SHA256_W = /* @__PURE__ */ new Uint32Array(64);
class SHA256 extends _sha2_js_1.SHA2 {
    constructor() {
        super(64, 32, 8, false);
        // We cannot use array here since array allows indexing by variable
        // which means optimizer/compiler cannot use registers.
        this.A = IV[0] | 0;
        this.B = IV[1] | 0;
        this.C = IV[2] | 0;
        this.D = IV[3] | 0;
        this.E = IV[4] | 0;
        this.F = IV[5] | 0;
        this.G = IV[6] | 0;
        this.H = IV[7] | 0;
    }
    get() {
        const { A, B, C, D, E, F, G, H } = this;
        return [A, B, C, D, E, F, G, H];
    }
    // prettier-ignore
    set(A, B, C, D, E, F, G, H) {
        this.A = A | 0;
        this.B = B | 0;
        this.C = C | 0;
        this.D = D | 0;
        this.E = E | 0;
        this.F = F | 0;
        this.G = G | 0;
        this.H = H | 0;
    }
    process(view, offset) {
        // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
        for (let i = 0; i < 16; i++, offset += 4)
            SHA256_W[i] = view.getUint32(offset, false);
        for (let i = 16; i < 64; i++) {
            const W15 = SHA256_W[i - 15];
            const W2 = SHA256_W[i - 2];
            const s0 = (0, utils_js_1.rotr)(W15, 7) ^ (0, utils_js_1.rotr)(W15, 18) ^ (W15 >>> 3);
            const s1 = (0, utils_js_1.rotr)(W2, 17) ^ (0, utils_js_1.rotr)(W2, 19) ^ (W2 >>> 10);
            SHA256_W[i] = (s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16]) | 0;
        }
        // Compression function main loop, 64 rounds
        let { A, B, C, D, E, F, G, H } = this;
        for (let i = 0; i < 64; i++) {
            const sigma1 = (0, utils_js_1.rotr)(E, 6) ^ (0, utils_js_1.rotr)(E, 11) ^ (0, utils_js_1.rotr)(E, 25);
            const T1 = (H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i]) | 0;
            const sigma0 = (0, utils_js_1.rotr)(A, 2) ^ (0, utils_js_1.rotr)(A, 13) ^ (0, utils_js_1.rotr)(A, 22);
            const T2 = (sigma0 + Maj(A, B, C)) | 0;
            H = G;
            G = F;
            F = E;
            E = (D + T1) | 0;
            D = C;
            C = B;
            B = A;
            A = (T1 + T2) | 0;
        }
        // Add the compressed chunk to the current hash value
        A = (A + this.A) | 0;
        B = (B + this.B) | 0;
        C = (C + this.C) | 0;
        D = (D + this.D) | 0;
        E = (E + this.E) | 0;
        F = (F + this.F) | 0;
        G = (G + this.G) | 0;
        H = (H + this.H) | 0;
        this.set(A, B, C, D, E, F, G, H);
    }
    roundClean() {
        SHA256_W.fill(0);
    }
    destroy() {
        this.set(0, 0, 0, 0, 0, 0, 0, 0);
        this.buffer.fill(0);
    }
}
// Constants from https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
class SHA224 extends SHA256 {
    constructor() {
        super();
        this.A = 0xc1059ed8 | 0;
        this.B = 0x367cd507 | 0;
        this.C = 0x3070dd17 | 0;
        this.D = 0xf70e5939 | 0;
        this.E = 0xffc00b31 | 0;
        this.F = 0x68581511 | 0;
        this.G = 0x64f98fa7 | 0;
        this.H = 0xbefa4fa4 | 0;
        this.outputLen = 28;
    }
}
/**
 * SHA2-256 hash function
 * @param message - data that would be hashed
 */
exports.sha256 = (0, utils_js_1.wrapConstructor)(() => new SHA256());
exports.sha224 = (0, utils_js_1.wrapConstructor)(() => new SHA224());

},{"./_sha2.js":3,"./utils.js":12}],11:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sha384 = exports.sha512_256 = exports.sha512_224 = exports.sha512 = exports.SHA512 = void 0;
const _sha2_js_1 = require("./_sha2.js");
const _u64_js_1 = require("./_u64.js");
const utils_js_1 = require("./utils.js");
// Round contants (first 32 bits of the fractional parts of the cube roots of the first 80 primes 2..409):
// prettier-ignore
const [SHA512_Kh, SHA512_Kl] = /* @__PURE__ */ (() => _u64_js_1.default.split([
    '0x428a2f98d728ae22', '0x7137449123ef65cd', '0xb5c0fbcfec4d3b2f', '0xe9b5dba58189dbbc',
    '0x3956c25bf348b538', '0x59f111f1b605d019', '0x923f82a4af194f9b', '0xab1c5ed5da6d8118',
    '0xd807aa98a3030242', '0x12835b0145706fbe', '0x243185be4ee4b28c', '0x550c7dc3d5ffb4e2',
    '0x72be5d74f27b896f', '0x80deb1fe3b1696b1', '0x9bdc06a725c71235', '0xc19bf174cf692694',
    '0xe49b69c19ef14ad2', '0xefbe4786384f25e3', '0x0fc19dc68b8cd5b5', '0x240ca1cc77ac9c65',
    '0x2de92c6f592b0275', '0x4a7484aa6ea6e483', '0x5cb0a9dcbd41fbd4', '0x76f988da831153b5',
    '0x983e5152ee66dfab', '0xa831c66d2db43210', '0xb00327c898fb213f', '0xbf597fc7beef0ee4',
    '0xc6e00bf33da88fc2', '0xd5a79147930aa725', '0x06ca6351e003826f', '0x142929670a0e6e70',
    '0x27b70a8546d22ffc', '0x2e1b21385c26c926', '0x4d2c6dfc5ac42aed', '0x53380d139d95b3df',
    '0x650a73548baf63de', '0x766a0abb3c77b2a8', '0x81c2c92e47edaee6', '0x92722c851482353b',
    '0xa2bfe8a14cf10364', '0xa81a664bbc423001', '0xc24b8b70d0f89791', '0xc76c51a30654be30',
    '0xd192e819d6ef5218', '0xd69906245565a910', '0xf40e35855771202a', '0x106aa07032bbd1b8',
    '0x19a4c116b8d2d0c8', '0x1e376c085141ab53', '0x2748774cdf8eeb99', '0x34b0bcb5e19b48a8',
    '0x391c0cb3c5c95a63', '0x4ed8aa4ae3418acb', '0x5b9cca4f7763e373', '0x682e6ff3d6b2b8a3',
    '0x748f82ee5defb2fc', '0x78a5636f43172f60', '0x84c87814a1f0ab72', '0x8cc702081a6439ec',
    '0x90befffa23631e28', '0xa4506cebde82bde9', '0xbef9a3f7b2c67915', '0xc67178f2e372532b',
    '0xca273eceea26619c', '0xd186b8c721c0c207', '0xeada7dd6cde0eb1e', '0xf57d4f7fee6ed178',
    '0x06f067aa72176fba', '0x0a637dc5a2c898a6', '0x113f9804bef90dae', '0x1b710b35131c471b',
    '0x28db77f523047d84', '0x32caab7b40c72493', '0x3c9ebe0a15c9bebc', '0x431d67c49c100d4c',
    '0x4cc5d4becb3e42b6', '0x597f299cfc657e2a', '0x5fcb6fab3ad6faec', '0x6c44198c4a475817'
].map(n => BigInt(n))))();
// Temporary buffer, not used to store anything between runs
const SHA512_W_H = /* @__PURE__ */ new Uint32Array(80);
const SHA512_W_L = /* @__PURE__ */ new Uint32Array(80);
class SHA512 extends _sha2_js_1.SHA2 {
    constructor() {
        super(128, 64, 16, false);
        // We cannot use array here since array allows indexing by variable which means optimizer/compiler cannot use registers.
        // Also looks cleaner and easier to verify with spec.
        // Initial state (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
        // h -- high 32 bits, l -- low 32 bits
        this.Ah = 0x6a09e667 | 0;
        this.Al = 0xf3bcc908 | 0;
        this.Bh = 0xbb67ae85 | 0;
        this.Bl = 0x84caa73b | 0;
        this.Ch = 0x3c6ef372 | 0;
        this.Cl = 0xfe94f82b | 0;
        this.Dh = 0xa54ff53a | 0;
        this.Dl = 0x5f1d36f1 | 0;
        this.Eh = 0x510e527f | 0;
        this.El = 0xade682d1 | 0;
        this.Fh = 0x9b05688c | 0;
        this.Fl = 0x2b3e6c1f | 0;
        this.Gh = 0x1f83d9ab | 0;
        this.Gl = 0xfb41bd6b | 0;
        this.Hh = 0x5be0cd19 | 0;
        this.Hl = 0x137e2179 | 0;
    }
    // prettier-ignore
    get() {
        const { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
        return [Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl];
    }
    // prettier-ignore
    set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl) {
        this.Ah = Ah | 0;
        this.Al = Al | 0;
        this.Bh = Bh | 0;
        this.Bl = Bl | 0;
        this.Ch = Ch | 0;
        this.Cl = Cl | 0;
        this.Dh = Dh | 0;
        this.Dl = Dl | 0;
        this.Eh = Eh | 0;
        this.El = El | 0;
        this.Fh = Fh | 0;
        this.Fl = Fl | 0;
        this.Gh = Gh | 0;
        this.Gl = Gl | 0;
        this.Hh = Hh | 0;
        this.Hl = Hl | 0;
    }
    process(view, offset) {
        // Extend the first 16 words into the remaining 64 words w[16..79] of the message schedule array
        for (let i = 0; i < 16; i++, offset += 4) {
            SHA512_W_H[i] = view.getUint32(offset);
            SHA512_W_L[i] = view.getUint32((offset += 4));
        }
        for (let i = 16; i < 80; i++) {
            // s0 := (w[i-15] rightrotate 1) xor (w[i-15] rightrotate 8) xor (w[i-15] rightshift 7)
            const W15h = SHA512_W_H[i - 15] | 0;
            const W15l = SHA512_W_L[i - 15] | 0;
            const s0h = _u64_js_1.default.rotrSH(W15h, W15l, 1) ^ _u64_js_1.default.rotrSH(W15h, W15l, 8) ^ _u64_js_1.default.shrSH(W15h, W15l, 7);
            const s0l = _u64_js_1.default.rotrSL(W15h, W15l, 1) ^ _u64_js_1.default.rotrSL(W15h, W15l, 8) ^ _u64_js_1.default.shrSL(W15h, W15l, 7);
            // s1 := (w[i-2] rightrotate 19) xor (w[i-2] rightrotate 61) xor (w[i-2] rightshift 6)
            const W2h = SHA512_W_H[i - 2] | 0;
            const W2l = SHA512_W_L[i - 2] | 0;
            const s1h = _u64_js_1.default.rotrSH(W2h, W2l, 19) ^ _u64_js_1.default.rotrBH(W2h, W2l, 61) ^ _u64_js_1.default.shrSH(W2h, W2l, 6);
            const s1l = _u64_js_1.default.rotrSL(W2h, W2l, 19) ^ _u64_js_1.default.rotrBL(W2h, W2l, 61) ^ _u64_js_1.default.shrSL(W2h, W2l, 6);
            // SHA256_W[i] = s0 + s1 + SHA256_W[i - 7] + SHA256_W[i - 16];
            const SUMl = _u64_js_1.default.add4L(s0l, s1l, SHA512_W_L[i - 7], SHA512_W_L[i - 16]);
            const SUMh = _u64_js_1.default.add4H(SUMl, s0h, s1h, SHA512_W_H[i - 7], SHA512_W_H[i - 16]);
            SHA512_W_H[i] = SUMh | 0;
            SHA512_W_L[i] = SUMl | 0;
        }
        let { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
        // Compression function main loop, 80 rounds
        for (let i = 0; i < 80; i++) {
            // S1 := (e rightrotate 14) xor (e rightrotate 18) xor (e rightrotate 41)
            const sigma1h = _u64_js_1.default.rotrSH(Eh, El, 14) ^ _u64_js_1.default.rotrSH(Eh, El, 18) ^ _u64_js_1.default.rotrBH(Eh, El, 41);
            const sigma1l = _u64_js_1.default.rotrSL(Eh, El, 14) ^ _u64_js_1.default.rotrSL(Eh, El, 18) ^ _u64_js_1.default.rotrBL(Eh, El, 41);
            //const T1 = (H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i]) | 0;
            const CHIh = (Eh & Fh) ^ (~Eh & Gh);
            const CHIl = (El & Fl) ^ (~El & Gl);
            // T1 = H + sigma1 + Chi(E, F, G) + SHA512_K[i] + SHA512_W[i]
            // prettier-ignore
            const T1ll = _u64_js_1.default.add5L(Hl, sigma1l, CHIl, SHA512_Kl[i], SHA512_W_L[i]);
            const T1h = _u64_js_1.default.add5H(T1ll, Hh, sigma1h, CHIh, SHA512_Kh[i], SHA512_W_H[i]);
            const T1l = T1ll | 0;
            // S0 := (a rightrotate 28) xor (a rightrotate 34) xor (a rightrotate 39)
            const sigma0h = _u64_js_1.default.rotrSH(Ah, Al, 28) ^ _u64_js_1.default.rotrBH(Ah, Al, 34) ^ _u64_js_1.default.rotrBH(Ah, Al, 39);
            const sigma0l = _u64_js_1.default.rotrSL(Ah, Al, 28) ^ _u64_js_1.default.rotrBL(Ah, Al, 34) ^ _u64_js_1.default.rotrBL(Ah, Al, 39);
            const MAJh = (Ah & Bh) ^ (Ah & Ch) ^ (Bh & Ch);
            const MAJl = (Al & Bl) ^ (Al & Cl) ^ (Bl & Cl);
            Hh = Gh | 0;
            Hl = Gl | 0;
            Gh = Fh | 0;
            Gl = Fl | 0;
            Fh = Eh | 0;
            Fl = El | 0;
            ({ h: Eh, l: El } = _u64_js_1.default.add(Dh | 0, Dl | 0, T1h | 0, T1l | 0));
            Dh = Ch | 0;
            Dl = Cl | 0;
            Ch = Bh | 0;
            Cl = Bl | 0;
            Bh = Ah | 0;
            Bl = Al | 0;
            const All = _u64_js_1.default.add3L(T1l, sigma0l, MAJl);
            Ah = _u64_js_1.default.add3H(All, T1h, sigma0h, MAJh);
            Al = All | 0;
        }
        // Add the compressed chunk to the current hash value
        ({ h: Ah, l: Al } = _u64_js_1.default.add(this.Ah | 0, this.Al | 0, Ah | 0, Al | 0));
        ({ h: Bh, l: Bl } = _u64_js_1.default.add(this.Bh | 0, this.Bl | 0, Bh | 0, Bl | 0));
        ({ h: Ch, l: Cl } = _u64_js_1.default.add(this.Ch | 0, this.Cl | 0, Ch | 0, Cl | 0));
        ({ h: Dh, l: Dl } = _u64_js_1.default.add(this.Dh | 0, this.Dl | 0, Dh | 0, Dl | 0));
        ({ h: Eh, l: El } = _u64_js_1.default.add(this.Eh | 0, this.El | 0, Eh | 0, El | 0));
        ({ h: Fh, l: Fl } = _u64_js_1.default.add(this.Fh | 0, this.Fl | 0, Fh | 0, Fl | 0));
        ({ h: Gh, l: Gl } = _u64_js_1.default.add(this.Gh | 0, this.Gl | 0, Gh | 0, Gl | 0));
        ({ h: Hh, l: Hl } = _u64_js_1.default.add(this.Hh | 0, this.Hl | 0, Hh | 0, Hl | 0));
        this.set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl);
    }
    roundClean() {
        SHA512_W_H.fill(0);
        SHA512_W_L.fill(0);
    }
    destroy() {
        this.buffer.fill(0);
        this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    }
}
exports.SHA512 = SHA512;
class SHA512_224 extends SHA512 {
    constructor() {
        super();
        // h -- high 32 bits, l -- low 32 bits
        this.Ah = 0x8c3d37c8 | 0;
        this.Al = 0x19544da2 | 0;
        this.Bh = 0x73e19966 | 0;
        this.Bl = 0x89dcd4d6 | 0;
        this.Ch = 0x1dfab7ae | 0;
        this.Cl = 0x32ff9c82 | 0;
        this.Dh = 0x679dd514 | 0;
        this.Dl = 0x582f9fcf | 0;
        this.Eh = 0x0f6d2b69 | 0;
        this.El = 0x7bd44da8 | 0;
        this.Fh = 0x77e36f73 | 0;
        this.Fl = 0x04c48942 | 0;
        this.Gh = 0x3f9d85a8 | 0;
        this.Gl = 0x6a1d36c8 | 0;
        this.Hh = 0x1112e6ad | 0;
        this.Hl = 0x91d692a1 | 0;
        this.outputLen = 28;
    }
}
class SHA512_256 extends SHA512 {
    constructor() {
        super();
        // h -- high 32 bits, l -- low 32 bits
        this.Ah = 0x22312194 | 0;
        this.Al = 0xfc2bf72c | 0;
        this.Bh = 0x9f555fa3 | 0;
        this.Bl = 0xc84c64c2 | 0;
        this.Ch = 0x2393b86b | 0;
        this.Cl = 0x6f53b151 | 0;
        this.Dh = 0x96387719 | 0;
        this.Dl = 0x5940eabd | 0;
        this.Eh = 0x96283ee2 | 0;
        this.El = 0xa88effe3 | 0;
        this.Fh = 0xbe5e1e25 | 0;
        this.Fl = 0x53863992 | 0;
        this.Gh = 0x2b0199fc | 0;
        this.Gl = 0x2c85b8aa | 0;
        this.Hh = 0x0eb72ddc | 0;
        this.Hl = 0x81c52ca2 | 0;
        this.outputLen = 32;
    }
}
class SHA384 extends SHA512 {
    constructor() {
        super();
        // h -- high 32 bits, l -- low 32 bits
        this.Ah = 0xcbbb9d5d | 0;
        this.Al = 0xc1059ed8 | 0;
        this.Bh = 0x629a292a | 0;
        this.Bl = 0x367cd507 | 0;
        this.Ch = 0x9159015a | 0;
        this.Cl = 0x3070dd17 | 0;
        this.Dh = 0x152fecd8 | 0;
        this.Dl = 0xf70e5939 | 0;
        this.Eh = 0x67332667 | 0;
        this.El = 0xffc00b31 | 0;
        this.Fh = 0x8eb44a87 | 0;
        this.Fl = 0x68581511 | 0;
        this.Gh = 0xdb0c2e0d | 0;
        this.Gl = 0x64f98fa7 | 0;
        this.Hh = 0x47b5481d | 0;
        this.Hl = 0xbefa4fa4 | 0;
        this.outputLen = 48;
    }
}
exports.sha512 = (0, utils_js_1.wrapConstructor)(() => new SHA512());
exports.sha512_224 = (0, utils_js_1.wrapConstructor)(() => new SHA512_224());
exports.sha512_256 = (0, utils_js_1.wrapConstructor)(() => new SHA512_256());
exports.sha384 = (0, utils_js_1.wrapConstructor)(() => new SHA384());

},{"./_sha2.js":3,"./_u64.js":4,"./utils.js":12}],12:[function(require,module,exports){
"use strict";
/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
Object.defineProperty(exports, "__esModule", { value: true });
exports.randomBytes = exports.wrapXOFConstructorWithOpts = exports.wrapConstructorWithOpts = exports.wrapConstructor = exports.checkOpts = exports.Hash = exports.concatBytes = exports.toBytes = exports.utf8ToBytes = exports.asyncLoop = exports.nextTick = exports.hexToBytes = exports.bytesToHex = exports.isLE = exports.rotr = exports.createView = exports.u32 = exports.u8 = void 0;
// We use WebCrypto aka globalThis.crypto, which exists in browsers and node.js 16+.
// node.js versions earlier than v19 don't declare it in global scope.
// For node.js, package.json#exports field mapping rewrites import
// from `crypto` to `cryptoNode`, which imports native module.
// Makes the utils un-importable in browsers without a bundler.
// Once node.js 18 is deprecated (2025-04-30), we can just drop the import.
const crypto_1 = require("@noble/hashes/crypto");
// Cast array to different type
const u8 = (arr) => new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
exports.u8 = u8;
const u32 = (arr) => new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
exports.u32 = u32;
function isBytes(a) {
    return (a instanceof Uint8Array ||
        (a != null && typeof a === 'object' && a.constructor.name === 'Uint8Array'));
}
// Cast array to view
const createView = (arr) => new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
exports.createView = createView;
// The rotate right (circular right shift) operation for uint32
const rotr = (word, shift) => (word << (32 - shift)) | (word >>> shift);
exports.rotr = rotr;
// big-endian hardware is rare. Just in case someone still decides to run hashes:
// early-throw an error because we don't support BE yet.
// Other libraries would silently corrupt the data instead of throwing an error,
// when they don't support it.
exports.isLE = new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44;
if (!exports.isLE)
    throw new Error('Non little-endian hardware is not supported');
// Array where index 0xf0 (240) is mapped to string 'f0'
const hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));
/**
 * @example bytesToHex(Uint8Array.from([0xca, 0xfe, 0x01, 0x23])) // 'cafe0123'
 */
function bytesToHex(bytes) {
    if (!isBytes(bytes))
        throw new Error('Uint8Array expected');
    // pre-caching improves the speed 6x
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
        hex += hexes[bytes[i]];
    }
    return hex;
}
exports.bytesToHex = bytesToHex;
// We use optimized technique to convert hex string to byte array
const asciis = { _0: 48, _9: 57, _A: 65, _F: 70, _a: 97, _f: 102 };
function asciiToBase16(char) {
    if (char >= asciis._0 && char <= asciis._9)
        return char - asciis._0;
    if (char >= asciis._A && char <= asciis._F)
        return char - (asciis._A - 10);
    if (char >= asciis._a && char <= asciis._f)
        return char - (asciis._a - 10);
    return;
}
/**
 * @example hexToBytes('cafe0123') // Uint8Array.from([0xca, 0xfe, 0x01, 0x23])
 */
function hexToBytes(hex) {
    if (typeof hex !== 'string')
        throw new Error('hex string expected, got ' + typeof hex);
    const hl = hex.length;
    const al = hl / 2;
    if (hl % 2)
        throw new Error('padded hex string expected, got unpadded hex of length ' + hl);
    const array = new Uint8Array(al);
    for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
        const n1 = asciiToBase16(hex.charCodeAt(hi));
        const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
        if (n1 === undefined || n2 === undefined) {
            const char = hex[hi] + hex[hi + 1];
            throw new Error('hex string expected, got non-hex character "' + char + '" at index ' + hi);
        }
        array[ai] = n1 * 16 + n2;
    }
    return array;
}
exports.hexToBytes = hexToBytes;
// There is no setImmediate in browser and setTimeout is slow.
// call of async fn will return Promise, which will be fullfiled only on
// next scheduler queue processing step and this is exactly what we need.
const nextTick = async () => { };
exports.nextTick = nextTick;
// Returns control to thread each 'tick' ms to avoid blocking
async function asyncLoop(iters, tick, cb) {
    let ts = Date.now();
    for (let i = 0; i < iters; i++) {
        cb(i);
        // Date.now() is not monotonic, so in case if clock goes backwards we return return control too
        const diff = Date.now() - ts;
        if (diff >= 0 && diff < tick)
            continue;
        await (0, exports.nextTick)();
        ts += diff;
    }
}
exports.asyncLoop = asyncLoop;
/**
 * @example utf8ToBytes('abc') // new Uint8Array([97, 98, 99])
 */
function utf8ToBytes(str) {
    if (typeof str !== 'string')
        throw new Error(`utf8ToBytes expected string, got ${typeof str}`);
    return new Uint8Array(new TextEncoder().encode(str)); // https://bugzil.la/1681809
}
exports.utf8ToBytes = utf8ToBytes;
/**
 * Normalizes (non-hex) string or Uint8Array to Uint8Array.
 * Warning: when Uint8Array is passed, it would NOT get copied.
 * Keep in mind for future mutable operations.
 */
function toBytes(data) {
    if (typeof data === 'string')
        data = utf8ToBytes(data);
    if (!isBytes(data))
        throw new Error(`expected Uint8Array, got ${typeof data}`);
    return data;
}
exports.toBytes = toBytes;
/**
 * Copies several Uint8Arrays into one.
 */
function concatBytes(...arrays) {
    let sum = 0;
    for (let i = 0; i < arrays.length; i++) {
        const a = arrays[i];
        if (!isBytes(a))
            throw new Error('Uint8Array expected');
        sum += a.length;
    }
    const res = new Uint8Array(sum);
    for (let i = 0, pad = 0; i < arrays.length; i++) {
        const a = arrays[i];
        res.set(a, pad);
        pad += a.length;
    }
    return res;
}
exports.concatBytes = concatBytes;
// For runtime check if class implements interface
class Hash {
    // Safe version that clones internal state
    clone() {
        return this._cloneInto();
    }
}
exports.Hash = Hash;
const toStr = {}.toString;
function checkOpts(defaults, opts) {
    if (opts !== undefined && toStr.call(opts) !== '[object Object]')
        throw new Error('Options should be object or undefined');
    const merged = Object.assign(defaults, opts);
    return merged;
}
exports.checkOpts = checkOpts;
function wrapConstructor(hashCons) {
    const hashC = (msg) => hashCons().update(toBytes(msg)).digest();
    const tmp = hashCons();
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.create = () => hashCons();
    return hashC;
}
exports.wrapConstructor = wrapConstructor;
function wrapConstructorWithOpts(hashCons) {
    const hashC = (msg, opts) => hashCons(opts).update(toBytes(msg)).digest();
    const tmp = hashCons({});
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.create = (opts) => hashCons(opts);
    return hashC;
}
exports.wrapConstructorWithOpts = wrapConstructorWithOpts;
function wrapXOFConstructorWithOpts(hashCons) {
    const hashC = (msg, opts) => hashCons(opts).update(toBytes(msg)).digest();
    const tmp = hashCons({});
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.create = (opts) => hashCons(opts);
    return hashC;
}
exports.wrapXOFConstructorWithOpts = wrapXOFConstructorWithOpts;
/**
 * Secure PRNG. Uses `crypto.getRandomValues`, which defers to OS.
 */
function randomBytes(bytesLength = 32) {
    if (crypto_1.crypto && typeof crypto_1.crypto.getRandomValues === 'function') {
        return crypto_1.crypto.getRandomValues(new Uint8Array(bytesLength));
    }
    throw new Error('crypto.getRandomValues must be defined');
}
exports.randomBytes = randomBytes;

},{"@noble/hashes/crypto":5}],13:[function(require,module,exports){
'use strict';
Object.defineProperty(exports, "__esModule", { value: true });
exports.bech32m = exports.bech32 = void 0;
const ALPHABET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const ALPHABET_MAP = {};
for (let z = 0; z < ALPHABET.length; z++) {
    const x = ALPHABET.charAt(z);
    ALPHABET_MAP[x] = z;
}
function polymodStep(pre) {
    const b = pre >> 25;
    return (((pre & 0x1ffffff) << 5) ^
        (-((b >> 0) & 1) & 0x3b6a57b2) ^
        (-((b >> 1) & 1) & 0x26508e6d) ^
        (-((b >> 2) & 1) & 0x1ea119fa) ^
        (-((b >> 3) & 1) & 0x3d4233dd) ^
        (-((b >> 4) & 1) & 0x2a1462b3));
}
function prefixChk(prefix) {
    let chk = 1;
    for (let i = 0; i < prefix.length; ++i) {
        const c = prefix.charCodeAt(i);
        if (c < 33 || c > 126)
            return 'Invalid prefix (' + prefix + ')';
        chk = polymodStep(chk) ^ (c >> 5);
    }
    chk = polymodStep(chk);
    for (let i = 0; i < prefix.length; ++i) {
        const v = prefix.charCodeAt(i);
        chk = polymodStep(chk) ^ (v & 0x1f);
    }
    return chk;
}
function convert(data, inBits, outBits, pad) {
    let value = 0;
    let bits = 0;
    const maxV = (1 << outBits) - 1;
    const result = [];
    for (let i = 0; i < data.length; ++i) {
        value = (value << inBits) | data[i];
        bits += inBits;
        while (bits >= outBits) {
            bits -= outBits;
            result.push((value >> bits) & maxV);
        }
    }
    if (pad) {
        if (bits > 0) {
            result.push((value << (outBits - bits)) & maxV);
        }
    }
    else {
        if (bits >= inBits)
            return 'Excess padding';
        if ((value << (outBits - bits)) & maxV)
            return 'Non-zero padding';
    }
    return result;
}
function toWords(bytes) {
    return convert(bytes, 8, 5, true);
}
function fromWordsUnsafe(words) {
    const res = convert(words, 5, 8, false);
    if (Array.isArray(res))
        return res;
}
function fromWords(words) {
    const res = convert(words, 5, 8, false);
    if (Array.isArray(res))
        return res;
    throw new Error(res);
}
function getLibraryFromEncoding(encoding) {
    let ENCODING_CONST;
    if (encoding === 'bech32') {
        ENCODING_CONST = 1;
    }
    else {
        ENCODING_CONST = 0x2bc830a3;
    }
    function encode(prefix, words, LIMIT) {
        LIMIT = LIMIT || 90;
        if (prefix.length + 7 + words.length > LIMIT)
            throw new TypeError('Exceeds length limit');
        prefix = prefix.toLowerCase();
        // determine chk mod
        let chk = prefixChk(prefix);
        if (typeof chk === 'string')
            throw new Error(chk);
        let result = prefix + '1';
        for (let i = 0; i < words.length; ++i) {
            const x = words[i];
            if (x >> 5 !== 0)
                throw new Error('Non 5-bit word');
            chk = polymodStep(chk) ^ x;
            result += ALPHABET.charAt(x);
        }
        for (let i = 0; i < 6; ++i) {
            chk = polymodStep(chk);
        }
        chk ^= ENCODING_CONST;
        for (let i = 0; i < 6; ++i) {
            const v = (chk >> ((5 - i) * 5)) & 0x1f;
            result += ALPHABET.charAt(v);
        }
        return result;
    }
    function __decode(str, LIMIT) {
        LIMIT = LIMIT || 90;
        if (str.length < 8)
            return str + ' too short';
        if (str.length > LIMIT)
            return 'Exceeds length limit';
        // don't allow mixed case
        const lowered = str.toLowerCase();
        const uppered = str.toUpperCase();
        if (str !== lowered && str !== uppered)
            return 'Mixed-case string ' + str;
        str = lowered;
        const split = str.lastIndexOf('1');
        if (split === -1)
            return 'No separator character for ' + str;
        if (split === 0)
            return 'Missing prefix for ' + str;
        const prefix = str.slice(0, split);
        const wordChars = str.slice(split + 1);
        if (wordChars.length < 6)
            return 'Data too short';
        let chk = prefixChk(prefix);
        if (typeof chk === 'string')
            return chk;
        const words = [];
        for (let i = 0; i < wordChars.length; ++i) {
            const c = wordChars.charAt(i);
            const v = ALPHABET_MAP[c];
            if (v === undefined)
                return 'Unknown character ' + c;
            chk = polymodStep(chk) ^ v;
            // not in the checksum?
            if (i + 6 >= wordChars.length)
                continue;
            words.push(v);
        }
        if (chk !== ENCODING_CONST)
            return 'Invalid checksum for ' + str;
        return { prefix, words };
    }
    function decodeUnsafe(str, LIMIT) {
        const res = __decode(str, LIMIT);
        if (typeof res === 'object')
            return res;
    }
    function decode(str, LIMIT) {
        const res = __decode(str, LIMIT);
        if (typeof res === 'object')
            return res;
        throw new Error(res);
    }
    return {
        decodeUnsafe,
        decode,
        encode,
        toWords,
        fromWordsUnsafe,
        fromWords,
    };
}
exports.bech32 = getLibraryFromEncoding('bech32');
exports.bech32m = getLibraryFromEncoding('bech32m');

},{}],14:[function(require,module,exports){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const parser_1 = require('../parser');
function combine(psbts) {
  const self = psbts[0];
  const selfKeyVals = parser_1.psbtToKeyVals(self);
  const others = psbts.slice(1);
  if (others.length === 0) throw new Error('Combine: Nothing to combine');
  const selfTx = getTx(self);
  if (selfTx === undefined) {
    throw new Error('Combine: Self missing transaction');
  }
  const selfGlobalSet = getKeySet(selfKeyVals.globalKeyVals);
  const selfInputSets = selfKeyVals.inputKeyVals.map(getKeySet);
  const selfOutputSets = selfKeyVals.outputKeyVals.map(getKeySet);
  for (const other of others) {
    const otherTx = getTx(other);
    if (
      otherTx === undefined ||
      !otherTx.toBuffer().equals(selfTx.toBuffer())
    ) {
      throw new Error(
        'Combine: One of the Psbts does not have the same transaction.',
      );
    }
    const otherKeyVals = parser_1.psbtToKeyVals(other);
    const otherGlobalSet = getKeySet(otherKeyVals.globalKeyVals);
    otherGlobalSet.forEach(
      keyPusher(
        selfGlobalSet,
        selfKeyVals.globalKeyVals,
        otherKeyVals.globalKeyVals,
      ),
    );
    const otherInputSets = otherKeyVals.inputKeyVals.map(getKeySet);
    otherInputSets.forEach((inputSet, idx) =>
      inputSet.forEach(
        keyPusher(
          selfInputSets[idx],
          selfKeyVals.inputKeyVals[idx],
          otherKeyVals.inputKeyVals[idx],
        ),
      ),
    );
    const otherOutputSets = otherKeyVals.outputKeyVals.map(getKeySet);
    otherOutputSets.forEach((outputSet, idx) =>
      outputSet.forEach(
        keyPusher(
          selfOutputSets[idx],
          selfKeyVals.outputKeyVals[idx],
          otherKeyVals.outputKeyVals[idx],
        ),
      ),
    );
  }
  return parser_1.psbtFromKeyVals(selfTx, {
    globalMapKeyVals: selfKeyVals.globalKeyVals,
    inputKeyVals: selfKeyVals.inputKeyVals,
    outputKeyVals: selfKeyVals.outputKeyVals,
  });
}
exports.combine = combine;
function keyPusher(selfSet, selfKeyVals, otherKeyVals) {
  return key => {
    if (selfSet.has(key)) return;
    const newKv = otherKeyVals.filter(kv => kv.key.toString('hex') === key)[0];
    selfKeyVals.push(newKv);
    selfSet.add(key);
  };
}
function getTx(psbt) {
  return psbt.globalMap.unsignedTx;
}
function getKeySet(keyVals) {
  const set = new Set();
  keyVals.forEach(keyVal => {
    const hex = keyVal.key.toString('hex');
    if (set.has(hex))
      throw new Error('Combine: KeyValue Map keys should be unique');
    set.add(hex);
  });
  return set;
}

},{"../parser":39}],15:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const typeFields_1 = require('../../typeFields');
const range = n => [...Array(n).keys()];
function decode(keyVal) {
  if (keyVal.key[0] !== typeFields_1.GlobalTypes.GLOBAL_XPUB) {
    throw new Error(
      'Decode Error: could not decode globalXpub with key 0x' +
        keyVal.key.toString('hex'),
    );
  }
  if (keyVal.key.length !== 79 || ![2, 3].includes(keyVal.key[46])) {
    throw new Error(
      'Decode Error: globalXpub has invalid extended pubkey in key 0x' +
        keyVal.key.toString('hex'),
    );
  }
  if ((keyVal.value.length / 4) % 1 !== 0) {
    throw new Error(
      'Decode Error: Global GLOBAL_XPUB value length should be multiple of 4',
    );
  }
  const extendedPubkey = keyVal.key.slice(1);
  const data = {
    masterFingerprint: keyVal.value.slice(0, 4),
    extendedPubkey,
    path: 'm',
  };
  for (const i of range(keyVal.value.length / 4 - 1)) {
    const val = keyVal.value.readUInt32LE(i * 4 + 4);
    const isHard = !!(val & 0x80000000);
    const idx = val & 0x7fffffff;
    data.path += '/' + idx.toString(10) + (isHard ? "'" : '');
  }
  return data;
}
exports.decode = decode;
function encode(data) {
  const head = Buffer.from([typeFields_1.GlobalTypes.GLOBAL_XPUB]);
  const key = Buffer.concat([head, data.extendedPubkey]);
  const splitPath = data.path.split('/');
  const value = Buffer.allocUnsafe(splitPath.length * 4);
  data.masterFingerprint.copy(value, 0);
  let offset = 4;
  splitPath.slice(1).forEach(level => {
    const isHard = level.slice(-1) === "'";
    let num = 0x7fffffff & parseInt(isHard ? level.slice(0, -1) : level, 10);
    if (isHard) num += 0x80000000;
    value.writeUInt32LE(num, offset);
    offset += 4;
  });
  return {
    key,
    value,
  };
}
exports.encode = encode;
exports.expected =
  '{ masterFingerprint: Buffer; extendedPubkey: Buffer; path: string; }';
function check(data) {
  const epk = data.extendedPubkey;
  const mfp = data.masterFingerprint;
  const p = data.path;
  return (
    Buffer.isBuffer(epk) &&
    epk.length === 78 &&
    [2, 3].indexOf(epk[45]) > -1 &&
    Buffer.isBuffer(mfp) &&
    mfp.length === 4 &&
    typeof p === 'string' &&
    !!p.match(/^m(\/\d+'?)*$/)
  );
}
exports.check = check;
function canAddToArray(array, item, dupeSet) {
  const dupeString = item.extendedPubkey.toString('hex');
  if (dupeSet.has(dupeString)) return false;
  dupeSet.add(dupeString);
  return (
    array.filter(v => v.extendedPubkey.equals(item.extendedPubkey)).length === 0
  );
}
exports.canAddToArray = canAddToArray;

}).call(this)}).call(this,require("buffer").Buffer)
},{"../../typeFields":42,"buffer":97}],16:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const typeFields_1 = require('../../typeFields');
function encode(data) {
  return {
    key: Buffer.from([typeFields_1.GlobalTypes.UNSIGNED_TX]),
    value: data.toBuffer(),
  };
}
exports.encode = encode;

}).call(this)}).call(this,require("buffer").Buffer)
},{"../../typeFields":42,"buffer":97}],17:[function(require,module,exports){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const typeFields_1 = require('../typeFields');
const globalXpub = require('./global/globalXpub');
const unsignedTx = require('./global/unsignedTx');
const finalScriptSig = require('./input/finalScriptSig');
const finalScriptWitness = require('./input/finalScriptWitness');
const nonWitnessUtxo = require('./input/nonWitnessUtxo');
const partialSig = require('./input/partialSig');
const porCommitment = require('./input/porCommitment');
const sighashType = require('./input/sighashType');
const tapKeySig = require('./input/tapKeySig');
const tapLeafScript = require('./input/tapLeafScript');
const tapMerkleRoot = require('./input/tapMerkleRoot');
const tapScriptSig = require('./input/tapScriptSig');
const witnessUtxo = require('./input/witnessUtxo');
const tapTree = require('./output/tapTree');
const bip32Derivation = require('./shared/bip32Derivation');
const checkPubkey = require('./shared/checkPubkey');
const redeemScript = require('./shared/redeemScript');
const tapBip32Derivation = require('./shared/tapBip32Derivation');
const tapInternalKey = require('./shared/tapInternalKey');
const witnessScript = require('./shared/witnessScript');
const globals = {
  unsignedTx,
  globalXpub,
  // pass an Array of key bytes that require pubkey beside the key
  checkPubkey: checkPubkey.makeChecker([]),
};
exports.globals = globals;
const inputs = {
  nonWitnessUtxo,
  partialSig,
  sighashType,
  finalScriptSig,
  finalScriptWitness,
  porCommitment,
  witnessUtxo,
  bip32Derivation: bip32Derivation.makeConverter(
    typeFields_1.InputTypes.BIP32_DERIVATION,
  ),
  redeemScript: redeemScript.makeConverter(
    typeFields_1.InputTypes.REDEEM_SCRIPT,
  ),
  witnessScript: witnessScript.makeConverter(
    typeFields_1.InputTypes.WITNESS_SCRIPT,
  ),
  checkPubkey: checkPubkey.makeChecker([
    typeFields_1.InputTypes.PARTIAL_SIG,
    typeFields_1.InputTypes.BIP32_DERIVATION,
  ]),
  tapKeySig,
  tapScriptSig,
  tapLeafScript,
  tapBip32Derivation: tapBip32Derivation.makeConverter(
    typeFields_1.InputTypes.TAP_BIP32_DERIVATION,
  ),
  tapInternalKey: tapInternalKey.makeConverter(
    typeFields_1.InputTypes.TAP_INTERNAL_KEY,
  ),
  tapMerkleRoot,
};
exports.inputs = inputs;
const outputs = {
  bip32Derivation: bip32Derivation.makeConverter(
    typeFields_1.OutputTypes.BIP32_DERIVATION,
  ),
  redeemScript: redeemScript.makeConverter(
    typeFields_1.OutputTypes.REDEEM_SCRIPT,
  ),
  witnessScript: witnessScript.makeConverter(
    typeFields_1.OutputTypes.WITNESS_SCRIPT,
  ),
  checkPubkey: checkPubkey.makeChecker([
    typeFields_1.OutputTypes.BIP32_DERIVATION,
  ]),
  tapBip32Derivation: tapBip32Derivation.makeConverter(
    typeFields_1.OutputTypes.TAP_BIP32_DERIVATION,
  ),
  tapTree,
  tapInternalKey: tapInternalKey.makeConverter(
    typeFields_1.OutputTypes.TAP_INTERNAL_KEY,
  ),
};
exports.outputs = outputs;

},{"../typeFields":42,"./global/globalXpub":15,"./global/unsignedTx":16,"./input/finalScriptSig":18,"./input/finalScriptWitness":19,"./input/nonWitnessUtxo":20,"./input/partialSig":21,"./input/porCommitment":22,"./input/sighashType":23,"./input/tapKeySig":24,"./input/tapLeafScript":25,"./input/tapMerkleRoot":26,"./input/tapScriptSig":27,"./input/witnessUtxo":28,"./output/tapTree":29,"./shared/bip32Derivation":30,"./shared/checkPubkey":31,"./shared/redeemScript":32,"./shared/tapBip32Derivation":33,"./shared/tapInternalKey":34,"./shared/witnessScript":35}],18:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const typeFields_1 = require('../../typeFields');
function decode(keyVal) {
  if (keyVal.key[0] !== typeFields_1.InputTypes.FINAL_SCRIPTSIG) {
    throw new Error(
      'Decode Error: could not decode finalScriptSig with key 0x' +
        keyVal.key.toString('hex'),
    );
  }
  return keyVal.value;
}
exports.decode = decode;
function encode(data) {
  const key = Buffer.from([typeFields_1.InputTypes.FINAL_SCRIPTSIG]);
  return {
    key,
    value: data,
  };
}
exports.encode = encode;
exports.expected = 'Buffer';
function check(data) {
  return Buffer.isBuffer(data);
}
exports.check = check;
function canAdd(currentData, newData) {
  return !!currentData && !!newData && currentData.finalScriptSig === undefined;
}
exports.canAdd = canAdd;

}).call(this)}).call(this,require("buffer").Buffer)
},{"../../typeFields":42,"buffer":97}],19:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const typeFields_1 = require('../../typeFields');
function decode(keyVal) {
  if (keyVal.key[0] !== typeFields_1.InputTypes.FINAL_SCRIPTWITNESS) {
    throw new Error(
      'Decode Error: could not decode finalScriptWitness with key 0x' +
        keyVal.key.toString('hex'),
    );
  }
  return keyVal.value;
}
exports.decode = decode;
function encode(data) {
  const key = Buffer.from([typeFields_1.InputTypes.FINAL_SCRIPTWITNESS]);
  return {
    key,
    value: data,
  };
}
exports.encode = encode;
exports.expected = 'Buffer';
function check(data) {
  return Buffer.isBuffer(data);
}
exports.check = check;
function canAdd(currentData, newData) {
  return (
    !!currentData && !!newData && currentData.finalScriptWitness === undefined
  );
}
exports.canAdd = canAdd;

}).call(this)}).call(this,require("buffer").Buffer)
},{"../../typeFields":42,"buffer":97}],20:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const typeFields_1 = require('../../typeFields');
function decode(keyVal) {
  if (keyVal.key[0] !== typeFields_1.InputTypes.NON_WITNESS_UTXO) {
    throw new Error(
      'Decode Error: could not decode nonWitnessUtxo with key 0x' +
        keyVal.key.toString('hex'),
    );
  }
  return keyVal.value;
}
exports.decode = decode;
function encode(data) {
  return {
    key: Buffer.from([typeFields_1.InputTypes.NON_WITNESS_UTXO]),
    value: data,
  };
}
exports.encode = encode;
exports.expected = 'Buffer';
function check(data) {
  return Buffer.isBuffer(data);
}
exports.check = check;
function canAdd(currentData, newData) {
  return !!currentData && !!newData && currentData.nonWitnessUtxo === undefined;
}
exports.canAdd = canAdd;

}).call(this)}).call(this,require("buffer").Buffer)
},{"../../typeFields":42,"buffer":97}],21:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const typeFields_1 = require('../../typeFields');
function decode(keyVal) {
  if (keyVal.key[0] !== typeFields_1.InputTypes.PARTIAL_SIG) {
    throw new Error(
      'Decode Error: could not decode partialSig with key 0x' +
        keyVal.key.toString('hex'),
    );
  }
  if (
    !(keyVal.key.length === 34 || keyVal.key.length === 66) ||
    ![2, 3, 4].includes(keyVal.key[1])
  ) {
    throw new Error(
      'Decode Error: partialSig has invalid pubkey in key 0x' +
        keyVal.key.toString('hex'),
    );
  }
  const pubkey = keyVal.key.slice(1);
  return {
    pubkey,
    signature: keyVal.value,
  };
}
exports.decode = decode;
function encode(pSig) {
  const head = Buffer.from([typeFields_1.InputTypes.PARTIAL_SIG]);
  return {
    key: Buffer.concat([head, pSig.pubkey]),
    value: pSig.signature,
  };
}
exports.encode = encode;
exports.expected = '{ pubkey: Buffer; signature: Buffer; }';
function check(data) {
  return (
    Buffer.isBuffer(data.pubkey) &&
    Buffer.isBuffer(data.signature) &&
    [33, 65].includes(data.pubkey.length) &&
    [2, 3, 4].includes(data.pubkey[0]) &&
    isDerSigWithSighash(data.signature)
  );
}
exports.check = check;
function isDerSigWithSighash(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 9) return false;
  if (buf[0] !== 0x30) return false;
  if (buf.length !== buf[1] + 3) return false;
  if (buf[2] !== 0x02) return false;
  const rLen = buf[3];
  if (rLen > 33 || rLen < 1) return false;
  if (buf[3 + rLen + 1] !== 0x02) return false;
  const sLen = buf[3 + rLen + 2];
  if (sLen > 33 || sLen < 1) return false;
  if (buf.length !== 3 + rLen + 2 + sLen + 2) return false;
  return true;
}
function canAddToArray(array, item, dupeSet) {
  const dupeString = item.pubkey.toString('hex');
  if (dupeSet.has(dupeString)) return false;
  dupeSet.add(dupeString);
  return array.filter(v => v.pubkey.equals(item.pubkey)).length === 0;
}
exports.canAddToArray = canAddToArray;

}).call(this)}).call(this,require("buffer").Buffer)
},{"../../typeFields":42,"buffer":97}],22:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const typeFields_1 = require('../../typeFields');
function decode(keyVal) {
  if (keyVal.key[0] !== typeFields_1.InputTypes.POR_COMMITMENT) {
    throw new Error(
      'Decode Error: could not decode porCommitment with key 0x' +
        keyVal.key.toString('hex'),
    );
  }
  return keyVal.value.toString('utf8');
}
exports.decode = decode;
function encode(data) {
  const key = Buffer.from([typeFields_1.InputTypes.POR_COMMITMENT]);
  return {
    key,
    value: Buffer.from(data, 'utf8'),
  };
}
exports.encode = encode;
exports.expected = 'string';
function check(data) {
  return typeof data === 'string';
}
exports.check = check;
function canAdd(currentData, newData) {
  return !!currentData && !!newData && currentData.porCommitment === undefined;
}
exports.canAdd = canAdd;

}).call(this)}).call(this,require("buffer").Buffer)
},{"../../typeFields":42,"buffer":97}],23:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const typeFields_1 = require('../../typeFields');
function decode(keyVal) {
  if (keyVal.key[0] !== typeFields_1.InputTypes.SIGHASH_TYPE) {
    throw new Error(
      'Decode Error: could not decode sighashType with key 0x' +
        keyVal.key.toString('hex'),
    );
  }
  return keyVal.value.readUInt32LE(0);
}
exports.decode = decode;
function encode(data) {
  const key = Buffer.from([typeFields_1.InputTypes.SIGHASH_TYPE]);
  const value = Buffer.allocUnsafe(4);
  value.writeUInt32LE(data, 0);
  return {
    key,
    value,
  };
}
exports.encode = encode;
exports.expected = 'number';
function check(data) {
  return typeof data === 'number';
}
exports.check = check;
function canAdd(currentData, newData) {
  return !!currentData && !!newData && currentData.sighashType === undefined;
}
exports.canAdd = canAdd;

}).call(this)}).call(this,require("buffer").Buffer)
},{"../../typeFields":42,"buffer":97}],24:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const typeFields_1 = require('../../typeFields');
function decode(keyVal) {
  if (
    keyVal.key[0] !== typeFields_1.InputTypes.TAP_KEY_SIG ||
    keyVal.key.length !== 1
  ) {
    throw new Error(
      'Decode Error: could not decode tapKeySig with key 0x' +
        keyVal.key.toString('hex'),
    );
  }
  if (!check(keyVal.value)) {
    throw new Error(
      'Decode Error: tapKeySig not a valid 64-65-byte BIP340 signature',
    );
  }
  return keyVal.value;
}
exports.decode = decode;
function encode(value) {
  const key = Buffer.from([typeFields_1.InputTypes.TAP_KEY_SIG]);
  return { key, value };
}
exports.encode = encode;
exports.expected = 'Buffer';
function check(data) {
  return Buffer.isBuffer(data) && (data.length === 64 || data.length === 65);
}
exports.check = check;
function canAdd(currentData, newData) {
  return !!currentData && !!newData && currentData.tapKeySig === undefined;
}
exports.canAdd = canAdd;

}).call(this)}).call(this,require("buffer").Buffer)
},{"../../typeFields":42,"buffer":97}],25:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const typeFields_1 = require('../../typeFields');
function decode(keyVal) {
  if (keyVal.key[0] !== typeFields_1.InputTypes.TAP_LEAF_SCRIPT) {
    throw new Error(
      'Decode Error: could not decode tapLeafScript with key 0x' +
        keyVal.key.toString('hex'),
    );
  }
  if ((keyVal.key.length - 2) % 32 !== 0) {
    throw new Error(
      'Decode Error: tapLeafScript has invalid control block in key 0x' +
        keyVal.key.toString('hex'),
    );
  }
  const leafVersion = keyVal.value[keyVal.value.length - 1];
  if ((keyVal.key[1] & 0xfe) !== leafVersion) {
    throw new Error(
      'Decode Error: tapLeafScript bad leaf version in key 0x' +
        keyVal.key.toString('hex'),
    );
  }
  const script = keyVal.value.slice(0, -1);
  const controlBlock = keyVal.key.slice(1);
  return { controlBlock, script, leafVersion };
}
exports.decode = decode;
function encode(tScript) {
  const head = Buffer.from([typeFields_1.InputTypes.TAP_LEAF_SCRIPT]);
  const verBuf = Buffer.from([tScript.leafVersion]);
  return {
    key: Buffer.concat([head, tScript.controlBlock]),
    value: Buffer.concat([tScript.script, verBuf]),
  };
}
exports.encode = encode;
exports.expected =
  '{ controlBlock: Buffer; leafVersion: number, script: Buffer; }';
function check(data) {
  return (
    Buffer.isBuffer(data.controlBlock) &&
    (data.controlBlock.length - 1) % 32 === 0 &&
    (data.controlBlock[0] & 0xfe) === data.leafVersion &&
    Buffer.isBuffer(data.script)
  );
}
exports.check = check;
function canAddToArray(array, item, dupeSet) {
  const dupeString = item.controlBlock.toString('hex');
  if (dupeSet.has(dupeString)) return false;
  dupeSet.add(dupeString);
  return (
    array.filter(v => v.controlBlock.equals(item.controlBlock)).length === 0
  );
}
exports.canAddToArray = canAddToArray;

}).call(this)}).call(this,require("buffer").Buffer)
},{"../../typeFields":42,"buffer":97}],26:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const typeFields_1 = require('../../typeFields');
function decode(keyVal) {
  if (
    keyVal.key[0] !== typeFields_1.InputTypes.TAP_MERKLE_ROOT ||
    keyVal.key.length !== 1
  ) {
    throw new Error(
      'Decode Error: could not decode tapMerkleRoot with key 0x' +
        keyVal.key.toString('hex'),
    );
  }
  if (!check(keyVal.value)) {
    throw new Error('Decode Error: tapMerkleRoot not a 32-byte hash');
  }
  return keyVal.value;
}
exports.decode = decode;
function encode(value) {
  const key = Buffer.from([typeFields_1.InputTypes.TAP_MERKLE_ROOT]);
  return { key, value };
}
exports.encode = encode;
exports.expected = 'Buffer';
function check(data) {
  return Buffer.isBuffer(data) && data.length === 32;
}
exports.check = check;
function canAdd(currentData, newData) {
  return !!currentData && !!newData && currentData.tapMerkleRoot === undefined;
}
exports.canAdd = canAdd;

}).call(this)}).call(this,require("buffer").Buffer)
},{"../../typeFields":42,"buffer":97}],27:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const typeFields_1 = require('../../typeFields');
function decode(keyVal) {
  if (keyVal.key[0] !== typeFields_1.InputTypes.TAP_SCRIPT_SIG) {
    throw new Error(
      'Decode Error: could not decode tapScriptSig with key 0x' +
        keyVal.key.toString('hex'),
    );
  }
  if (keyVal.key.length !== 65) {
    throw new Error(
      'Decode Error: tapScriptSig has invalid key 0x' +
        keyVal.key.toString('hex'),
    );
  }
  if (keyVal.value.length !== 64 && keyVal.value.length !== 65) {
    throw new Error(
      'Decode Error: tapScriptSig has invalid signature in key 0x' +
        keyVal.key.toString('hex'),
    );
  }
  const pubkey = keyVal.key.slice(1, 33);
  const leafHash = keyVal.key.slice(33);
  return {
    pubkey,
    leafHash,
    signature: keyVal.value,
  };
}
exports.decode = decode;
function encode(tSig) {
  const head = Buffer.from([typeFields_1.InputTypes.TAP_SCRIPT_SIG]);
  return {
    key: Buffer.concat([head, tSig.pubkey, tSig.leafHash]),
    value: tSig.signature,
  };
}
exports.encode = encode;
exports.expected = '{ pubkey: Buffer; leafHash: Buffer; signature: Buffer; }';
function check(data) {
  return (
    Buffer.isBuffer(data.pubkey) &&
    Buffer.isBuffer(data.leafHash) &&
    Buffer.isBuffer(data.signature) &&
    data.pubkey.length === 32 &&
    data.leafHash.length === 32 &&
    (data.signature.length === 64 || data.signature.length === 65)
  );
}
exports.check = check;
function canAddToArray(array, item, dupeSet) {
  const dupeString =
    item.pubkey.toString('hex') + item.leafHash.toString('hex');
  if (dupeSet.has(dupeString)) return false;
  dupeSet.add(dupeString);
  return (
    array.filter(
      v => v.pubkey.equals(item.pubkey) && v.leafHash.equals(item.leafHash),
    ).length === 0
  );
}
exports.canAddToArray = canAddToArray;

}).call(this)}).call(this,require("buffer").Buffer)
},{"../../typeFields":42,"buffer":97}],28:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const typeFields_1 = require('../../typeFields');
const tools_1 = require('../tools');
const varuint = require('../varint');
function decode(keyVal) {
  if (keyVal.key[0] !== typeFields_1.InputTypes.WITNESS_UTXO) {
    throw new Error(
      'Decode Error: could not decode witnessUtxo with key 0x' +
        keyVal.key.toString('hex'),
    );
  }
  const value = tools_1.readUInt64LE(keyVal.value, 0);
  let _offset = 8;
  const scriptLen = varuint.decode(keyVal.value, _offset);
  _offset += varuint.encodingLength(scriptLen);
  const script = keyVal.value.slice(_offset);
  if (script.length !== scriptLen) {
    throw new Error('Decode Error: WITNESS_UTXO script is not proper length');
  }
  return {
    script,
    value,
  };
}
exports.decode = decode;
function encode(data) {
  const { script, value } = data;
  const varintLen = varuint.encodingLength(script.length);
  const result = Buffer.allocUnsafe(8 + varintLen + script.length);
  tools_1.writeUInt64LE(result, value, 0);
  varuint.encode(script.length, result, 8);
  script.copy(result, 8 + varintLen);
  return {
    key: Buffer.from([typeFields_1.InputTypes.WITNESS_UTXO]),
    value: result,
  };
}
exports.encode = encode;
exports.expected = '{ script: Buffer; value: number; }';
function check(data) {
  return Buffer.isBuffer(data.script) && typeof data.value === 'number';
}
exports.check = check;
function canAdd(currentData, newData) {
  return !!currentData && !!newData && currentData.witnessUtxo === undefined;
}
exports.canAdd = canAdd;

}).call(this)}).call(this,require("buffer").Buffer)
},{"../../typeFields":42,"../tools":36,"../varint":37,"buffer":97}],29:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const typeFields_1 = require('../../typeFields');
const varuint = require('../varint');
function decode(keyVal) {
  if (
    keyVal.key[0] !== typeFields_1.OutputTypes.TAP_TREE ||
    keyVal.key.length !== 1
  ) {
    throw new Error(
      'Decode Error: could not decode tapTree with key 0x' +
        keyVal.key.toString('hex'),
    );
  }
  let _offset = 0;
  const data = [];
  while (_offset < keyVal.value.length) {
    const depth = keyVal.value[_offset++];
    const leafVersion = keyVal.value[_offset++];
    const scriptLen = varuint.decode(keyVal.value, _offset);
    _offset += varuint.encodingLength(scriptLen);
    data.push({
      depth,
      leafVersion,
      script: keyVal.value.slice(_offset, _offset + scriptLen),
    });
    _offset += scriptLen;
  }
  return { leaves: data };
}
exports.decode = decode;
function encode(tree) {
  const key = Buffer.from([typeFields_1.OutputTypes.TAP_TREE]);
  const bufs = [].concat(
    ...tree.leaves.map(tapLeaf => [
      Buffer.of(tapLeaf.depth, tapLeaf.leafVersion),
      varuint.encode(tapLeaf.script.length),
      tapLeaf.script,
    ]),
  );
  return {
    key,
    value: Buffer.concat(bufs),
  };
}
exports.encode = encode;
exports.expected =
  '{ leaves: [{ depth: number; leafVersion: number, script: Buffer; }] }';
function check(data) {
  return (
    Array.isArray(data.leaves) &&
    data.leaves.every(
      tapLeaf =>
        tapLeaf.depth >= 0 &&
        tapLeaf.depth <= 128 &&
        (tapLeaf.leafVersion & 0xfe) === tapLeaf.leafVersion &&
        Buffer.isBuffer(tapLeaf.script),
    )
  );
}
exports.check = check;
function canAdd(currentData, newData) {
  return !!currentData && !!newData && currentData.tapTree === undefined;
}
exports.canAdd = canAdd;

}).call(this)}).call(this,require("buffer").Buffer)
},{"../../typeFields":42,"../varint":37,"buffer":97}],30:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const range = n => [...Array(n).keys()];
const isValidDERKey = pubkey =>
  (pubkey.length === 33 && [2, 3].includes(pubkey[0])) ||
  (pubkey.length === 65 && 4 === pubkey[0]);
function makeConverter(TYPE_BYTE, isValidPubkey = isValidDERKey) {
  function decode(keyVal) {
    if (keyVal.key[0] !== TYPE_BYTE) {
      throw new Error(
        'Decode Error: could not decode bip32Derivation with key 0x' +
          keyVal.key.toString('hex'),
      );
    }
    const pubkey = keyVal.key.slice(1);
    if (!isValidPubkey(pubkey)) {
      throw new Error(
        'Decode Error: bip32Derivation has invalid pubkey in key 0x' +
          keyVal.key.toString('hex'),
      );
    }
    if ((keyVal.value.length / 4) % 1 !== 0) {
      throw new Error(
        'Decode Error: Input BIP32_DERIVATION value length should be multiple of 4',
      );
    }
    const data = {
      masterFingerprint: keyVal.value.slice(0, 4),
      pubkey,
      path: 'm',
    };
    for (const i of range(keyVal.value.length / 4 - 1)) {
      const val = keyVal.value.readUInt32LE(i * 4 + 4);
      const isHard = !!(val & 0x80000000);
      const idx = val & 0x7fffffff;
      data.path += '/' + idx.toString(10) + (isHard ? "'" : '');
    }
    return data;
  }
  function encode(data) {
    const head = Buffer.from([TYPE_BYTE]);
    const key = Buffer.concat([head, data.pubkey]);
    const splitPath = data.path.split('/');
    const value = Buffer.allocUnsafe(splitPath.length * 4);
    data.masterFingerprint.copy(value, 0);
    let offset = 4;
    splitPath.slice(1).forEach(level => {
      const isHard = level.slice(-1) === "'";
      let num = 0x7fffffff & parseInt(isHard ? level.slice(0, -1) : level, 10);
      if (isHard) num += 0x80000000;
      value.writeUInt32LE(num, offset);
      offset += 4;
    });
    return {
      key,
      value,
    };
  }
  const expected =
    '{ masterFingerprint: Buffer; pubkey: Buffer; path: string; }';
  function check(data) {
    return (
      Buffer.isBuffer(data.pubkey) &&
      Buffer.isBuffer(data.masterFingerprint) &&
      typeof data.path === 'string' &&
      isValidPubkey(data.pubkey) &&
      data.masterFingerprint.length === 4
    );
  }
  function canAddToArray(array, item, dupeSet) {
    const dupeString = item.pubkey.toString('hex');
    if (dupeSet.has(dupeString)) return false;
    dupeSet.add(dupeString);
    return array.filter(v => v.pubkey.equals(item.pubkey)).length === 0;
  }
  return {
    decode,
    encode,
    check,
    expected,
    canAddToArray,
  };
}
exports.makeConverter = makeConverter;

}).call(this)}).call(this,require("buffer").Buffer)
},{"buffer":97}],31:[function(require,module,exports){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
function makeChecker(pubkeyTypes) {
  return checkPubkey;
  function checkPubkey(keyVal) {
    let pubkey;
    if (pubkeyTypes.includes(keyVal.key[0])) {
      pubkey = keyVal.key.slice(1);
      if (
        !(pubkey.length === 33 || pubkey.length === 65) ||
        ![2, 3, 4].includes(pubkey[0])
      ) {
        throw new Error(
          'Format Error: invalid pubkey in key 0x' + keyVal.key.toString('hex'),
        );
      }
    }
    return pubkey;
  }
}
exports.makeChecker = makeChecker;

},{}],32:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
function makeConverter(TYPE_BYTE) {
  function decode(keyVal) {
    if (keyVal.key[0] !== TYPE_BYTE) {
      throw new Error(
        'Decode Error: could not decode redeemScript with key 0x' +
          keyVal.key.toString('hex'),
      );
    }
    return keyVal.value;
  }
  function encode(data) {
    const key = Buffer.from([TYPE_BYTE]);
    return {
      key,
      value: data,
    };
  }
  const expected = 'Buffer';
  function check(data) {
    return Buffer.isBuffer(data);
  }
  function canAdd(currentData, newData) {
    return !!currentData && !!newData && currentData.redeemScript === undefined;
  }
  return {
    decode,
    encode,
    check,
    expected,
    canAdd,
  };
}
exports.makeConverter = makeConverter;

}).call(this)}).call(this,require("buffer").Buffer)
},{"buffer":97}],33:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const varuint = require('../varint');
const bip32Derivation = require('./bip32Derivation');
const isValidBIP340Key = pubkey => pubkey.length === 32;
function makeConverter(TYPE_BYTE) {
  const parent = bip32Derivation.makeConverter(TYPE_BYTE, isValidBIP340Key);
  function decode(keyVal) {
    const nHashes = varuint.decode(keyVal.value);
    const nHashesLen = varuint.encodingLength(nHashes);
    const base = parent.decode({
      key: keyVal.key,
      value: keyVal.value.slice(nHashesLen + nHashes * 32),
    });
    const leafHashes = new Array(nHashes);
    for (let i = 0, _offset = nHashesLen; i < nHashes; i++, _offset += 32) {
      leafHashes[i] = keyVal.value.slice(_offset, _offset + 32);
    }
    return Object.assign({}, base, { leafHashes });
  }
  function encode(data) {
    const base = parent.encode(data);
    const nHashesLen = varuint.encodingLength(data.leafHashes.length);
    const nHashesBuf = Buffer.allocUnsafe(nHashesLen);
    varuint.encode(data.leafHashes.length, nHashesBuf);
    const value = Buffer.concat([nHashesBuf, ...data.leafHashes, base.value]);
    return Object.assign({}, base, { value });
  }
  const expected =
    '{ ' +
    'masterFingerprint: Buffer; ' +
    'pubkey: Buffer; ' +
    'path: string; ' +
    'leafHashes: Buffer[]; ' +
    '}';
  function check(data) {
    return (
      Array.isArray(data.leafHashes) &&
      data.leafHashes.every(
        leafHash => Buffer.isBuffer(leafHash) && leafHash.length === 32,
      ) &&
      parent.check(data)
    );
  }
  return {
    decode,
    encode,
    check,
    expected,
    canAddToArray: parent.canAddToArray,
  };
}
exports.makeConverter = makeConverter;

}).call(this)}).call(this,require("buffer").Buffer)
},{"../varint":37,"./bip32Derivation":30,"buffer":97}],34:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
function makeConverter(TYPE_BYTE) {
  function decode(keyVal) {
    if (keyVal.key[0] !== TYPE_BYTE || keyVal.key.length !== 1) {
      throw new Error(
        'Decode Error: could not decode tapInternalKey with key 0x' +
          keyVal.key.toString('hex'),
      );
    }
    if (keyVal.value.length !== 32) {
      throw new Error(
        'Decode Error: tapInternalKey not a 32-byte x-only pubkey',
      );
    }
    return keyVal.value;
  }
  function encode(value) {
    const key = Buffer.from([TYPE_BYTE]);
    return { key, value };
  }
  const expected = 'Buffer';
  function check(data) {
    return Buffer.isBuffer(data) && data.length === 32;
  }
  function canAdd(currentData, newData) {
    return (
      !!currentData && !!newData && currentData.tapInternalKey === undefined
    );
  }
  return {
    decode,
    encode,
    check,
    expected,
    canAdd,
  };
}
exports.makeConverter = makeConverter;

}).call(this)}).call(this,require("buffer").Buffer)
},{"buffer":97}],35:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
function makeConverter(TYPE_BYTE) {
  function decode(keyVal) {
    if (keyVal.key[0] !== TYPE_BYTE) {
      throw new Error(
        'Decode Error: could not decode witnessScript with key 0x' +
          keyVal.key.toString('hex'),
      );
    }
    return keyVal.value;
  }
  function encode(data) {
    const key = Buffer.from([TYPE_BYTE]);
    return {
      key,
      value: data,
    };
  }
  const expected = 'Buffer';
  function check(data) {
    return Buffer.isBuffer(data);
  }
  function canAdd(currentData, newData) {
    return (
      !!currentData && !!newData && currentData.witnessScript === undefined
    );
  }
  return {
    decode,
    encode,
    check,
    expected,
    canAdd,
  };
}
exports.makeConverter = makeConverter;

}).call(this)}).call(this,require("buffer").Buffer)
},{"buffer":97}],36:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const varuint = require('./varint');
exports.range = n => [...Array(n).keys()];
function reverseBuffer(buffer) {
  if (buffer.length < 1) return buffer;
  let j = buffer.length - 1;
  let tmp = 0;
  for (let i = 0; i < buffer.length / 2; i++) {
    tmp = buffer[i];
    buffer[i] = buffer[j];
    buffer[j] = tmp;
    j--;
  }
  return buffer;
}
exports.reverseBuffer = reverseBuffer;
function keyValsToBuffer(keyVals) {
  const buffers = keyVals.map(keyValToBuffer);
  buffers.push(Buffer.from([0]));
  return Buffer.concat(buffers);
}
exports.keyValsToBuffer = keyValsToBuffer;
function keyValToBuffer(keyVal) {
  const keyLen = keyVal.key.length;
  const valLen = keyVal.value.length;
  const keyVarIntLen = varuint.encodingLength(keyLen);
  const valVarIntLen = varuint.encodingLength(valLen);
  const buffer = Buffer.allocUnsafe(
    keyVarIntLen + keyLen + valVarIntLen + valLen,
  );
  varuint.encode(keyLen, buffer, 0);
  keyVal.key.copy(buffer, keyVarIntLen);
  varuint.encode(valLen, buffer, keyVarIntLen + keyLen);
  keyVal.value.copy(buffer, keyVarIntLen + keyLen + valVarIntLen);
  return buffer;
}
exports.keyValToBuffer = keyValToBuffer;
// https://github.com/feross/buffer/blob/master/index.js#L1127
function verifuint(value, max) {
  if (typeof value !== 'number')
    throw new Error('cannot write a non-number as a number');
  if (value < 0)
    throw new Error('specified a negative value for writing an unsigned value');
  if (value > max) throw new Error('RangeError: value out of range');
  if (Math.floor(value) !== value)
    throw new Error('value has a fractional component');
}
function readUInt64LE(buffer, offset) {
  const a = buffer.readUInt32LE(offset);
  let b = buffer.readUInt32LE(offset + 4);
  b *= 0x100000000;
  verifuint(b + a, 0x001fffffffffffff);
  return b + a;
}
exports.readUInt64LE = readUInt64LE;
function writeUInt64LE(buffer, value, offset) {
  verifuint(value, 0x001fffffffffffff);
  buffer.writeInt32LE(value & -1, offset);
  buffer.writeUInt32LE(Math.floor(value / 0x100000000), offset + 4);
  return offset + 8;
}
exports.writeUInt64LE = writeUInt64LE;

}).call(this)}).call(this,require("buffer").Buffer)
},{"./varint":37,"buffer":97}],37:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
// Number.MAX_SAFE_INTEGER
const MAX_SAFE_INTEGER = 9007199254740991;
function checkUInt53(n) {
  if (n < 0 || n > MAX_SAFE_INTEGER || n % 1 !== 0)
    throw new RangeError('value out of range');
}
function encode(_number, buffer, offset) {
  checkUInt53(_number);
  if (!buffer) buffer = Buffer.allocUnsafe(encodingLength(_number));
  if (!Buffer.isBuffer(buffer))
    throw new TypeError('buffer must be a Buffer instance');
  if (!offset) offset = 0;
  // 8 bit
  if (_number < 0xfd) {
    buffer.writeUInt8(_number, offset);
    Object.assign(encode, { bytes: 1 });
    // 16 bit
  } else if (_number <= 0xffff) {
    buffer.writeUInt8(0xfd, offset);
    buffer.writeUInt16LE(_number, offset + 1);
    Object.assign(encode, { bytes: 3 });
    // 32 bit
  } else if (_number <= 0xffffffff) {
    buffer.writeUInt8(0xfe, offset);
    buffer.writeUInt32LE(_number, offset + 1);
    Object.assign(encode, { bytes: 5 });
    // 64 bit
  } else {
    buffer.writeUInt8(0xff, offset);
    buffer.writeUInt32LE(_number >>> 0, offset + 1);
    buffer.writeUInt32LE((_number / 0x100000000) | 0, offset + 5);
    Object.assign(encode, { bytes: 9 });
  }
  return buffer;
}
exports.encode = encode;
function decode(buffer, offset) {
  if (!Buffer.isBuffer(buffer))
    throw new TypeError('buffer must be a Buffer instance');
  if (!offset) offset = 0;
  const first = buffer.readUInt8(offset);
  // 8 bit
  if (first < 0xfd) {
    Object.assign(decode, { bytes: 1 });
    return first;
    // 16 bit
  } else if (first === 0xfd) {
    Object.assign(decode, { bytes: 3 });
    return buffer.readUInt16LE(offset + 1);
    // 32 bit
  } else if (first === 0xfe) {
    Object.assign(decode, { bytes: 5 });
    return buffer.readUInt32LE(offset + 1);
    // 64 bit
  } else {
    Object.assign(decode, { bytes: 9 });
    const lo = buffer.readUInt32LE(offset + 1);
    const hi = buffer.readUInt32LE(offset + 5);
    const _number = hi * 0x0100000000 + lo;
    checkUInt53(_number);
    return _number;
  }
}
exports.decode = decode;
function encodingLength(_number) {
  checkUInt53(_number);
  return _number < 0xfd
    ? 1
    : _number <= 0xffff
    ? 3
    : _number <= 0xffffffff
    ? 5
    : 9;
}
exports.encodingLength = encodingLength;

}).call(this)}).call(this,require("buffer").Buffer)
},{"buffer":97}],38:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const convert = require('../converter');
const tools_1 = require('../converter/tools');
const varuint = require('../converter/varint');
const typeFields_1 = require('../typeFields');
function psbtFromBuffer(buffer, txGetter) {
  let offset = 0;
  function varSlice() {
    const keyLen = varuint.decode(buffer, offset);
    offset += varuint.encodingLength(keyLen);
    const key = buffer.slice(offset, offset + keyLen);
    offset += keyLen;
    return key;
  }
  function readUInt32BE() {
    const num = buffer.readUInt32BE(offset);
    offset += 4;
    return num;
  }
  function readUInt8() {
    const num = buffer.readUInt8(offset);
    offset += 1;
    return num;
  }
  function getKeyValue() {
    const key = varSlice();
    const value = varSlice();
    return {
      key,
      value,
    };
  }
  function checkEndOfKeyValPairs() {
    if (offset >= buffer.length) {
      throw new Error('Format Error: Unexpected End of PSBT');
    }
    const isEnd = buffer.readUInt8(offset) === 0;
    if (isEnd) {
      offset++;
    }
    return isEnd;
  }
  if (readUInt32BE() !== 0x70736274) {
    throw new Error('Format Error: Invalid Magic Number');
  }
  if (readUInt8() !== 0xff) {
    throw new Error(
      'Format Error: Magic Number must be followed by 0xff separator',
    );
  }
  const globalMapKeyVals = [];
  const globalKeyIndex = {};
  while (!checkEndOfKeyValPairs()) {
    const keyVal = getKeyValue();
    const hexKey = keyVal.key.toString('hex');
    if (globalKeyIndex[hexKey]) {
      throw new Error(
        'Format Error: Keys must be unique for global keymap: key ' + hexKey,
      );
    }
    globalKeyIndex[hexKey] = 1;
    globalMapKeyVals.push(keyVal);
  }
  const unsignedTxMaps = globalMapKeyVals.filter(
    keyVal => keyVal.key[0] === typeFields_1.GlobalTypes.UNSIGNED_TX,
  );
  if (unsignedTxMaps.length !== 1) {
    throw new Error('Format Error: Only one UNSIGNED_TX allowed');
  }
  const unsignedTx = txGetter(unsignedTxMaps[0].value);
  // Get input and output counts to loop the respective fields
  const { inputCount, outputCount } = unsignedTx.getInputOutputCounts();
  const inputKeyVals = [];
  const outputKeyVals = [];
  // Get input fields
  for (const index of tools_1.range(inputCount)) {
    const inputKeyIndex = {};
    const input = [];
    while (!checkEndOfKeyValPairs()) {
      const keyVal = getKeyValue();
      const hexKey = keyVal.key.toString('hex');
      if (inputKeyIndex[hexKey]) {
        throw new Error(
          'Format Error: Keys must be unique for each input: ' +
            'input index ' +
            index +
            ' key ' +
            hexKey,
        );
      }
      inputKeyIndex[hexKey] = 1;
      input.push(keyVal);
    }
    inputKeyVals.push(input);
  }
  for (const index of tools_1.range(outputCount)) {
    const outputKeyIndex = {};
    const output = [];
    while (!checkEndOfKeyValPairs()) {
      const keyVal = getKeyValue();
      const hexKey = keyVal.key.toString('hex');
      if (outputKeyIndex[hexKey]) {
        throw new Error(
          'Format Error: Keys must be unique for each output: ' +
            'output index ' +
            index +
            ' key ' +
            hexKey,
        );
      }
      outputKeyIndex[hexKey] = 1;
      output.push(keyVal);
    }
    outputKeyVals.push(output);
  }
  return psbtFromKeyVals(unsignedTx, {
    globalMapKeyVals,
    inputKeyVals,
    outputKeyVals,
  });
}
exports.psbtFromBuffer = psbtFromBuffer;
function checkKeyBuffer(type, keyBuf, keyNum) {
  if (!keyBuf.equals(Buffer.from([keyNum]))) {
    throw new Error(
      `Format Error: Invalid ${type} key: ${keyBuf.toString('hex')}`,
    );
  }
}
exports.checkKeyBuffer = checkKeyBuffer;
function psbtFromKeyVals(
  unsignedTx,
  { globalMapKeyVals, inputKeyVals, outputKeyVals },
) {
  // That was easy :-)
  const globalMap = {
    unsignedTx,
  };
  let txCount = 0;
  for (const keyVal of globalMapKeyVals) {
    // If a globalMap item needs pubkey, uncomment
    // const pubkey = convert.globals.checkPubkey(keyVal);
    switch (keyVal.key[0]) {
      case typeFields_1.GlobalTypes.UNSIGNED_TX:
        checkKeyBuffer(
          'global',
          keyVal.key,
          typeFields_1.GlobalTypes.UNSIGNED_TX,
        );
        if (txCount > 0) {
          throw new Error('Format Error: GlobalMap has multiple UNSIGNED_TX');
        }
        txCount++;
        break;
      case typeFields_1.GlobalTypes.GLOBAL_XPUB:
        if (globalMap.globalXpub === undefined) {
          globalMap.globalXpub = [];
        }
        globalMap.globalXpub.push(convert.globals.globalXpub.decode(keyVal));
        break;
      default:
        // This will allow inclusion during serialization.
        if (!globalMap.unknownKeyVals) globalMap.unknownKeyVals = [];
        globalMap.unknownKeyVals.push(keyVal);
    }
  }
  // Get input and output counts to loop the respective fields
  const inputCount = inputKeyVals.length;
  const outputCount = outputKeyVals.length;
  const inputs = [];
  const outputs = [];
  // Get input fields
  for (const index of tools_1.range(inputCount)) {
    const input = {};
    for (const keyVal of inputKeyVals[index]) {
      convert.inputs.checkPubkey(keyVal);
      switch (keyVal.key[0]) {
        case typeFields_1.InputTypes.NON_WITNESS_UTXO:
          checkKeyBuffer(
            'input',
            keyVal.key,
            typeFields_1.InputTypes.NON_WITNESS_UTXO,
          );
          if (input.nonWitnessUtxo !== undefined) {
            throw new Error(
              'Format Error: Input has multiple NON_WITNESS_UTXO',
            );
          }
          input.nonWitnessUtxo = convert.inputs.nonWitnessUtxo.decode(keyVal);
          break;
        case typeFields_1.InputTypes.WITNESS_UTXO:
          checkKeyBuffer(
            'input',
            keyVal.key,
            typeFields_1.InputTypes.WITNESS_UTXO,
          );
          if (input.witnessUtxo !== undefined) {
            throw new Error('Format Error: Input has multiple WITNESS_UTXO');
          }
          input.witnessUtxo = convert.inputs.witnessUtxo.decode(keyVal);
          break;
        case typeFields_1.InputTypes.PARTIAL_SIG:
          if (input.partialSig === undefined) {
            input.partialSig = [];
          }
          input.partialSig.push(convert.inputs.partialSig.decode(keyVal));
          break;
        case typeFields_1.InputTypes.SIGHASH_TYPE:
          checkKeyBuffer(
            'input',
            keyVal.key,
            typeFields_1.InputTypes.SIGHASH_TYPE,
          );
          if (input.sighashType !== undefined) {
            throw new Error('Format Error: Input has multiple SIGHASH_TYPE');
          }
          input.sighashType = convert.inputs.sighashType.decode(keyVal);
          break;
        case typeFields_1.InputTypes.REDEEM_SCRIPT:
          checkKeyBuffer(
            'input',
            keyVal.key,
            typeFields_1.InputTypes.REDEEM_SCRIPT,
          );
          if (input.redeemScript !== undefined) {
            throw new Error('Format Error: Input has multiple REDEEM_SCRIPT');
          }
          input.redeemScript = convert.inputs.redeemScript.decode(keyVal);
          break;
        case typeFields_1.InputTypes.WITNESS_SCRIPT:
          checkKeyBuffer(
            'input',
            keyVal.key,
            typeFields_1.InputTypes.WITNESS_SCRIPT,
          );
          if (input.witnessScript !== undefined) {
            throw new Error('Format Error: Input has multiple WITNESS_SCRIPT');
          }
          input.witnessScript = convert.inputs.witnessScript.decode(keyVal);
          break;
        case typeFields_1.InputTypes.BIP32_DERIVATION:
          if (input.bip32Derivation === undefined) {
            input.bip32Derivation = [];
          }
          input.bip32Derivation.push(
            convert.inputs.bip32Derivation.decode(keyVal),
          );
          break;
        case typeFields_1.InputTypes.FINAL_SCRIPTSIG:
          checkKeyBuffer(
            'input',
            keyVal.key,
            typeFields_1.InputTypes.FINAL_SCRIPTSIG,
          );
          input.finalScriptSig = convert.inputs.finalScriptSig.decode(keyVal);
          break;
        case typeFields_1.InputTypes.FINAL_SCRIPTWITNESS:
          checkKeyBuffer(
            'input',
            keyVal.key,
            typeFields_1.InputTypes.FINAL_SCRIPTWITNESS,
          );
          input.finalScriptWitness = convert.inputs.finalScriptWitness.decode(
            keyVal,
          );
          break;
        case typeFields_1.InputTypes.POR_COMMITMENT:
          checkKeyBuffer(
            'input',
            keyVal.key,
            typeFields_1.InputTypes.POR_COMMITMENT,
          );
          input.porCommitment = convert.inputs.porCommitment.decode(keyVal);
          break;
        case typeFields_1.InputTypes.TAP_KEY_SIG:
          checkKeyBuffer(
            'input',
            keyVal.key,
            typeFields_1.InputTypes.TAP_KEY_SIG,
          );
          input.tapKeySig = convert.inputs.tapKeySig.decode(keyVal);
          break;
        case typeFields_1.InputTypes.TAP_SCRIPT_SIG:
          if (input.tapScriptSig === undefined) {
            input.tapScriptSig = [];
          }
          input.tapScriptSig.push(convert.inputs.tapScriptSig.decode(keyVal));
          break;
        case typeFields_1.InputTypes.TAP_LEAF_SCRIPT:
          if (input.tapLeafScript === undefined) {
            input.tapLeafScript = [];
          }
          input.tapLeafScript.push(convert.inputs.tapLeafScript.decode(keyVal));
          break;
        case typeFields_1.InputTypes.TAP_BIP32_DERIVATION:
          if (input.tapBip32Derivation === undefined) {
            input.tapBip32Derivation = [];
          }
          input.tapBip32Derivation.push(
            convert.inputs.tapBip32Derivation.decode(keyVal),
          );
          break;
        case typeFields_1.InputTypes.TAP_INTERNAL_KEY:
          checkKeyBuffer(
            'input',
            keyVal.key,
            typeFields_1.InputTypes.TAP_INTERNAL_KEY,
          );
          input.tapInternalKey = convert.inputs.tapInternalKey.decode(keyVal);
          break;
        case typeFields_1.InputTypes.TAP_MERKLE_ROOT:
          checkKeyBuffer(
            'input',
            keyVal.key,
            typeFields_1.InputTypes.TAP_MERKLE_ROOT,
          );
          input.tapMerkleRoot = convert.inputs.tapMerkleRoot.decode(keyVal);
          break;
        default:
          // This will allow inclusion during serialization.
          if (!input.unknownKeyVals) input.unknownKeyVals = [];
          input.unknownKeyVals.push(keyVal);
      }
    }
    inputs.push(input);
  }
  for (const index of tools_1.range(outputCount)) {
    const output = {};
    for (const keyVal of outputKeyVals[index]) {
      convert.outputs.checkPubkey(keyVal);
      switch (keyVal.key[0]) {
        case typeFields_1.OutputTypes.REDEEM_SCRIPT:
          checkKeyBuffer(
            'output',
            keyVal.key,
            typeFields_1.OutputTypes.REDEEM_SCRIPT,
          );
          if (output.redeemScript !== undefined) {
            throw new Error('Format Error: Output has multiple REDEEM_SCRIPT');
          }
          output.redeemScript = convert.outputs.redeemScript.decode(keyVal);
          break;
        case typeFields_1.OutputTypes.WITNESS_SCRIPT:
          checkKeyBuffer(
            'output',
            keyVal.key,
            typeFields_1.OutputTypes.WITNESS_SCRIPT,
          );
          if (output.witnessScript !== undefined) {
            throw new Error('Format Error: Output has multiple WITNESS_SCRIPT');
          }
          output.witnessScript = convert.outputs.witnessScript.decode(keyVal);
          break;
        case typeFields_1.OutputTypes.BIP32_DERIVATION:
          if (output.bip32Derivation === undefined) {
            output.bip32Derivation = [];
          }
          output.bip32Derivation.push(
            convert.outputs.bip32Derivation.decode(keyVal),
          );
          break;
        case typeFields_1.OutputTypes.TAP_INTERNAL_KEY:
          checkKeyBuffer(
            'output',
            keyVal.key,
            typeFields_1.OutputTypes.TAP_INTERNAL_KEY,
          );
          output.tapInternalKey = convert.outputs.tapInternalKey.decode(keyVal);
          break;
        case typeFields_1.OutputTypes.TAP_TREE:
          checkKeyBuffer(
            'output',
            keyVal.key,
            typeFields_1.OutputTypes.TAP_TREE,
          );
          output.tapTree = convert.outputs.tapTree.decode(keyVal);
          break;
        case typeFields_1.OutputTypes.TAP_BIP32_DERIVATION:
          if (output.tapBip32Derivation === undefined) {
            output.tapBip32Derivation = [];
          }
          output.tapBip32Derivation.push(
            convert.outputs.tapBip32Derivation.decode(keyVal),
          );
          break;
        default:
          if (!output.unknownKeyVals) output.unknownKeyVals = [];
          output.unknownKeyVals.push(keyVal);
      }
    }
    outputs.push(output);
  }
  return { globalMap, inputs, outputs };
}
exports.psbtFromKeyVals = psbtFromKeyVals;

}).call(this)}).call(this,require("buffer").Buffer)
},{"../converter":17,"../converter/tools":36,"../converter/varint":37,"../typeFields":42,"buffer":97}],39:[function(require,module,exports){
'use strict';
function __export(m) {
  for (var p in m) if (!exports.hasOwnProperty(p)) exports[p] = m[p];
}
Object.defineProperty(exports, '__esModule', { value: true });
__export(require('./fromBuffer'));
__export(require('./toBuffer'));

},{"./fromBuffer":38,"./toBuffer":40}],40:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const convert = require('../converter');
const tools_1 = require('../converter/tools');
function psbtToBuffer({ globalMap, inputs, outputs }) {
  const { globalKeyVals, inputKeyVals, outputKeyVals } = psbtToKeyVals({
    globalMap,
    inputs,
    outputs,
  });
  const globalBuffer = tools_1.keyValsToBuffer(globalKeyVals);
  const keyValsOrEmptyToBuffer = keyVals =>
    keyVals.length === 0
      ? [Buffer.from([0])]
      : keyVals.map(tools_1.keyValsToBuffer);
  const inputBuffers = keyValsOrEmptyToBuffer(inputKeyVals);
  const outputBuffers = keyValsOrEmptyToBuffer(outputKeyVals);
  const header = Buffer.allocUnsafe(5);
  header.writeUIntBE(0x70736274ff, 0, 5);
  return Buffer.concat(
    [header, globalBuffer].concat(inputBuffers, outputBuffers),
  );
}
exports.psbtToBuffer = psbtToBuffer;
const sortKeyVals = (a, b) => {
  return a.key.compare(b.key);
};
function keyValsFromMap(keyValMap, converterFactory) {
  const keyHexSet = new Set();
  const keyVals = Object.entries(keyValMap).reduce((result, [key, value]) => {
    if (key === 'unknownKeyVals') return result;
    // We are checking for undefined anyways. So ignore TS error
    // @ts-ignore
    const converter = converterFactory[key];
    if (converter === undefined) return result;
    const encodedKeyVals = (Array.isArray(value) ? value : [value]).map(
      converter.encode,
    );
    const keyHexes = encodedKeyVals.map(kv => kv.key.toString('hex'));
    keyHexes.forEach(hex => {
      if (keyHexSet.has(hex))
        throw new Error('Serialize Error: Duplicate key: ' + hex);
      keyHexSet.add(hex);
    });
    return result.concat(encodedKeyVals);
  }, []);
  // Get other keyVals that have not yet been gotten
  const otherKeyVals = keyValMap.unknownKeyVals
    ? keyValMap.unknownKeyVals.filter(keyVal => {
        return !keyHexSet.has(keyVal.key.toString('hex'));
      })
    : [];
  return keyVals.concat(otherKeyVals).sort(sortKeyVals);
}
function psbtToKeyVals({ globalMap, inputs, outputs }) {
  // First parse the global keyVals
  // Get any extra keyvals to pass along
  return {
    globalKeyVals: keyValsFromMap(globalMap, convert.globals),
    inputKeyVals: inputs.map(i => keyValsFromMap(i, convert.inputs)),
    outputKeyVals: outputs.map(o => keyValsFromMap(o, convert.outputs)),
  };
}
exports.psbtToKeyVals = psbtToKeyVals;

}).call(this)}).call(this,require("buffer").Buffer)
},{"../converter":17,"../converter/tools":36,"buffer":97}],41:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const combiner_1 = require('./combiner');
const parser_1 = require('./parser');
const typeFields_1 = require('./typeFields');
const utils_1 = require('./utils');
class Psbt {
  constructor(tx) {
    this.inputs = [];
    this.outputs = [];
    this.globalMap = {
      unsignedTx: tx,
    };
  }
  static fromBase64(data, txFromBuffer) {
    const buffer = Buffer.from(data, 'base64');
    return this.fromBuffer(buffer, txFromBuffer);
  }
  static fromHex(data, txFromBuffer) {
    const buffer = Buffer.from(data, 'hex');
    return this.fromBuffer(buffer, txFromBuffer);
  }
  static fromBuffer(buffer, txFromBuffer) {
    const results = parser_1.psbtFromBuffer(buffer, txFromBuffer);
    const psbt = new this(results.globalMap.unsignedTx);
    Object.assign(psbt, results);
    return psbt;
  }
  toBase64() {
    const buffer = this.toBuffer();
    return buffer.toString('base64');
  }
  toHex() {
    const buffer = this.toBuffer();
    return buffer.toString('hex');
  }
  toBuffer() {
    return parser_1.psbtToBuffer(this);
  }
  updateGlobal(updateData) {
    utils_1.updateGlobal(updateData, this.globalMap);
    return this;
  }
  updateInput(inputIndex, updateData) {
    const input = utils_1.checkForInput(this.inputs, inputIndex);
    utils_1.updateInput(updateData, input);
    return this;
  }
  updateOutput(outputIndex, updateData) {
    const output = utils_1.checkForOutput(this.outputs, outputIndex);
    utils_1.updateOutput(updateData, output);
    return this;
  }
  addUnknownKeyValToGlobal(keyVal) {
    utils_1.checkHasKey(
      keyVal,
      this.globalMap.unknownKeyVals,
      utils_1.getEnumLength(typeFields_1.GlobalTypes),
    );
    if (!this.globalMap.unknownKeyVals) this.globalMap.unknownKeyVals = [];
    this.globalMap.unknownKeyVals.push(keyVal);
    return this;
  }
  addUnknownKeyValToInput(inputIndex, keyVal) {
    const input = utils_1.checkForInput(this.inputs, inputIndex);
    utils_1.checkHasKey(
      keyVal,
      input.unknownKeyVals,
      utils_1.getEnumLength(typeFields_1.InputTypes),
    );
    if (!input.unknownKeyVals) input.unknownKeyVals = [];
    input.unknownKeyVals.push(keyVal);
    return this;
  }
  addUnknownKeyValToOutput(outputIndex, keyVal) {
    const output = utils_1.checkForOutput(this.outputs, outputIndex);
    utils_1.checkHasKey(
      keyVal,
      output.unknownKeyVals,
      utils_1.getEnumLength(typeFields_1.OutputTypes),
    );
    if (!output.unknownKeyVals) output.unknownKeyVals = [];
    output.unknownKeyVals.push(keyVal);
    return this;
  }
  addInput(inputData) {
    this.globalMap.unsignedTx.addInput(inputData);
    this.inputs.push({
      unknownKeyVals: [],
    });
    const addKeyVals = inputData.unknownKeyVals || [];
    const inputIndex = this.inputs.length - 1;
    if (!Array.isArray(addKeyVals)) {
      throw new Error('unknownKeyVals must be an Array');
    }
    addKeyVals.forEach(keyVal =>
      this.addUnknownKeyValToInput(inputIndex, keyVal),
    );
    utils_1.addInputAttributes(this.inputs, inputData);
    return this;
  }
  addOutput(outputData) {
    this.globalMap.unsignedTx.addOutput(outputData);
    this.outputs.push({
      unknownKeyVals: [],
    });
    const addKeyVals = outputData.unknownKeyVals || [];
    const outputIndex = this.outputs.length - 1;
    if (!Array.isArray(addKeyVals)) {
      throw new Error('unknownKeyVals must be an Array');
    }
    addKeyVals.forEach(keyVal =>
      this.addUnknownKeyValToOutput(outputIndex, keyVal),
    );
    utils_1.addOutputAttributes(this.outputs, outputData);
    return this;
  }
  clearFinalizedInput(inputIndex) {
    const input = utils_1.checkForInput(this.inputs, inputIndex);
    utils_1.inputCheckUncleanFinalized(inputIndex, input);
    for (const key of Object.keys(input)) {
      if (
        ![
          'witnessUtxo',
          'nonWitnessUtxo',
          'finalScriptSig',
          'finalScriptWitness',
          'unknownKeyVals',
        ].includes(key)
      ) {
        // @ts-ignore
        delete input[key];
      }
    }
    return this;
  }
  combine(...those) {
    // Combine this with those.
    // Return self for chaining.
    const result = combiner_1.combine([this].concat(those));
    Object.assign(this, result);
    return this;
  }
  getTransaction() {
    return this.globalMap.unsignedTx.toBuffer();
  }
}
exports.Psbt = Psbt;

}).call(this)}).call(this,require("buffer").Buffer)
},{"./combiner":14,"./parser":39,"./typeFields":42,"./utils":43,"buffer":97}],42:[function(require,module,exports){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
var GlobalTypes;
(function(GlobalTypes) {
  GlobalTypes[(GlobalTypes['UNSIGNED_TX'] = 0)] = 'UNSIGNED_TX';
  GlobalTypes[(GlobalTypes['GLOBAL_XPUB'] = 1)] = 'GLOBAL_XPUB';
})((GlobalTypes = exports.GlobalTypes || (exports.GlobalTypes = {})));
exports.GLOBAL_TYPE_NAMES = ['unsignedTx', 'globalXpub'];
var InputTypes;
(function(InputTypes) {
  InputTypes[(InputTypes['NON_WITNESS_UTXO'] = 0)] = 'NON_WITNESS_UTXO';
  InputTypes[(InputTypes['WITNESS_UTXO'] = 1)] = 'WITNESS_UTXO';
  InputTypes[(InputTypes['PARTIAL_SIG'] = 2)] = 'PARTIAL_SIG';
  InputTypes[(InputTypes['SIGHASH_TYPE'] = 3)] = 'SIGHASH_TYPE';
  InputTypes[(InputTypes['REDEEM_SCRIPT'] = 4)] = 'REDEEM_SCRIPT';
  InputTypes[(InputTypes['WITNESS_SCRIPT'] = 5)] = 'WITNESS_SCRIPT';
  InputTypes[(InputTypes['BIP32_DERIVATION'] = 6)] = 'BIP32_DERIVATION';
  InputTypes[(InputTypes['FINAL_SCRIPTSIG'] = 7)] = 'FINAL_SCRIPTSIG';
  InputTypes[(InputTypes['FINAL_SCRIPTWITNESS'] = 8)] = 'FINAL_SCRIPTWITNESS';
  InputTypes[(InputTypes['POR_COMMITMENT'] = 9)] = 'POR_COMMITMENT';
  InputTypes[(InputTypes['TAP_KEY_SIG'] = 19)] = 'TAP_KEY_SIG';
  InputTypes[(InputTypes['TAP_SCRIPT_SIG'] = 20)] = 'TAP_SCRIPT_SIG';
  InputTypes[(InputTypes['TAP_LEAF_SCRIPT'] = 21)] = 'TAP_LEAF_SCRIPT';
  InputTypes[(InputTypes['TAP_BIP32_DERIVATION'] = 22)] =
    'TAP_BIP32_DERIVATION';
  InputTypes[(InputTypes['TAP_INTERNAL_KEY'] = 23)] = 'TAP_INTERNAL_KEY';
  InputTypes[(InputTypes['TAP_MERKLE_ROOT'] = 24)] = 'TAP_MERKLE_ROOT';
})((InputTypes = exports.InputTypes || (exports.InputTypes = {})));
exports.INPUT_TYPE_NAMES = [
  'nonWitnessUtxo',
  'witnessUtxo',
  'partialSig',
  'sighashType',
  'redeemScript',
  'witnessScript',
  'bip32Derivation',
  'finalScriptSig',
  'finalScriptWitness',
  'porCommitment',
  'tapKeySig',
  'tapScriptSig',
  'tapLeafScript',
  'tapBip32Derivation',
  'tapInternalKey',
  'tapMerkleRoot',
];
var OutputTypes;
(function(OutputTypes) {
  OutputTypes[(OutputTypes['REDEEM_SCRIPT'] = 0)] = 'REDEEM_SCRIPT';
  OutputTypes[(OutputTypes['WITNESS_SCRIPT'] = 1)] = 'WITNESS_SCRIPT';
  OutputTypes[(OutputTypes['BIP32_DERIVATION'] = 2)] = 'BIP32_DERIVATION';
  OutputTypes[(OutputTypes['TAP_INTERNAL_KEY'] = 5)] = 'TAP_INTERNAL_KEY';
  OutputTypes[(OutputTypes['TAP_TREE'] = 6)] = 'TAP_TREE';
  OutputTypes[(OutputTypes['TAP_BIP32_DERIVATION'] = 7)] =
    'TAP_BIP32_DERIVATION';
})((OutputTypes = exports.OutputTypes || (exports.OutputTypes = {})));
exports.OUTPUT_TYPE_NAMES = [
  'redeemScript',
  'witnessScript',
  'bip32Derivation',
  'tapInternalKey',
  'tapTree',
  'tapBip32Derivation',
];

},{}],43:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const converter = require('./converter');
function checkForInput(inputs, inputIndex) {
  const input = inputs[inputIndex];
  if (input === undefined) throw new Error(`No input #${inputIndex}`);
  return input;
}
exports.checkForInput = checkForInput;
function checkForOutput(outputs, outputIndex) {
  const output = outputs[outputIndex];
  if (output === undefined) throw new Error(`No output #${outputIndex}`);
  return output;
}
exports.checkForOutput = checkForOutput;
function checkHasKey(checkKeyVal, keyVals, enumLength) {
  if (checkKeyVal.key[0] < enumLength) {
    throw new Error(
      `Use the method for your specific key instead of addUnknownKeyVal*`,
    );
  }
  if (
    keyVals &&
    keyVals.filter(kv => kv.key.equals(checkKeyVal.key)).length !== 0
  ) {
    throw new Error(`Duplicate Key: ${checkKeyVal.key.toString('hex')}`);
  }
}
exports.checkHasKey = checkHasKey;
function getEnumLength(myenum) {
  let count = 0;
  Object.keys(myenum).forEach(val => {
    if (Number(isNaN(Number(val)))) {
      count++;
    }
  });
  return count;
}
exports.getEnumLength = getEnumLength;
function inputCheckUncleanFinalized(inputIndex, input) {
  let result = false;
  if (input.nonWitnessUtxo || input.witnessUtxo) {
    const needScriptSig = !!input.redeemScript;
    const needWitnessScript = !!input.witnessScript;
    const scriptSigOK = !needScriptSig || !!input.finalScriptSig;
    const witnessScriptOK = !needWitnessScript || !!input.finalScriptWitness;
    const hasOneFinal = !!input.finalScriptSig || !!input.finalScriptWitness;
    result = scriptSigOK && witnessScriptOK && hasOneFinal;
  }
  if (result === false) {
    throw new Error(
      `Input #${inputIndex} has too much or too little data to clean`,
    );
  }
}
exports.inputCheckUncleanFinalized = inputCheckUncleanFinalized;
function throwForUpdateMaker(typeName, name, expected, data) {
  throw new Error(
    `Data for ${typeName} key ${name} is incorrect: Expected ` +
      `${expected} and got ${JSON.stringify(data)}`,
  );
}
function updateMaker(typeName) {
  return (updateData, mainData) => {
    for (const name of Object.keys(updateData)) {
      // @ts-ignore
      const data = updateData[name];
      // @ts-ignore
      const { canAdd, canAddToArray, check, expected } =
        // @ts-ignore
        converter[typeName + 's'][name] || {};
      const isArray = !!canAddToArray;
      // If unknown data. ignore and do not add
      if (check) {
        if (isArray) {
          if (
            !Array.isArray(data) ||
            // @ts-ignore
            (mainData[name] && !Array.isArray(mainData[name]))
          ) {
            throw new Error(`Key type ${name} must be an array`);
          }
          if (!data.every(check)) {
            throwForUpdateMaker(typeName, name, expected, data);
          }
          // @ts-ignore
          const arr = mainData[name] || [];
          const dupeCheckSet = new Set();
          if (!data.every(v => canAddToArray(arr, v, dupeCheckSet))) {
            throw new Error('Can not add duplicate data to array');
          }
          // @ts-ignore
          mainData[name] = arr.concat(data);
        } else {
          if (!check(data)) {
            throwForUpdateMaker(typeName, name, expected, data);
          }
          if (!canAdd(mainData, data)) {
            throw new Error(`Can not add duplicate data to ${typeName}`);
          }
          // @ts-ignore
          mainData[name] = data;
        }
      }
    }
  };
}
exports.updateGlobal = updateMaker('global');
exports.updateInput = updateMaker('input');
exports.updateOutput = updateMaker('output');
function addInputAttributes(inputs, data) {
  const index = inputs.length - 1;
  const input = checkForInput(inputs, index);
  exports.updateInput(data, input);
}
exports.addInputAttributes = addInputAttributes;
function addOutputAttributes(outputs, data) {
  const index = outputs.length - 1;
  const output = checkForOutput(outputs, index);
  exports.updateOutput(data, output);
}
exports.addOutputAttributes = addOutputAttributes;
function defaultVersionSetter(version, txBuf) {
  if (!Buffer.isBuffer(txBuf) || txBuf.length < 4) {
    throw new Error('Set Version: Invalid Transaction');
  }
  txBuf.writeUInt32LE(version, 0);
  return txBuf;
}
exports.defaultVersionSetter = defaultVersionSetter;
function defaultLocktimeSetter(locktime, txBuf) {
  if (!Buffer.isBuffer(txBuf) || txBuf.length < 4) {
    throw new Error('Set Locktime: Invalid Transaction');
  }
  txBuf.writeUInt32LE(locktime, txBuf.length - 4);
  return txBuf;
}
exports.defaultLocktimeSetter = defaultLocktimeSetter;

}).call(this)}).call(this,{"isBuffer":require("../../../../../../../../usr/local/lib/node_modules/browserify/node_modules/is-buffer/index.js")})
},{"../../../../../../../../usr/local/lib/node_modules/browserify/node_modules/is-buffer/index.js":99,"./converter":17}],44:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
// browserify by default only pulls in files that are hard coded in requires
// In order of last to first in this file, the default wordlist will be chosen
// based on what is present. (Bundles may remove wordlists they don't need)
const wordlists = {};
exports.wordlists = wordlists;
let _default;
exports._default = _default;
try {
    exports._default = _default = require('./wordlists/czech.json');
    wordlists.czech = _default;
}
catch (err) { }
try {
    exports._default = _default = require('./wordlists/chinese_simplified.json');
    wordlists.chinese_simplified = _default;
}
catch (err) { }
try {
    exports._default = _default = require('./wordlists/chinese_traditional.json');
    wordlists.chinese_traditional = _default;
}
catch (err) { }
try {
    exports._default = _default = require('./wordlists/korean.json');
    wordlists.korean = _default;
}
catch (err) { }
try {
    exports._default = _default = require('./wordlists/french.json');
    wordlists.french = _default;
}
catch (err) { }
try {
    exports._default = _default = require('./wordlists/italian.json');
    wordlists.italian = _default;
}
catch (err) { }
try {
    exports._default = _default = require('./wordlists/spanish.json');
    wordlists.spanish = _default;
}
catch (err) { }
try {
    exports._default = _default = require('./wordlists/japanese.json');
    wordlists.japanese = _default;
    wordlists.JA = _default;
}
catch (err) { }
try {
    exports._default = _default = require('./wordlists/portuguese.json');
    wordlists.portuguese = _default;
}
catch (err) { }
try {
    exports._default = _default = require('./wordlists/english.json');
    wordlists.english = _default;
    wordlists.EN = _default;
}
catch (err) { }

},{"./wordlists/chinese_simplified.json":46,"./wordlists/chinese_traditional.json":47,"./wordlists/czech.json":48,"./wordlists/english.json":49,"./wordlists/french.json":50,"./wordlists/italian.json":51,"./wordlists/japanese.json":52,"./wordlists/korean.json":53,"./wordlists/portuguese.json":54,"./wordlists/spanish.json":55}],45:[function(require,module,exports){
(function (Buffer){(function (){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const sha256_1 = require("@noble/hashes/sha256");
const sha512_1 = require("@noble/hashes/sha512");
const pbkdf2_1 = require("@noble/hashes/pbkdf2");
const utils_1 = require("@noble/hashes/utils");
const _wordlists_1 = require("./_wordlists");
let DEFAULT_WORDLIST = _wordlists_1._default;
const INVALID_MNEMONIC = 'Invalid mnemonic';
const INVALID_ENTROPY = 'Invalid entropy';
const INVALID_CHECKSUM = 'Invalid mnemonic checksum';
const WORDLIST_REQUIRED = 'A wordlist is required but a default could not be found.\n' +
    'Please pass a 2048 word array explicitly.';
function normalize(str) {
    return (str || '').normalize('NFKD');
}
function lpad(str, padString, length) {
    while (str.length < length) {
        str = padString + str;
    }
    return str;
}
function binaryToByte(bin) {
    return parseInt(bin, 2);
}
function bytesToBinary(bytes) {
    return bytes.map((x) => lpad(x.toString(2), '0', 8)).join('');
}
function deriveChecksumBits(entropyBuffer) {
    const ENT = entropyBuffer.length * 8;
    const CS = ENT / 32;
    const hash = sha256_1.sha256(Uint8Array.from(entropyBuffer));
    return bytesToBinary(Array.from(hash)).slice(0, CS);
}
function salt(password) {
    return 'mnemonic' + (password || '');
}
function mnemonicToSeedSync(mnemonic, password) {
    const mnemonicBuffer = Uint8Array.from(Buffer.from(normalize(mnemonic), 'utf8'));
    const saltBuffer = Uint8Array.from(Buffer.from(salt(normalize(password)), 'utf8'));
    const res = pbkdf2_1.pbkdf2(sha512_1.sha512, mnemonicBuffer, saltBuffer, {
        c: 2048,
        dkLen: 64,
    });
    return Buffer.from(res);
}
exports.mnemonicToSeedSync = mnemonicToSeedSync;
function mnemonicToSeed(mnemonic, password) {
    const mnemonicBuffer = Uint8Array.from(Buffer.from(normalize(mnemonic), 'utf8'));
    const saltBuffer = Uint8Array.from(Buffer.from(salt(normalize(password)), 'utf8'));
    return pbkdf2_1.pbkdf2Async(sha512_1.sha512, mnemonicBuffer, saltBuffer, {
        c: 2048,
        dkLen: 64,
    }).then((res) => Buffer.from(res));
}
exports.mnemonicToSeed = mnemonicToSeed;
function mnemonicToEntropy(mnemonic, wordlist) {
    wordlist = wordlist || DEFAULT_WORDLIST;
    if (!wordlist) {
        throw new Error(WORDLIST_REQUIRED);
    }
    const words = normalize(mnemonic).split(' ');
    if (words.length % 3 !== 0) {
        throw new Error(INVALID_MNEMONIC);
    }
    // convert word indices to 11 bit binary strings
    const bits = words
        .map((word) => {
        const index = wordlist.indexOf(word);
        if (index === -1) {
            throw new Error(INVALID_MNEMONIC);
        }
        return lpad(index.toString(2), '0', 11);
    })
        .join('');
    // split the binary string into ENT/CS
    const dividerIndex = Math.floor(bits.length / 33) * 32;
    const entropyBits = bits.slice(0, dividerIndex);
    const checksumBits = bits.slice(dividerIndex);
    // calculate the checksum and compare
    const entropyBytes = entropyBits.match(/(.{1,8})/g).map(binaryToByte);
    if (entropyBytes.length < 16) {
        throw new Error(INVALID_ENTROPY);
    }
    if (entropyBytes.length > 32) {
        throw new Error(INVALID_ENTROPY);
    }
    if (entropyBytes.length % 4 !== 0) {
        throw new Error(INVALID_ENTROPY);
    }
    const entropy = Buffer.from(entropyBytes);
    const newChecksum = deriveChecksumBits(entropy);
    if (newChecksum !== checksumBits) {
        throw new Error(INVALID_CHECKSUM);
    }
    return entropy.toString('hex');
}
exports.mnemonicToEntropy = mnemonicToEntropy;
function entropyToMnemonic(entropy, wordlist) {
    if (!Buffer.isBuffer(entropy)) {
        entropy = Buffer.from(entropy, 'hex');
    }
    wordlist = wordlist || DEFAULT_WORDLIST;
    if (!wordlist) {
        throw new Error(WORDLIST_REQUIRED);
    }
    // 128 <= ENT <= 256
    if (entropy.length < 16) {
        throw new TypeError(INVALID_ENTROPY);
    }
    if (entropy.length > 32) {
        throw new TypeError(INVALID_ENTROPY);
    }
    if (entropy.length % 4 !== 0) {
        throw new TypeError(INVALID_ENTROPY);
    }
    const entropyBits = bytesToBinary(Array.from(entropy));
    const checksumBits = deriveChecksumBits(entropy);
    const bits = entropyBits + checksumBits;
    const chunks = bits.match(/(.{1,11})/g);
    const words = chunks.map((binary) => {
        const index = binaryToByte(binary);
        return wordlist[index];
    });
    return wordlist[0] === '\u3042\u3044\u3053\u304f\u3057\u3093' // Japanese wordlist
        ? words.join('\u3000')
        : words.join(' ');
}
exports.entropyToMnemonic = entropyToMnemonic;
function generateMnemonic(strength, rng, wordlist) {
    strength = strength || 128;
    if (strength % 32 !== 0) {
        throw new TypeError(INVALID_ENTROPY);
    }
    rng = rng || ((size) => Buffer.from(utils_1.randomBytes(size)));
    return entropyToMnemonic(rng(strength / 8), wordlist);
}
exports.generateMnemonic = generateMnemonic;
function validateMnemonic(mnemonic, wordlist) {
    try {
        mnemonicToEntropy(mnemonic, wordlist);
    }
    catch (e) {
        return false;
    }
    return true;
}
exports.validateMnemonic = validateMnemonic;
function setDefaultWordlist(language) {
    const result = _wordlists_1.wordlists[language];
    if (result) {
        DEFAULT_WORDLIST = result;
    }
    else {
        throw new Error('Could not find wordlist for language "' + language + '"');
    }
}
exports.setDefaultWordlist = setDefaultWordlist;
function getDefaultWordlist() {
    if (!DEFAULT_WORDLIST) {
        throw new Error('No Default Wordlist set');
    }
    return Object.keys(_wordlists_1.wordlists).filter((lang) => {
        if (lang === 'JA' || lang === 'EN') {
            return false;
        }
        return _wordlists_1.wordlists[lang].every((word, index) => word === DEFAULT_WORDLIST[index]);
    })[0];
}
exports.getDefaultWordlist = getDefaultWordlist;
var _wordlists_2 = require("./_wordlists");
exports.wordlists = _wordlists_2.wordlists;

}).call(this)}).call(this,require("buffer").Buffer)
},{"./_wordlists":44,"@noble/hashes/pbkdf2":7,"@noble/hashes/sha256":10,"@noble/hashes/sha512":11,"@noble/hashes/utils":12,"buffer":97}],46:[function(require,module,exports){
module.exports=[
    "的",
    "一",
    "是",
    "在",
    "不",
    "了",
    "有",
    "和",
    "人",
    "这",
    "中",
    "大",
    "为",
    "上",
    "个",
    "国",
    "我",
    "以",
    "要",
    "他",
    "时",
    "来",
    "用",
    "们",
    "生",
    "到",
    "作",
    "地",
    "于",
    "出",
    "就",
    "分",
    "对",
    "成",
    "会",
    "可",
    "主",
    "发",
    "年",
    "动",
    "同",
    "工",
    "也",
    "能",
    "下",
    "过",
    "子",
    "说",
    "产",
    "种",
    "面",
    "而",
    "方",
    "后",
    "多",
    "定",
    "行",
    "学",
    "法",
    "所",
    "民",
    "得",
    "经",
    "十",
    "三",
    "之",
    "进",
    "着",
    "等",
    "部",
    "度",
    "家",
    "电",
    "力",
    "里",
    "如",
    "水",
    "化",
    "高",
    "自",
    "二",
    "理",
    "起",
    "小",
    "物",
    "现",
    "实",
    "加",
    "量",
    "都",
    "两",
    "体",
    "制",
    "机",
    "当",
    "使",
    "点",
    "从",
    "业",
    "本",
    "去",
    "把",
    "性",
    "好",
    "应",
    "开",
    "它",
    "合",
    "还",
    "因",
    "由",
    "其",
    "些",
    "然",
    "前",
    "外",
    "天",
    "政",
    "四",
    "日",
    "那",
    "社",
    "义",
    "事",
    "平",
    "形",
    "相",
    "全",
    "表",
    "间",
    "样",
    "与",
    "关",
    "各",
    "重",
    "新",
    "线",
    "内",
    "数",
    "正",
    "心",
    "反",
    "你",
    "明",
    "看",
    "原",
    "又",
    "么",
    "利",
    "比",
    "或",
    "但",
    "质",
    "气",
    "第",
    "向",
    "道",
    "命",
    "此",
    "变",
    "条",
    "只",
    "没",
    "结",
    "解",
    "问",
    "意",
    "建",
    "月",
    "公",
    "无",
    "系",
    "军",
    "很",
    "情",
    "者",
    "最",
    "立",
    "代",
    "想",
    "已",
    "通",
    "并",
    "提",
    "直",
    "题",
    "党",
    "程",
    "展",
    "五",
    "果",
    "料",
    "象",
    "员",
    "革",
    "位",
    "入",
    "常",
    "文",
    "总",
    "次",
    "品",
    "式",
    "活",
    "设",
    "及",
    "管",
    "特",
    "件",
    "长",
    "求",
    "老",
    "头",
    "基",
    "资",
    "边",
    "流",
    "路",
    "级",
    "少",
    "图",
    "山",
    "统",
    "接",
    "知",
    "较",
    "将",
    "组",
    "见",
    "计",
    "别",
    "她",
    "手",
    "角",
    "期",
    "根",
    "论",
    "运",
    "农",
    "指",
    "几",
    "九",
    "区",
    "强",
    "放",
    "决",
    "西",
    "被",
    "干",
    "做",
    "必",
    "战",
    "先",
    "回",
    "则",
    "任",
    "取",
    "据",
    "处",
    "队",
    "南",
    "给",
    "色",
    "光",
    "门",
    "即",
    "保",
    "治",
    "北",
    "造",
    "百",
    "规",
    "热",
    "领",
    "七",
    "海",
    "口",
    "东",
    "导",
    "器",
    "压",
    "志",
    "世",
    "金",
    "增",
    "争",
    "济",
    "阶",
    "油",
    "思",
    "术",
    "极",
    "交",
    "受",
    "联",
    "什",
    "认",
    "六",
    "共",
    "权",
    "收",
    "证",
    "改",
    "清",
    "美",
    "再",
    "采",
    "转",
    "更",
    "单",
    "风",
    "切",
    "打",
    "白",
    "教",
    "速",
    "花",
    "带",
    "安",
    "场",
    "身",
    "车",
    "例",
    "真",
    "务",
    "具",
    "万",
    "每",
    "目",
    "至",
    "达",
    "走",
    "积",
    "示",
    "议",
    "声",
    "报",
    "斗",
    "完",
    "类",
    "八",
    "离",
    "华",
    "名",
    "确",
    "才",
    "科",
    "张",
    "信",
    "马",
    "节",
    "话",
    "米",
    "整",
    "空",
    "元",
    "况",
    "今",
    "集",
    "温",
    "传",
    "土",
    "许",
    "步",
    "群",
    "广",
    "石",
    "记",
    "需",
    "段",
    "研",
    "界",
    "拉",
    "林",
    "律",
    "叫",
    "且",
    "究",
    "观",
    "越",
    "织",
    "装",
    "影",
    "算",
    "低",
    "持",
    "音",
    "众",
    "书",
    "布",
    "复",
    "容",
    "儿",
    "须",
    "际",
    "商",
    "非",
    "验",
    "连",
    "断",
    "深",
    "难",
    "近",
    "矿",
    "千",
    "周",
    "委",
    "素",
    "技",
    "备",
    "半",
    "办",
    "青",
    "省",
    "列",
    "习",
    "响",
    "约",
    "支",
    "般",
    "史",
    "感",
    "劳",
    "便",
    "团",
    "往",
    "酸",
    "历",
    "市",
    "克",
    "何",
    "除",
    "消",
    "构",
    "府",
    "称",
    "太",
    "准",
    "精",
    "值",
    "号",
    "率",
    "族",
    "维",
    "划",
    "选",
    "标",
    "写",
    "存",
    "候",
    "毛",
    "亲",
    "快",
    "效",
    "斯",
    "院",
    "查",
    "江",
    "型",
    "眼",
    "王",
    "按",
    "格",
    "养",
    "易",
    "置",
    "派",
    "层",
    "片",
    "始",
    "却",
    "专",
    "状",
    "育",
    "厂",
    "京",
    "识",
    "适",
    "属",
    "圆",
    "包",
    "火",
    "住",
    "调",
    "满",
    "县",
    "局",
    "照",
    "参",
    "红",
    "细",
    "引",
    "听",
    "该",
    "铁",
    "价",
    "严",
    "首",
    "底",
    "液",
    "官",
    "德",
    "随",
    "病",
    "苏",
    "失",
    "尔",
    "死",
    "讲",
    "配",
    "女",
    "黄",
    "推",
    "显",
    "谈",
    "罪",
    "神",
    "艺",
    "呢",
    "席",
    "含",
    "企",
    "望",
    "密",
    "批",
    "营",
    "项",
    "防",
    "举",
    "球",
    "英",
    "氧",
    "势",
    "告",
    "李",
    "台",
    "落",
    "木",
    "帮",
    "轮",
    "破",
    "亚",
    "师",
    "围",
    "注",
    "远",
    "字",
    "材",
    "排",
    "供",
    "河",
    "态",
    "封",
    "另",
    "施",
    "减",
    "树",
    "溶",
    "怎",
    "止",
    "案",
    "言",
    "士",
    "均",
    "武",
    "固",
    "叶",
    "鱼",
    "波",
    "视",
    "仅",
    "费",
    "紧",
    "爱",
    "左",
    "章",
    "早",
    "朝",
    "害",
    "续",
    "轻",
    "服",
    "试",
    "食",
    "充",
    "兵",
    "源",
    "判",
    "护",
    "司",
    "足",
    "某",
    "练",
    "差",
    "致",
    "板",
    "田",
    "降",
    "黑",
    "犯",
    "负",
    "击",
    "范",
    "继",
    "兴",
    "似",
    "余",
    "坚",
    "曲",
    "输",
    "修",
    "故",
    "城",
    "夫",
    "够",
    "送",
    "笔",
    "船",
    "占",
    "右",
    "财",
    "吃",
    "富",
    "春",
    "职",
    "觉",
    "汉",
    "画",
    "功",
    "巴",
    "跟",
    "虽",
    "杂",
    "飞",
    "检",
    "吸",
    "助",
    "升",
    "阳",
    "互",
    "初",
    "创",
    "抗",
    "考",
    "投",
    "坏",
    "策",
    "古",
    "径",
    "换",
    "未",
    "跑",
    "留",
    "钢",
    "曾",
    "端",
    "责",
    "站",
    "简",
    "述",
    "钱",
    "副",
    "尽",
    "帝",
    "射",
    "草",
    "冲",
    "承",
    "独",
    "令",
    "限",
    "阿",
    "宣",
    "环",
    "双",
    "请",
    "超",
    "微",
    "让",
    "控",
    "州",
    "良",
    "轴",
    "找",
    "否",
    "纪",
    "益",
    "依",
    "优",
    "顶",
    "础",
    "载",
    "倒",
    "房",
    "突",
    "坐",
    "粉",
    "敌",
    "略",
    "客",
    "袁",
    "冷",
    "胜",
    "绝",
    "析",
    "块",
    "剂",
    "测",
    "丝",
    "协",
    "诉",
    "念",
    "陈",
    "仍",
    "罗",
    "盐",
    "友",
    "洋",
    "错",
    "苦",
    "夜",
    "刑",
    "移",
    "频",
    "逐",
    "靠",
    "混",
    "母",
    "短",
    "皮",
    "终",
    "聚",
    "汽",
    "村",
    "云",
    "哪",
    "既",
    "距",
    "卫",
    "停",
    "烈",
    "央",
    "察",
    "烧",
    "迅",
    "境",
    "若",
    "印",
    "洲",
    "刻",
    "括",
    "激",
    "孔",
    "搞",
    "甚",
    "室",
    "待",
    "核",
    "校",
    "散",
    "侵",
    "吧",
    "甲",
    "游",
    "久",
    "菜",
    "味",
    "旧",
    "模",
    "湖",
    "货",
    "损",
    "预",
    "阻",
    "毫",
    "普",
    "稳",
    "乙",
    "妈",
    "植",
    "息",
    "扩",
    "银",
    "语",
    "挥",
    "酒",
    "守",
    "拿",
    "序",
    "纸",
    "医",
    "缺",
    "雨",
    "吗",
    "针",
    "刘",
    "啊",
    "急",
    "唱",
    "误",
    "训",
    "愿",
    "审",
    "附",
    "获",
    "茶",
    "鲜",
    "粮",
    "斤",
    "孩",
    "脱",
    "硫",
    "肥",
    "善",
    "龙",
    "演",
    "父",
    "渐",
    "血",
    "欢",
    "械",
    "掌",
    "歌",
    "沙",
    "刚",
    "攻",
    "谓",
    "盾",
    "讨",
    "晚",
    "粒",
    "乱",
    "燃",
    "矛",
    "乎",
    "杀",
    "药",
    "宁",
    "鲁",
    "贵",
    "钟",
    "煤",
    "读",
    "班",
    "伯",
    "香",
    "介",
    "迫",
    "句",
    "丰",
    "培",
    "握",
    "兰",
    "担",
    "弦",
    "蛋",
    "沉",
    "假",
    "穿",
    "执",
    "答",
    "乐",
    "谁",
    "顺",
    "烟",
    "缩",
    "征",
    "脸",
    "喜",
    "松",
    "脚",
    "困",
    "异",
    "免",
    "背",
    "星",
    "福",
    "买",
    "染",
    "井",
    "概",
    "慢",
    "怕",
    "磁",
    "倍",
    "祖",
    "皇",
    "促",
    "静",
    "补",
    "评",
    "翻",
    "肉",
    "践",
    "尼",
    "衣",
    "宽",
    "扬",
    "棉",
    "希",
    "伤",
    "操",
    "垂",
    "秋",
    "宜",
    "氢",
    "套",
    "督",
    "振",
    "架",
    "亮",
    "末",
    "宪",
    "庆",
    "编",
    "牛",
    "触",
    "映",
    "雷",
    "销",
    "诗",
    "座",
    "居",
    "抓",
    "裂",
    "胞",
    "呼",
    "娘",
    "景",
    "威",
    "绿",
    "晶",
    "厚",
    "盟",
    "衡",
    "鸡",
    "孙",
    "延",
    "危",
    "胶",
    "屋",
    "乡",
    "临",
    "陆",
    "顾",
    "掉",
    "呀",
    "灯",
    "岁",
    "措",
    "束",
    "耐",
    "剧",
    "玉",
    "赵",
    "跳",
    "哥",
    "季",
    "课",
    "凯",
    "胡",
    "额",
    "款",
    "绍",
    "卷",
    "齐",
    "伟",
    "蒸",
    "殖",
    "永",
    "宗",
    "苗",
    "川",
    "炉",
    "岩",
    "弱",
    "零",
    "杨",
    "奏",
    "沿",
    "露",
    "杆",
    "探",
    "滑",
    "镇",
    "饭",
    "浓",
    "航",
    "怀",
    "赶",
    "库",
    "夺",
    "伊",
    "灵",
    "税",
    "途",
    "灭",
    "赛",
    "归",
    "召",
    "鼓",
    "播",
    "盘",
    "裁",
    "险",
    "康",
    "唯",
    "录",
    "菌",
    "纯",
    "借",
    "糖",
    "盖",
    "横",
    "符",
    "私",
    "努",
    "堂",
    "域",
    "枪",
    "润",
    "幅",
    "哈",
    "竟",
    "熟",
    "虫",
    "泽",
    "脑",
    "壤",
    "碳",
    "欧",
    "遍",
    "侧",
    "寨",
    "敢",
    "彻",
    "虑",
    "斜",
    "薄",
    "庭",
    "纳",
    "弹",
    "饲",
    "伸",
    "折",
    "麦",
    "湿",
    "暗",
    "荷",
    "瓦",
    "塞",
    "床",
    "筑",
    "恶",
    "户",
    "访",
    "塔",
    "奇",
    "透",
    "梁",
    "刀",
    "旋",
    "迹",
    "卡",
    "氯",
    "遇",
    "份",
    "毒",
    "泥",
    "退",
    "洗",
    "摆",
    "灰",
    "彩",
    "卖",
    "耗",
    "夏",
    "择",
    "忙",
    "铜",
    "献",
    "硬",
    "予",
    "繁",
    "圈",
    "雪",
    "函",
    "亦",
    "抽",
    "篇",
    "阵",
    "阴",
    "丁",
    "尺",
    "追",
    "堆",
    "雄",
    "迎",
    "泛",
    "爸",
    "楼",
    "避",
    "谋",
    "吨",
    "野",
    "猪",
    "旗",
    "累",
    "偏",
    "典",
    "馆",
    "索",
    "秦",
    "脂",
    "潮",
    "爷",
    "豆",
    "忽",
    "托",
    "惊",
    "塑",
    "遗",
    "愈",
    "朱",
    "替",
    "纤",
    "粗",
    "倾",
    "尚",
    "痛",
    "楚",
    "谢",
    "奋",
    "购",
    "磨",
    "君",
    "池",
    "旁",
    "碎",
    "骨",
    "监",
    "捕",
    "弟",
    "暴",
    "割",
    "贯",
    "殊",
    "释",
    "词",
    "亡",
    "壁",
    "顿",
    "宝",
    "午",
    "尘",
    "闻",
    "揭",
    "炮",
    "残",
    "冬",
    "桥",
    "妇",
    "警",
    "综",
    "招",
    "吴",
    "付",
    "浮",
    "遭",
    "徐",
    "您",
    "摇",
    "谷",
    "赞",
    "箱",
    "隔",
    "订",
    "男",
    "吹",
    "园",
    "纷",
    "唐",
    "败",
    "宋",
    "玻",
    "巨",
    "耕",
    "坦",
    "荣",
    "闭",
    "湾",
    "键",
    "凡",
    "驻",
    "锅",
    "救",
    "恩",
    "剥",
    "凝",
    "碱",
    "齿",
    "截",
    "炼",
    "麻",
    "纺",
    "禁",
    "废",
    "盛",
    "版",
    "缓",
    "净",
    "睛",
    "昌",
    "婚",
    "涉",
    "筒",
    "嘴",
    "插",
    "岸",
    "朗",
    "庄",
    "街",
    "藏",
    "姑",
    "贸",
    "腐",
    "奴",
    "啦",
    "惯",
    "乘",
    "伙",
    "恢",
    "匀",
    "纱",
    "扎",
    "辩",
    "耳",
    "彪",
    "臣",
    "亿",
    "璃",
    "抵",
    "脉",
    "秀",
    "萨",
    "俄",
    "网",
    "舞",
    "店",
    "喷",
    "纵",
    "寸",
    "汗",
    "挂",
    "洪",
    "贺",
    "闪",
    "柬",
    "爆",
    "烯",
    "津",
    "稻",
    "墙",
    "软",
    "勇",
    "像",
    "滚",
    "厘",
    "蒙",
    "芳",
    "肯",
    "坡",
    "柱",
    "荡",
    "腿",
    "仪",
    "旅",
    "尾",
    "轧",
    "冰",
    "贡",
    "登",
    "黎",
    "削",
    "钻",
    "勒",
    "逃",
    "障",
    "氨",
    "郭",
    "峰",
    "币",
    "港",
    "伏",
    "轨",
    "亩",
    "毕",
    "擦",
    "莫",
    "刺",
    "浪",
    "秘",
    "援",
    "株",
    "健",
    "售",
    "股",
    "岛",
    "甘",
    "泡",
    "睡",
    "童",
    "铸",
    "汤",
    "阀",
    "休",
    "汇",
    "舍",
    "牧",
    "绕",
    "炸",
    "哲",
    "磷",
    "绩",
    "朋",
    "淡",
    "尖",
    "启",
    "陷",
    "柴",
    "呈",
    "徒",
    "颜",
    "泪",
    "稍",
    "忘",
    "泵",
    "蓝",
    "拖",
    "洞",
    "授",
    "镜",
    "辛",
    "壮",
    "锋",
    "贫",
    "虚",
    "弯",
    "摩",
    "泰",
    "幼",
    "廷",
    "尊",
    "窗",
    "纲",
    "弄",
    "隶",
    "疑",
    "氏",
    "宫",
    "姐",
    "震",
    "瑞",
    "怪",
    "尤",
    "琴",
    "循",
    "描",
    "膜",
    "违",
    "夹",
    "腰",
    "缘",
    "珠",
    "穷",
    "森",
    "枝",
    "竹",
    "沟",
    "催",
    "绳",
    "忆",
    "邦",
    "剩",
    "幸",
    "浆",
    "栏",
    "拥",
    "牙",
    "贮",
    "礼",
    "滤",
    "钠",
    "纹",
    "罢",
    "拍",
    "咱",
    "喊",
    "袖",
    "埃",
    "勤",
    "罚",
    "焦",
    "潜",
    "伍",
    "墨",
    "欲",
    "缝",
    "姓",
    "刊",
    "饱",
    "仿",
    "奖",
    "铝",
    "鬼",
    "丽",
    "跨",
    "默",
    "挖",
    "链",
    "扫",
    "喝",
    "袋",
    "炭",
    "污",
    "幕",
    "诸",
    "弧",
    "励",
    "梅",
    "奶",
    "洁",
    "灾",
    "舟",
    "鉴",
    "苯",
    "讼",
    "抱",
    "毁",
    "懂",
    "寒",
    "智",
    "埔",
    "寄",
    "届",
    "跃",
    "渡",
    "挑",
    "丹",
    "艰",
    "贝",
    "碰",
    "拔",
    "爹",
    "戴",
    "码",
    "梦",
    "芽",
    "熔",
    "赤",
    "渔",
    "哭",
    "敬",
    "颗",
    "奔",
    "铅",
    "仲",
    "虎",
    "稀",
    "妹",
    "乏",
    "珍",
    "申",
    "桌",
    "遵",
    "允",
    "隆",
    "螺",
    "仓",
    "魏",
    "锐",
    "晓",
    "氮",
    "兼",
    "隐",
    "碍",
    "赫",
    "拨",
    "忠",
    "肃",
    "缸",
    "牵",
    "抢",
    "博",
    "巧",
    "壳",
    "兄",
    "杜",
    "讯",
    "诚",
    "碧",
    "祥",
    "柯",
    "页",
    "巡",
    "矩",
    "悲",
    "灌",
    "龄",
    "伦",
    "票",
    "寻",
    "桂",
    "铺",
    "圣",
    "恐",
    "恰",
    "郑",
    "趣",
    "抬",
    "荒",
    "腾",
    "贴",
    "柔",
    "滴",
    "猛",
    "阔",
    "辆",
    "妻",
    "填",
    "撤",
    "储",
    "签",
    "闹",
    "扰",
    "紫",
    "砂",
    "递",
    "戏",
    "吊",
    "陶",
    "伐",
    "喂",
    "疗",
    "瓶",
    "婆",
    "抚",
    "臂",
    "摸",
    "忍",
    "虾",
    "蜡",
    "邻",
    "胸",
    "巩",
    "挤",
    "偶",
    "弃",
    "槽",
    "劲",
    "乳",
    "邓",
    "吉",
    "仁",
    "烂",
    "砖",
    "租",
    "乌",
    "舰",
    "伴",
    "瓜",
    "浅",
    "丙",
    "暂",
    "燥",
    "橡",
    "柳",
    "迷",
    "暖",
    "牌",
    "秧",
    "胆",
    "详",
    "簧",
    "踏",
    "瓷",
    "谱",
    "呆",
    "宾",
    "糊",
    "洛",
    "辉",
    "愤",
    "竞",
    "隙",
    "怒",
    "粘",
    "乃",
    "绪",
    "肩",
    "籍",
    "敏",
    "涂",
    "熙",
    "皆",
    "侦",
    "悬",
    "掘",
    "享",
    "纠",
    "醒",
    "狂",
    "锁",
    "淀",
    "恨",
    "牲",
    "霸",
    "爬",
    "赏",
    "逆",
    "玩",
    "陵",
    "祝",
    "秒",
    "浙",
    "貌",
    "役",
    "彼",
    "悉",
    "鸭",
    "趋",
    "凤",
    "晨",
    "畜",
    "辈",
    "秩",
    "卵",
    "署",
    "梯",
    "炎",
    "滩",
    "棋",
    "驱",
    "筛",
    "峡",
    "冒",
    "啥",
    "寿",
    "译",
    "浸",
    "泉",
    "帽",
    "迟",
    "硅",
    "疆",
    "贷",
    "漏",
    "稿",
    "冠",
    "嫩",
    "胁",
    "芯",
    "牢",
    "叛",
    "蚀",
    "奥",
    "鸣",
    "岭",
    "羊",
    "凭",
    "串",
    "塘",
    "绘",
    "酵",
    "融",
    "盆",
    "锡",
    "庙",
    "筹",
    "冻",
    "辅",
    "摄",
    "袭",
    "筋",
    "拒",
    "僚",
    "旱",
    "钾",
    "鸟",
    "漆",
    "沈",
    "眉",
    "疏",
    "添",
    "棒",
    "穗",
    "硝",
    "韩",
    "逼",
    "扭",
    "侨",
    "凉",
    "挺",
    "碗",
    "栽",
    "炒",
    "杯",
    "患",
    "馏",
    "劝",
    "豪",
    "辽",
    "勃",
    "鸿",
    "旦",
    "吏",
    "拜",
    "狗",
    "埋",
    "辊",
    "掩",
    "饮",
    "搬",
    "骂",
    "辞",
    "勾",
    "扣",
    "估",
    "蒋",
    "绒",
    "雾",
    "丈",
    "朵",
    "姆",
    "拟",
    "宇",
    "辑",
    "陕",
    "雕",
    "偿",
    "蓄",
    "崇",
    "剪",
    "倡",
    "厅",
    "咬",
    "驶",
    "薯",
    "刷",
    "斥",
    "番",
    "赋",
    "奉",
    "佛",
    "浇",
    "漫",
    "曼",
    "扇",
    "钙",
    "桃",
    "扶",
    "仔",
    "返",
    "俗",
    "亏",
    "腔",
    "鞋",
    "棱",
    "覆",
    "框",
    "悄",
    "叔",
    "撞",
    "骗",
    "勘",
    "旺",
    "沸",
    "孤",
    "吐",
    "孟",
    "渠",
    "屈",
    "疾",
    "妙",
    "惜",
    "仰",
    "狠",
    "胀",
    "谐",
    "抛",
    "霉",
    "桑",
    "岗",
    "嘛",
    "衰",
    "盗",
    "渗",
    "脏",
    "赖",
    "涌",
    "甜",
    "曹",
    "阅",
    "肌",
    "哩",
    "厉",
    "烃",
    "纬",
    "毅",
    "昨",
    "伪",
    "症",
    "煮",
    "叹",
    "钉",
    "搭",
    "茎",
    "笼",
    "酷",
    "偷",
    "弓",
    "锥",
    "恒",
    "杰",
    "坑",
    "鼻",
    "翼",
    "纶",
    "叙",
    "狱",
    "逮",
    "罐",
    "络",
    "棚",
    "抑",
    "膨",
    "蔬",
    "寺",
    "骤",
    "穆",
    "冶",
    "枯",
    "册",
    "尸",
    "凸",
    "绅",
    "坯",
    "牺",
    "焰",
    "轰",
    "欣",
    "晋",
    "瘦",
    "御",
    "锭",
    "锦",
    "丧",
    "旬",
    "锻",
    "垄",
    "搜",
    "扑",
    "邀",
    "亭",
    "酯",
    "迈",
    "舒",
    "脆",
    "酶",
    "闲",
    "忧",
    "酚",
    "顽",
    "羽",
    "涨",
    "卸",
    "仗",
    "陪",
    "辟",
    "惩",
    "杭",
    "姚",
    "肚",
    "捉",
    "飘",
    "漂",
    "昆",
    "欺",
    "吾",
    "郎",
    "烷",
    "汁",
    "呵",
    "饰",
    "萧",
    "雅",
    "邮",
    "迁",
    "燕",
    "撒",
    "姻",
    "赴",
    "宴",
    "烦",
    "债",
    "帐",
    "斑",
    "铃",
    "旨",
    "醇",
    "董",
    "饼",
    "雏",
    "姿",
    "拌",
    "傅",
    "腹",
    "妥",
    "揉",
    "贤",
    "拆",
    "歪",
    "葡",
    "胺",
    "丢",
    "浩",
    "徽",
    "昂",
    "垫",
    "挡",
    "览",
    "贪",
    "慰",
    "缴",
    "汪",
    "慌",
    "冯",
    "诺",
    "姜",
    "谊",
    "凶",
    "劣",
    "诬",
    "耀",
    "昏",
    "躺",
    "盈",
    "骑",
    "乔",
    "溪",
    "丛",
    "卢",
    "抹",
    "闷",
    "咨",
    "刮",
    "驾",
    "缆",
    "悟",
    "摘",
    "铒",
    "掷",
    "颇",
    "幻",
    "柄",
    "惠",
    "惨",
    "佳",
    "仇",
    "腊",
    "窝",
    "涤",
    "剑",
    "瞧",
    "堡",
    "泼",
    "葱",
    "罩",
    "霍",
    "捞",
    "胎",
    "苍",
    "滨",
    "俩",
    "捅",
    "湘",
    "砍",
    "霞",
    "邵",
    "萄",
    "疯",
    "淮",
    "遂",
    "熊",
    "粪",
    "烘",
    "宿",
    "档",
    "戈",
    "驳",
    "嫂",
    "裕",
    "徙",
    "箭",
    "捐",
    "肠",
    "撑",
    "晒",
    "辨",
    "殿",
    "莲",
    "摊",
    "搅",
    "酱",
    "屏",
    "疫",
    "哀",
    "蔡",
    "堵",
    "沫",
    "皱",
    "畅",
    "叠",
    "阁",
    "莱",
    "敲",
    "辖",
    "钩",
    "痕",
    "坝",
    "巷",
    "饿",
    "祸",
    "丘",
    "玄",
    "溜",
    "曰",
    "逻",
    "彭",
    "尝",
    "卿",
    "妨",
    "艇",
    "吞",
    "韦",
    "怨",
    "矮",
    "歇"
]

},{}],47:[function(require,module,exports){
module.exports=[
    "的",
    "一",
    "是",
    "在",
    "不",
    "了",
    "有",
    "和",
    "人",
    "這",
    "中",
    "大",
    "為",
    "上",
    "個",
    "國",
    "我",
    "以",
    "要",
    "他",
    "時",
    "來",
    "用",
    "們",
    "生",
    "到",
    "作",
    "地",
    "於",
    "出",
    "就",
    "分",
    "對",
    "成",
    "會",
    "可",
    "主",
    "發",
    "年",
    "動",
    "同",
    "工",
    "也",
    "能",
    "下",
    "過",
    "子",
    "說",
    "產",
    "種",
    "面",
    "而",
    "方",
    "後",
    "多",
    "定",
    "行",
    "學",
    "法",
    "所",
    "民",
    "得",
    "經",
    "十",
    "三",
    "之",
    "進",
    "著",
    "等",
    "部",
    "度",
    "家",
    "電",
    "力",
    "裡",
    "如",
    "水",
    "化",
    "高",
    "自",
    "二",
    "理",
    "起",
    "小",
    "物",
    "現",
    "實",
    "加",
    "量",
    "都",
    "兩",
    "體",
    "制",
    "機",
    "當",
    "使",
    "點",
    "從",
    "業",
    "本",
    "去",
    "把",
    "性",
    "好",
    "應",
    "開",
    "它",
    "合",
    "還",
    "因",
    "由",
    "其",
    "些",
    "然",
    "前",
    "外",
    "天",
    "政",
    "四",
    "日",
    "那",
    "社",
    "義",
    "事",
    "平",
    "形",
    "相",
    "全",
    "表",
    "間",
    "樣",
    "與",
    "關",
    "各",
    "重",
    "新",
    "線",
    "內",
    "數",
    "正",
    "心",
    "反",
    "你",
    "明",
    "看",
    "原",
    "又",
    "麼",
    "利",
    "比",
    "或",
    "但",
    "質",
    "氣",
    "第",
    "向",
    "道",
    "命",
    "此",
    "變",
    "條",
    "只",
    "沒",
    "結",
    "解",
    "問",
    "意",
    "建",
    "月",
    "公",
    "無",
    "系",
    "軍",
    "很",
    "情",
    "者",
    "最",
    "立",
    "代",
    "想",
    "已",
    "通",
    "並",
    "提",
    "直",
    "題",
    "黨",
    "程",
    "展",
    "五",
    "果",
    "料",
    "象",
    "員",
    "革",
    "位",
    "入",
    "常",
    "文",
    "總",
    "次",
    "品",
    "式",
    "活",
    "設",
    "及",
    "管",
    "特",
    "件",
    "長",
    "求",
    "老",
    "頭",
    "基",
    "資",
    "邊",
    "流",
    "路",
    "級",
    "少",
    "圖",
    "山",
    "統",
    "接",
    "知",
    "較",
    "將",
    "組",
    "見",
    "計",
    "別",
    "她",
    "手",
    "角",
    "期",
    "根",
    "論",
    "運",
    "農",
    "指",
    "幾",
    "九",
    "區",
    "強",
    "放",
    "決",
    "西",
    "被",
    "幹",
    "做",
    "必",
    "戰",
    "先",
    "回",
    "則",
    "任",
    "取",
    "據",
    "處",
    "隊",
    "南",
    "給",
    "色",
    "光",
    "門",
    "即",
    "保",
    "治",
    "北",
    "造",
    "百",
    "規",
    "熱",
    "領",
    "七",
    "海",
    "口",
    "東",
    "導",
    "器",
    "壓",
    "志",
    "世",
    "金",
    "增",
    "爭",
    "濟",
    "階",
    "油",
    "思",
    "術",
    "極",
    "交",
    "受",
    "聯",
    "什",
    "認",
    "六",
    "共",
    "權",
    "收",
    "證",
    "改",
    "清",
    "美",
    "再",
    "採",
    "轉",
    "更",
    "單",
    "風",
    "切",
    "打",
    "白",
    "教",
    "速",
    "花",
    "帶",
    "安",
    "場",
    "身",
    "車",
    "例",
    "真",
    "務",
    "具",
    "萬",
    "每",
    "目",
    "至",
    "達",
    "走",
    "積",
    "示",
    "議",
    "聲",
    "報",
    "鬥",
    "完",
    "類",
    "八",
    "離",
    "華",
    "名",
    "確",
    "才",
    "科",
    "張",
    "信",
    "馬",
    "節",
    "話",
    "米",
    "整",
    "空",
    "元",
    "況",
    "今",
    "集",
    "溫",
    "傳",
    "土",
    "許",
    "步",
    "群",
    "廣",
    "石",
    "記",
    "需",
    "段",
    "研",
    "界",
    "拉",
    "林",
    "律",
    "叫",
    "且",
    "究",
    "觀",
    "越",
    "織",
    "裝",
    "影",
    "算",
    "低",
    "持",
    "音",
    "眾",
    "書",
    "布",
    "复",
    "容",
    "兒",
    "須",
    "際",
    "商",
    "非",
    "驗",
    "連",
    "斷",
    "深",
    "難",
    "近",
    "礦",
    "千",
    "週",
    "委",
    "素",
    "技",
    "備",
    "半",
    "辦",
    "青",
    "省",
    "列",
    "習",
    "響",
    "約",
    "支",
    "般",
    "史",
    "感",
    "勞",
    "便",
    "團",
    "往",
    "酸",
    "歷",
    "市",
    "克",
    "何",
    "除",
    "消",
    "構",
    "府",
    "稱",
    "太",
    "準",
    "精",
    "值",
    "號",
    "率",
    "族",
    "維",
    "劃",
    "選",
    "標",
    "寫",
    "存",
    "候",
    "毛",
    "親",
    "快",
    "效",
    "斯",
    "院",
    "查",
    "江",
    "型",
    "眼",
    "王",
    "按",
    "格",
    "養",
    "易",
    "置",
    "派",
    "層",
    "片",
    "始",
    "卻",
    "專",
    "狀",
    "育",
    "廠",
    "京",
    "識",
    "適",
    "屬",
    "圓",
    "包",
    "火",
    "住",
    "調",
    "滿",
    "縣",
    "局",
    "照",
    "參",
    "紅",
    "細",
    "引",
    "聽",
    "該",
    "鐵",
    "價",
    "嚴",
    "首",
    "底",
    "液",
    "官",
    "德",
    "隨",
    "病",
    "蘇",
    "失",
    "爾",
    "死",
    "講",
    "配",
    "女",
    "黃",
    "推",
    "顯",
    "談",
    "罪",
    "神",
    "藝",
    "呢",
    "席",
    "含",
    "企",
    "望",
    "密",
    "批",
    "營",
    "項",
    "防",
    "舉",
    "球",
    "英",
    "氧",
    "勢",
    "告",
    "李",
    "台",
    "落",
    "木",
    "幫",
    "輪",
    "破",
    "亞",
    "師",
    "圍",
    "注",
    "遠",
    "字",
    "材",
    "排",
    "供",
    "河",
    "態",
    "封",
    "另",
    "施",
    "減",
    "樹",
    "溶",
    "怎",
    "止",
    "案",
    "言",
    "士",
    "均",
    "武",
    "固",
    "葉",
    "魚",
    "波",
    "視",
    "僅",
    "費",
    "緊",
    "愛",
    "左",
    "章",
    "早",
    "朝",
    "害",
    "續",
    "輕",
    "服",
    "試",
    "食",
    "充",
    "兵",
    "源",
    "判",
    "護",
    "司",
    "足",
    "某",
    "練",
    "差",
    "致",
    "板",
    "田",
    "降",
    "黑",
    "犯",
    "負",
    "擊",
    "范",
    "繼",
    "興",
    "似",
    "餘",
    "堅",
    "曲",
    "輸",
    "修",
    "故",
    "城",
    "夫",
    "夠",
    "送",
    "筆",
    "船",
    "佔",
    "右",
    "財",
    "吃",
    "富",
    "春",
    "職",
    "覺",
    "漢",
    "畫",
    "功",
    "巴",
    "跟",
    "雖",
    "雜",
    "飛",
    "檢",
    "吸",
    "助",
    "昇",
    "陽",
    "互",
    "初",
    "創",
    "抗",
    "考",
    "投",
    "壞",
    "策",
    "古",
    "徑",
    "換",
    "未",
    "跑",
    "留",
    "鋼",
    "曾",
    "端",
    "責",
    "站",
    "簡",
    "述",
    "錢",
    "副",
    "盡",
    "帝",
    "射",
    "草",
    "衝",
    "承",
    "獨",
    "令",
    "限",
    "阿",
    "宣",
    "環",
    "雙",
    "請",
    "超",
    "微",
    "讓",
    "控",
    "州",
    "良",
    "軸",
    "找",
    "否",
    "紀",
    "益",
    "依",
    "優",
    "頂",
    "礎",
    "載",
    "倒",
    "房",
    "突",
    "坐",
    "粉",
    "敵",
    "略",
    "客",
    "袁",
    "冷",
    "勝",
    "絕",
    "析",
    "塊",
    "劑",
    "測",
    "絲",
    "協",
    "訴",
    "念",
    "陳",
    "仍",
    "羅",
    "鹽",
    "友",
    "洋",
    "錯",
    "苦",
    "夜",
    "刑",
    "移",
    "頻",
    "逐",
    "靠",
    "混",
    "母",
    "短",
    "皮",
    "終",
    "聚",
    "汽",
    "村",
    "雲",
    "哪",
    "既",
    "距",
    "衛",
    "停",
    "烈",
    "央",
    "察",
    "燒",
    "迅",
    "境",
    "若",
    "印",
    "洲",
    "刻",
    "括",
    "激",
    "孔",
    "搞",
    "甚",
    "室",
    "待",
    "核",
    "校",
    "散",
    "侵",
    "吧",
    "甲",
    "遊",
    "久",
    "菜",
    "味",
    "舊",
    "模",
    "湖",
    "貨",
    "損",
    "預",
    "阻",
    "毫",
    "普",
    "穩",
    "乙",
    "媽",
    "植",
    "息",
    "擴",
    "銀",
    "語",
    "揮",
    "酒",
    "守",
    "拿",
    "序",
    "紙",
    "醫",
    "缺",
    "雨",
    "嗎",
    "針",
    "劉",
    "啊",
    "急",
    "唱",
    "誤",
    "訓",
    "願",
    "審",
    "附",
    "獲",
    "茶",
    "鮮",
    "糧",
    "斤",
    "孩",
    "脫",
    "硫",
    "肥",
    "善",
    "龍",
    "演",
    "父",
    "漸",
    "血",
    "歡",
    "械",
    "掌",
    "歌",
    "沙",
    "剛",
    "攻",
    "謂",
    "盾",
    "討",
    "晚",
    "粒",
    "亂",
    "燃",
    "矛",
    "乎",
    "殺",
    "藥",
    "寧",
    "魯",
    "貴",
    "鐘",
    "煤",
    "讀",
    "班",
    "伯",
    "香",
    "介",
    "迫",
    "句",
    "豐",
    "培",
    "握",
    "蘭",
    "擔",
    "弦",
    "蛋",
    "沉",
    "假",
    "穿",
    "執",
    "答",
    "樂",
    "誰",
    "順",
    "煙",
    "縮",
    "徵",
    "臉",
    "喜",
    "松",
    "腳",
    "困",
    "異",
    "免",
    "背",
    "星",
    "福",
    "買",
    "染",
    "井",
    "概",
    "慢",
    "怕",
    "磁",
    "倍",
    "祖",
    "皇",
    "促",
    "靜",
    "補",
    "評",
    "翻",
    "肉",
    "踐",
    "尼",
    "衣",
    "寬",
    "揚",
    "棉",
    "希",
    "傷",
    "操",
    "垂",
    "秋",
    "宜",
    "氫",
    "套",
    "督",
    "振",
    "架",
    "亮",
    "末",
    "憲",
    "慶",
    "編",
    "牛",
    "觸",
    "映",
    "雷",
    "銷",
    "詩",
    "座",
    "居",
    "抓",
    "裂",
    "胞",
    "呼",
    "娘",
    "景",
    "威",
    "綠",
    "晶",
    "厚",
    "盟",
    "衡",
    "雞",
    "孫",
    "延",
    "危",
    "膠",
    "屋",
    "鄉",
    "臨",
    "陸",
    "顧",
    "掉",
    "呀",
    "燈",
    "歲",
    "措",
    "束",
    "耐",
    "劇",
    "玉",
    "趙",
    "跳",
    "哥",
    "季",
    "課",
    "凱",
    "胡",
    "額",
    "款",
    "紹",
    "卷",
    "齊",
    "偉",
    "蒸",
    "殖",
    "永",
    "宗",
    "苗",
    "川",
    "爐",
    "岩",
    "弱",
    "零",
    "楊",
    "奏",
    "沿",
    "露",
    "桿",
    "探",
    "滑",
    "鎮",
    "飯",
    "濃",
    "航",
    "懷",
    "趕",
    "庫",
    "奪",
    "伊",
    "靈",
    "稅",
    "途",
    "滅",
    "賽",
    "歸",
    "召",
    "鼓",
    "播",
    "盤",
    "裁",
    "險",
    "康",
    "唯",
    "錄",
    "菌",
    "純",
    "借",
    "糖",
    "蓋",
    "橫",
    "符",
    "私",
    "努",
    "堂",
    "域",
    "槍",
    "潤",
    "幅",
    "哈",
    "竟",
    "熟",
    "蟲",
    "澤",
    "腦",
    "壤",
    "碳",
    "歐",
    "遍",
    "側",
    "寨",
    "敢",
    "徹",
    "慮",
    "斜",
    "薄",
    "庭",
    "納",
    "彈",
    "飼",
    "伸",
    "折",
    "麥",
    "濕",
    "暗",
    "荷",
    "瓦",
    "塞",
    "床",
    "築",
    "惡",
    "戶",
    "訪",
    "塔",
    "奇",
    "透",
    "梁",
    "刀",
    "旋",
    "跡",
    "卡",
    "氯",
    "遇",
    "份",
    "毒",
    "泥",
    "退",
    "洗",
    "擺",
    "灰",
    "彩",
    "賣",
    "耗",
    "夏",
    "擇",
    "忙",
    "銅",
    "獻",
    "硬",
    "予",
    "繁",
    "圈",
    "雪",
    "函",
    "亦",
    "抽",
    "篇",
    "陣",
    "陰",
    "丁",
    "尺",
    "追",
    "堆",
    "雄",
    "迎",
    "泛",
    "爸",
    "樓",
    "避",
    "謀",
    "噸",
    "野",
    "豬",
    "旗",
    "累",
    "偏",
    "典",
    "館",
    "索",
    "秦",
    "脂",
    "潮",
    "爺",
    "豆",
    "忽",
    "托",
    "驚",
    "塑",
    "遺",
    "愈",
    "朱",
    "替",
    "纖",
    "粗",
    "傾",
    "尚",
    "痛",
    "楚",
    "謝",
    "奮",
    "購",
    "磨",
    "君",
    "池",
    "旁",
    "碎",
    "骨",
    "監",
    "捕",
    "弟",
    "暴",
    "割",
    "貫",
    "殊",
    "釋",
    "詞",
    "亡",
    "壁",
    "頓",
    "寶",
    "午",
    "塵",
    "聞",
    "揭",
    "炮",
    "殘",
    "冬",
    "橋",
    "婦",
    "警",
    "綜",
    "招",
    "吳",
    "付",
    "浮",
    "遭",
    "徐",
    "您",
    "搖",
    "谷",
    "贊",
    "箱",
    "隔",
    "訂",
    "男",
    "吹",
    "園",
    "紛",
    "唐",
    "敗",
    "宋",
    "玻",
    "巨",
    "耕",
    "坦",
    "榮",
    "閉",
    "灣",
    "鍵",
    "凡",
    "駐",
    "鍋",
    "救",
    "恩",
    "剝",
    "凝",
    "鹼",
    "齒",
    "截",
    "煉",
    "麻",
    "紡",
    "禁",
    "廢",
    "盛",
    "版",
    "緩",
    "淨",
    "睛",
    "昌",
    "婚",
    "涉",
    "筒",
    "嘴",
    "插",
    "岸",
    "朗",
    "莊",
    "街",
    "藏",
    "姑",
    "貿",
    "腐",
    "奴",
    "啦",
    "慣",
    "乘",
    "夥",
    "恢",
    "勻",
    "紗",
    "扎",
    "辯",
    "耳",
    "彪",
    "臣",
    "億",
    "璃",
    "抵",
    "脈",
    "秀",
    "薩",
    "俄",
    "網",
    "舞",
    "店",
    "噴",
    "縱",
    "寸",
    "汗",
    "掛",
    "洪",
    "賀",
    "閃",
    "柬",
    "爆",
    "烯",
    "津",
    "稻",
    "牆",
    "軟",
    "勇",
    "像",
    "滾",
    "厘",
    "蒙",
    "芳",
    "肯",
    "坡",
    "柱",
    "盪",
    "腿",
    "儀",
    "旅",
    "尾",
    "軋",
    "冰",
    "貢",
    "登",
    "黎",
    "削",
    "鑽",
    "勒",
    "逃",
    "障",
    "氨",
    "郭",
    "峰",
    "幣",
    "港",
    "伏",
    "軌",
    "畝",
    "畢",
    "擦",
    "莫",
    "刺",
    "浪",
    "秘",
    "援",
    "株",
    "健",
    "售",
    "股",
    "島",
    "甘",
    "泡",
    "睡",
    "童",
    "鑄",
    "湯",
    "閥",
    "休",
    "匯",
    "舍",
    "牧",
    "繞",
    "炸",
    "哲",
    "磷",
    "績",
    "朋",
    "淡",
    "尖",
    "啟",
    "陷",
    "柴",
    "呈",
    "徒",
    "顏",
    "淚",
    "稍",
    "忘",
    "泵",
    "藍",
    "拖",
    "洞",
    "授",
    "鏡",
    "辛",
    "壯",
    "鋒",
    "貧",
    "虛",
    "彎",
    "摩",
    "泰",
    "幼",
    "廷",
    "尊",
    "窗",
    "綱",
    "弄",
    "隸",
    "疑",
    "氏",
    "宮",
    "姐",
    "震",
    "瑞",
    "怪",
    "尤",
    "琴",
    "循",
    "描",
    "膜",
    "違",
    "夾",
    "腰",
    "緣",
    "珠",
    "窮",
    "森",
    "枝",
    "竹",
    "溝",
    "催",
    "繩",
    "憶",
    "邦",
    "剩",
    "幸",
    "漿",
    "欄",
    "擁",
    "牙",
    "貯",
    "禮",
    "濾",
    "鈉",
    "紋",
    "罷",
    "拍",
    "咱",
    "喊",
    "袖",
    "埃",
    "勤",
    "罰",
    "焦",
    "潛",
    "伍",
    "墨",
    "欲",
    "縫",
    "姓",
    "刊",
    "飽",
    "仿",
    "獎",
    "鋁",
    "鬼",
    "麗",
    "跨",
    "默",
    "挖",
    "鏈",
    "掃",
    "喝",
    "袋",
    "炭",
    "污",
    "幕",
    "諸",
    "弧",
    "勵",
    "梅",
    "奶",
    "潔",
    "災",
    "舟",
    "鑑",
    "苯",
    "訟",
    "抱",
    "毀",
    "懂",
    "寒",
    "智",
    "埔",
    "寄",
    "屆",
    "躍",
    "渡",
    "挑",
    "丹",
    "艱",
    "貝",
    "碰",
    "拔",
    "爹",
    "戴",
    "碼",
    "夢",
    "芽",
    "熔",
    "赤",
    "漁",
    "哭",
    "敬",
    "顆",
    "奔",
    "鉛",
    "仲",
    "虎",
    "稀",
    "妹",
    "乏",
    "珍",
    "申",
    "桌",
    "遵",
    "允",
    "隆",
    "螺",
    "倉",
    "魏",
    "銳",
    "曉",
    "氮",
    "兼",
    "隱",
    "礙",
    "赫",
    "撥",
    "忠",
    "肅",
    "缸",
    "牽",
    "搶",
    "博",
    "巧",
    "殼",
    "兄",
    "杜",
    "訊",
    "誠",
    "碧",
    "祥",
    "柯",
    "頁",
    "巡",
    "矩",
    "悲",
    "灌",
    "齡",
    "倫",
    "票",
    "尋",
    "桂",
    "鋪",
    "聖",
    "恐",
    "恰",
    "鄭",
    "趣",
    "抬",
    "荒",
    "騰",
    "貼",
    "柔",
    "滴",
    "猛",
    "闊",
    "輛",
    "妻",
    "填",
    "撤",
    "儲",
    "簽",
    "鬧",
    "擾",
    "紫",
    "砂",
    "遞",
    "戲",
    "吊",
    "陶",
    "伐",
    "餵",
    "療",
    "瓶",
    "婆",
    "撫",
    "臂",
    "摸",
    "忍",
    "蝦",
    "蠟",
    "鄰",
    "胸",
    "鞏",
    "擠",
    "偶",
    "棄",
    "槽",
    "勁",
    "乳",
    "鄧",
    "吉",
    "仁",
    "爛",
    "磚",
    "租",
    "烏",
    "艦",
    "伴",
    "瓜",
    "淺",
    "丙",
    "暫",
    "燥",
    "橡",
    "柳",
    "迷",
    "暖",
    "牌",
    "秧",
    "膽",
    "詳",
    "簧",
    "踏",
    "瓷",
    "譜",
    "呆",
    "賓",
    "糊",
    "洛",
    "輝",
    "憤",
    "競",
    "隙",
    "怒",
    "粘",
    "乃",
    "緒",
    "肩",
    "籍",
    "敏",
    "塗",
    "熙",
    "皆",
    "偵",
    "懸",
    "掘",
    "享",
    "糾",
    "醒",
    "狂",
    "鎖",
    "淀",
    "恨",
    "牲",
    "霸",
    "爬",
    "賞",
    "逆",
    "玩",
    "陵",
    "祝",
    "秒",
    "浙",
    "貌",
    "役",
    "彼",
    "悉",
    "鴨",
    "趨",
    "鳳",
    "晨",
    "畜",
    "輩",
    "秩",
    "卵",
    "署",
    "梯",
    "炎",
    "灘",
    "棋",
    "驅",
    "篩",
    "峽",
    "冒",
    "啥",
    "壽",
    "譯",
    "浸",
    "泉",
    "帽",
    "遲",
    "矽",
    "疆",
    "貸",
    "漏",
    "稿",
    "冠",
    "嫩",
    "脅",
    "芯",
    "牢",
    "叛",
    "蝕",
    "奧",
    "鳴",
    "嶺",
    "羊",
    "憑",
    "串",
    "塘",
    "繪",
    "酵",
    "融",
    "盆",
    "錫",
    "廟",
    "籌",
    "凍",
    "輔",
    "攝",
    "襲",
    "筋",
    "拒",
    "僚",
    "旱",
    "鉀",
    "鳥",
    "漆",
    "沈",
    "眉",
    "疏",
    "添",
    "棒",
    "穗",
    "硝",
    "韓",
    "逼",
    "扭",
    "僑",
    "涼",
    "挺",
    "碗",
    "栽",
    "炒",
    "杯",
    "患",
    "餾",
    "勸",
    "豪",
    "遼",
    "勃",
    "鴻",
    "旦",
    "吏",
    "拜",
    "狗",
    "埋",
    "輥",
    "掩",
    "飲",
    "搬",
    "罵",
    "辭",
    "勾",
    "扣",
    "估",
    "蔣",
    "絨",
    "霧",
    "丈",
    "朵",
    "姆",
    "擬",
    "宇",
    "輯",
    "陝",
    "雕",
    "償",
    "蓄",
    "崇",
    "剪",
    "倡",
    "廳",
    "咬",
    "駛",
    "薯",
    "刷",
    "斥",
    "番",
    "賦",
    "奉",
    "佛",
    "澆",
    "漫",
    "曼",
    "扇",
    "鈣",
    "桃",
    "扶",
    "仔",
    "返",
    "俗",
    "虧",
    "腔",
    "鞋",
    "棱",
    "覆",
    "框",
    "悄",
    "叔",
    "撞",
    "騙",
    "勘",
    "旺",
    "沸",
    "孤",
    "吐",
    "孟",
    "渠",
    "屈",
    "疾",
    "妙",
    "惜",
    "仰",
    "狠",
    "脹",
    "諧",
    "拋",
    "黴",
    "桑",
    "崗",
    "嘛",
    "衰",
    "盜",
    "滲",
    "臟",
    "賴",
    "湧",
    "甜",
    "曹",
    "閱",
    "肌",
    "哩",
    "厲",
    "烴",
    "緯",
    "毅",
    "昨",
    "偽",
    "症",
    "煮",
    "嘆",
    "釘",
    "搭",
    "莖",
    "籠",
    "酷",
    "偷",
    "弓",
    "錐",
    "恆",
    "傑",
    "坑",
    "鼻",
    "翼",
    "綸",
    "敘",
    "獄",
    "逮",
    "罐",
    "絡",
    "棚",
    "抑",
    "膨",
    "蔬",
    "寺",
    "驟",
    "穆",
    "冶",
    "枯",
    "冊",
    "屍",
    "凸",
    "紳",
    "坯",
    "犧",
    "焰",
    "轟",
    "欣",
    "晉",
    "瘦",
    "禦",
    "錠",
    "錦",
    "喪",
    "旬",
    "鍛",
    "壟",
    "搜",
    "撲",
    "邀",
    "亭",
    "酯",
    "邁",
    "舒",
    "脆",
    "酶",
    "閒",
    "憂",
    "酚",
    "頑",
    "羽",
    "漲",
    "卸",
    "仗",
    "陪",
    "闢",
    "懲",
    "杭",
    "姚",
    "肚",
    "捉",
    "飄",
    "漂",
    "昆",
    "欺",
    "吾",
    "郎",
    "烷",
    "汁",
    "呵",
    "飾",
    "蕭",
    "雅",
    "郵",
    "遷",
    "燕",
    "撒",
    "姻",
    "赴",
    "宴",
    "煩",
    "債",
    "帳",
    "斑",
    "鈴",
    "旨",
    "醇",
    "董",
    "餅",
    "雛",
    "姿",
    "拌",
    "傅",
    "腹",
    "妥",
    "揉",
    "賢",
    "拆",
    "歪",
    "葡",
    "胺",
    "丟",
    "浩",
    "徽",
    "昂",
    "墊",
    "擋",
    "覽",
    "貪",
    "慰",
    "繳",
    "汪",
    "慌",
    "馮",
    "諾",
    "姜",
    "誼",
    "兇",
    "劣",
    "誣",
    "耀",
    "昏",
    "躺",
    "盈",
    "騎",
    "喬",
    "溪",
    "叢",
    "盧",
    "抹",
    "悶",
    "諮",
    "刮",
    "駕",
    "纜",
    "悟",
    "摘",
    "鉺",
    "擲",
    "頗",
    "幻",
    "柄",
    "惠",
    "慘",
    "佳",
    "仇",
    "臘",
    "窩",
    "滌",
    "劍",
    "瞧",
    "堡",
    "潑",
    "蔥",
    "罩",
    "霍",
    "撈",
    "胎",
    "蒼",
    "濱",
    "倆",
    "捅",
    "湘",
    "砍",
    "霞",
    "邵",
    "萄",
    "瘋",
    "淮",
    "遂",
    "熊",
    "糞",
    "烘",
    "宿",
    "檔",
    "戈",
    "駁",
    "嫂",
    "裕",
    "徙",
    "箭",
    "捐",
    "腸",
    "撐",
    "曬",
    "辨",
    "殿",
    "蓮",
    "攤",
    "攪",
    "醬",
    "屏",
    "疫",
    "哀",
    "蔡",
    "堵",
    "沫",
    "皺",
    "暢",
    "疊",
    "閣",
    "萊",
    "敲",
    "轄",
    "鉤",
    "痕",
    "壩",
    "巷",
    "餓",
    "禍",
    "丘",
    "玄",
    "溜",
    "曰",
    "邏",
    "彭",
    "嘗",
    "卿",
    "妨",
    "艇",
    "吞",
    "韋",
    "怨",
    "矮",
    "歇"
]

},{}],48:[function(require,module,exports){
module.exports=[
    "abdikace",
    "abeceda",
    "adresa",
    "agrese",
    "akce",
    "aktovka",
    "alej",
    "alkohol",
    "amputace",
    "ananas",
    "andulka",
    "anekdota",
    "anketa",
    "antika",
    "anulovat",
    "archa",
    "arogance",
    "asfalt",
    "asistent",
    "aspirace",
    "astma",
    "astronom",
    "atlas",
    "atletika",
    "atol",
    "autobus",
    "azyl",
    "babka",
    "bachor",
    "bacil",
    "baculka",
    "badatel",
    "bageta",
    "bagr",
    "bahno",
    "bakterie",
    "balada",
    "baletka",
    "balkon",
    "balonek",
    "balvan",
    "balza",
    "bambus",
    "bankomat",
    "barbar",
    "baret",
    "barman",
    "baroko",
    "barva",
    "baterka",
    "batoh",
    "bavlna",
    "bazalka",
    "bazilika",
    "bazuka",
    "bedna",
    "beran",
    "beseda",
    "bestie",
    "beton",
    "bezinka",
    "bezmoc",
    "beztak",
    "bicykl",
    "bidlo",
    "biftek",
    "bikiny",
    "bilance",
    "biograf",
    "biolog",
    "bitva",
    "bizon",
    "blahobyt",
    "blatouch",
    "blecha",
    "bledule",
    "blesk",
    "blikat",
    "blizna",
    "blokovat",
    "bloudit",
    "blud",
    "bobek",
    "bobr",
    "bodlina",
    "bodnout",
    "bohatost",
    "bojkot",
    "bojovat",
    "bokorys",
    "bolest",
    "borec",
    "borovice",
    "bota",
    "boubel",
    "bouchat",
    "bouda",
    "boule",
    "bourat",
    "boxer",
    "bradavka",
    "brambora",
    "branka",
    "bratr",
    "brepta",
    "briketa",
    "brko",
    "brloh",
    "bronz",
    "broskev",
    "brunetka",
    "brusinka",
    "brzda",
    "brzy",
    "bublina",
    "bubnovat",
    "buchta",
    "buditel",
    "budka",
    "budova",
    "bufet",
    "bujarost",
    "bukvice",
    "buldok",
    "bulva",
    "bunda",
    "bunkr",
    "burza",
    "butik",
    "buvol",
    "buzola",
    "bydlet",
    "bylina",
    "bytovka",
    "bzukot",
    "capart",
    "carevna",
    "cedr",
    "cedule",
    "cejch",
    "cejn",
    "cela",
    "celer",
    "celkem",
    "celnice",
    "cenina",
    "cennost",
    "cenovka",
    "centrum",
    "cenzor",
    "cestopis",
    "cetka",
    "chalupa",
    "chapadlo",
    "charita",
    "chata",
    "chechtat",
    "chemie",
    "chichot",
    "chirurg",
    "chlad",
    "chleba",
    "chlubit",
    "chmel",
    "chmura",
    "chobot",
    "chochol",
    "chodba",
    "cholera",
    "chomout",
    "chopit",
    "choroba",
    "chov",
    "chrapot",
    "chrlit",
    "chrt",
    "chrup",
    "chtivost",
    "chudina",
    "chutnat",
    "chvat",
    "chvilka",
    "chvost",
    "chyba",
    "chystat",
    "chytit",
    "cibule",
    "cigareta",
    "cihelna",
    "cihla",
    "cinkot",
    "cirkus",
    "cisterna",
    "citace",
    "citrus",
    "cizinec",
    "cizost",
    "clona",
    "cokoliv",
    "couvat",
    "ctitel",
    "ctnost",
    "cudnost",
    "cuketa",
    "cukr",
    "cupot",
    "cvaknout",
    "cval",
    "cvik",
    "cvrkot",
    "cyklista",
    "daleko",
    "dareba",
    "datel",
    "datum",
    "dcera",
    "debata",
    "dechovka",
    "decibel",
    "deficit",
    "deflace",
    "dekl",
    "dekret",
    "demokrat",
    "deprese",
    "derby",
    "deska",
    "detektiv",
    "dikobraz",
    "diktovat",
    "dioda",
    "diplom",
    "disk",
    "displej",
    "divadlo",
    "divoch",
    "dlaha",
    "dlouho",
    "dluhopis",
    "dnes",
    "dobro",
    "dobytek",
    "docent",
    "dochutit",
    "dodnes",
    "dohled",
    "dohoda",
    "dohra",
    "dojem",
    "dojnice",
    "doklad",
    "dokola",
    "doktor",
    "dokument",
    "dolar",
    "doleva",
    "dolina",
    "doma",
    "dominant",
    "domluvit",
    "domov",
    "donutit",
    "dopad",
    "dopis",
    "doplnit",
    "doposud",
    "doprovod",
    "dopustit",
    "dorazit",
    "dorost",
    "dort",
    "dosah",
    "doslov",
    "dostatek",
    "dosud",
    "dosyta",
    "dotaz",
    "dotek",
    "dotknout",
    "doufat",
    "doutnat",
    "dovozce",
    "dozadu",
    "doznat",
    "dozorce",
    "drahota",
    "drak",
    "dramatik",
    "dravec",
    "draze",
    "drdol",
    "drobnost",
    "drogerie",
    "drozd",
    "drsnost",
    "drtit",
    "drzost",
    "duben",
    "duchovno",
    "dudek",
    "duha",
    "duhovka",
    "dusit",
    "dusno",
    "dutost",
    "dvojice",
    "dvorec",
    "dynamit",
    "ekolog",
    "ekonomie",
    "elektron",
    "elipsa",
    "email",
    "emise",
    "emoce",
    "empatie",
    "epizoda",
    "epocha",
    "epopej",
    "epos",
    "esej",
    "esence",
    "eskorta",
    "eskymo",
    "etiketa",
    "euforie",
    "evoluce",
    "exekuce",
    "exkurze",
    "expedice",
    "exploze",
    "export",
    "extrakt",
    "facka",
    "fajfka",
    "fakulta",
    "fanatik",
    "fantazie",
    "farmacie",
    "favorit",
    "fazole",
    "federace",
    "fejeton",
    "fenka",
    "fialka",
    "figurant",
    "filozof",
    "filtr",
    "finance",
    "finta",
    "fixace",
    "fjord",
    "flanel",
    "flirt",
    "flotila",
    "fond",
    "fosfor",
    "fotbal",
    "fotka",
    "foton",
    "frakce",
    "freska",
    "fronta",
    "fukar",
    "funkce",
    "fyzika",
    "galeje",
    "garant",
    "genetika",
    "geolog",
    "gilotina",
    "glazura",
    "glejt",
    "golem",
    "golfista",
    "gotika",
    "graf",
    "gramofon",
    "granule",
    "grep",
    "gril",
    "grog",
    "groteska",
    "guma",
    "hadice",
    "hadr",
    "hala",
    "halenka",
    "hanba",
    "hanopis",
    "harfa",
    "harpuna",
    "havran",
    "hebkost",
    "hejkal",
    "hejno",
    "hejtman",
    "hektar",
    "helma",
    "hematom",
    "herec",
    "herna",
    "heslo",
    "hezky",
    "historik",
    "hladovka",
    "hlasivky",
    "hlava",
    "hledat",
    "hlen",
    "hlodavec",
    "hloh",
    "hloupost",
    "hltat",
    "hlubina",
    "hluchota",
    "hmat",
    "hmota",
    "hmyz",
    "hnis",
    "hnojivo",
    "hnout",
    "hoblina",
    "hoboj",
    "hoch",
    "hodiny",
    "hodlat",
    "hodnota",
    "hodovat",
    "hojnost",
    "hokej",
    "holinka",
    "holka",
    "holub",
    "homole",
    "honitba",
    "honorace",
    "horal",
    "horda",
    "horizont",
    "horko",
    "horlivec",
    "hormon",
    "hornina",
    "horoskop",
    "horstvo",
    "hospoda",
    "hostina",
    "hotovost",
    "houba",
    "houf",
    "houpat",
    "houska",
    "hovor",
    "hradba",
    "hranice",
    "hravost",
    "hrazda",
    "hrbolek",
    "hrdina",
    "hrdlo",
    "hrdost",
    "hrnek",
    "hrobka",
    "hromada",
    "hrot",
    "hrouda",
    "hrozen",
    "hrstka",
    "hrubost",
    "hryzat",
    "hubenost",
    "hubnout",
    "hudba",
    "hukot",
    "humr",
    "husita",
    "hustota",
    "hvozd",
    "hybnost",
    "hydrant",
    "hygiena",
    "hymna",
    "hysterik",
    "idylka",
    "ihned",
    "ikona",
    "iluze",
    "imunita",
    "infekce",
    "inflace",
    "inkaso",
    "inovace",
    "inspekce",
    "internet",
    "invalida",
    "investor",
    "inzerce",
    "ironie",
    "jablko",
    "jachta",
    "jahoda",
    "jakmile",
    "jakost",
    "jalovec",
    "jantar",
    "jarmark",
    "jaro",
    "jasan",
    "jasno",
    "jatka",
    "javor",
    "jazyk",
    "jedinec",
    "jedle",
    "jednatel",
    "jehlan",
    "jekot",
    "jelen",
    "jelito",
    "jemnost",
    "jenom",
    "jepice",
    "jeseter",
    "jevit",
    "jezdec",
    "jezero",
    "jinak",
    "jindy",
    "jinoch",
    "jiskra",
    "jistota",
    "jitrnice",
    "jizva",
    "jmenovat",
    "jogurt",
    "jurta",
    "kabaret",
    "kabel",
    "kabinet",
    "kachna",
    "kadet",
    "kadidlo",
    "kahan",
    "kajak",
    "kajuta",
    "kakao",
    "kaktus",
    "kalamita",
    "kalhoty",
    "kalibr",
    "kalnost",
    "kamera",
    "kamkoliv",
    "kamna",
    "kanibal",
    "kanoe",
    "kantor",
    "kapalina",
    "kapela",
    "kapitola",
    "kapka",
    "kaple",
    "kapota",
    "kapr",
    "kapusta",
    "kapybara",
    "karamel",
    "karotka",
    "karton",
    "kasa",
    "katalog",
    "katedra",
    "kauce",
    "kauza",
    "kavalec",
    "kazajka",
    "kazeta",
    "kazivost",
    "kdekoliv",
    "kdesi",
    "kedluben",
    "kemp",
    "keramika",
    "kino",
    "klacek",
    "kladivo",
    "klam",
    "klapot",
    "klasika",
    "klaun",
    "klec",
    "klenba",
    "klepat",
    "klesnout",
    "klid",
    "klima",
    "klisna",
    "klobouk",
    "klokan",
    "klopa",
    "kloub",
    "klubovna",
    "klusat",
    "kluzkost",
    "kmen",
    "kmitat",
    "kmotr",
    "kniha",
    "knot",
    "koalice",
    "koberec",
    "kobka",
    "kobliha",
    "kobyla",
    "kocour",
    "kohout",
    "kojenec",
    "kokos",
    "koktejl",
    "kolaps",
    "koleda",
    "kolize",
    "kolo",
    "komando",
    "kometa",
    "komik",
    "komnata",
    "komora",
    "kompas",
    "komunita",
    "konat",
    "koncept",
    "kondice",
    "konec",
    "konfese",
    "kongres",
    "konina",
    "konkurs",
    "kontakt",
    "konzerva",
    "kopanec",
    "kopie",
    "kopnout",
    "koprovka",
    "korbel",
    "korektor",
    "kormidlo",
    "koroptev",
    "korpus",
    "koruna",
    "koryto",
    "korzet",
    "kosatec",
    "kostka",
    "kotel",
    "kotleta",
    "kotoul",
    "koukat",
    "koupelna",
    "kousek",
    "kouzlo",
    "kovboj",
    "koza",
    "kozoroh",
    "krabice",
    "krach",
    "krajina",
    "kralovat",
    "krasopis",
    "kravata",
    "kredit",
    "krejcar",
    "kresba",
    "kreveta",
    "kriket",
    "kritik",
    "krize",
    "krkavec",
    "krmelec",
    "krmivo",
    "krocan",
    "krok",
    "kronika",
    "kropit",
    "kroupa",
    "krovka",
    "krtek",
    "kruhadlo",
    "krupice",
    "krutost",
    "krvinka",
    "krychle",
    "krypta",
    "krystal",
    "kryt",
    "kudlanka",
    "kufr",
    "kujnost",
    "kukla",
    "kulajda",
    "kulich",
    "kulka",
    "kulomet",
    "kultura",
    "kuna",
    "kupodivu",
    "kurt",
    "kurzor",
    "kutil",
    "kvalita",
    "kvasinka",
    "kvestor",
    "kynolog",
    "kyselina",
    "kytara",
    "kytice",
    "kytka",
    "kytovec",
    "kyvadlo",
    "labrador",
    "lachtan",
    "ladnost",
    "laik",
    "lakomec",
    "lamela",
    "lampa",
    "lanovka",
    "lasice",
    "laso",
    "lastura",
    "latinka",
    "lavina",
    "lebka",
    "leckdy",
    "leden",
    "lednice",
    "ledovka",
    "ledvina",
    "legenda",
    "legie",
    "legrace",
    "lehce",
    "lehkost",
    "lehnout",
    "lektvar",
    "lenochod",
    "lentilka",
    "lepenka",
    "lepidlo",
    "letadlo",
    "letec",
    "letmo",
    "letokruh",
    "levhart",
    "levitace",
    "levobok",
    "libra",
    "lichotka",
    "lidojed",
    "lidskost",
    "lihovina",
    "lijavec",
    "lilek",
    "limetka",
    "linie",
    "linka",
    "linoleum",
    "listopad",
    "litina",
    "litovat",
    "lobista",
    "lodivod",
    "logika",
    "logoped",
    "lokalita",
    "loket",
    "lomcovat",
    "lopata",
    "lopuch",
    "lord",
    "losos",
    "lotr",
    "loudal",
    "louh",
    "louka",
    "louskat",
    "lovec",
    "lstivost",
    "lucerna",
    "lucifer",
    "lump",
    "lusk",
    "lustrace",
    "lvice",
    "lyra",
    "lyrika",
    "lysina",
    "madam",
    "madlo",
    "magistr",
    "mahagon",
    "majetek",
    "majitel",
    "majorita",
    "makak",
    "makovice",
    "makrela",
    "malba",
    "malina",
    "malovat",
    "malvice",
    "maminka",
    "mandle",
    "manko",
    "marnost",
    "masakr",
    "maskot",
    "masopust",
    "matice",
    "matrika",
    "maturita",
    "mazanec",
    "mazivo",
    "mazlit",
    "mazurka",
    "mdloba",
    "mechanik",
    "meditace",
    "medovina",
    "melasa",
    "meloun",
    "mentolka",
    "metla",
    "metoda",
    "metr",
    "mezera",
    "migrace",
    "mihnout",
    "mihule",
    "mikina",
    "mikrofon",
    "milenec",
    "milimetr",
    "milost",
    "mimika",
    "mincovna",
    "minibar",
    "minomet",
    "minulost",
    "miska",
    "mistr",
    "mixovat",
    "mladost",
    "mlha",
    "mlhovina",
    "mlok",
    "mlsat",
    "mluvit",
    "mnich",
    "mnohem",
    "mobil",
    "mocnost",
    "modelka",
    "modlitba",
    "mohyla",
    "mokro",
    "molekula",
    "momentka",
    "monarcha",
    "monokl",
    "monstrum",
    "montovat",
    "monzun",
    "mosaz",
    "moskyt",
    "most",
    "motivace",
    "motorka",
    "motyka",
    "moucha",
    "moudrost",
    "mozaika",
    "mozek",
    "mozol",
    "mramor",
    "mravenec",
    "mrkev",
    "mrtvola",
    "mrzet",
    "mrzutost",
    "mstitel",
    "mudrc",
    "muflon",
    "mulat",
    "mumie",
    "munice",
    "muset",
    "mutace",
    "muzeum",
    "muzikant",
    "myslivec",
    "mzda",
    "nabourat",
    "nachytat",
    "nadace",
    "nadbytek",
    "nadhoz",
    "nadobro",
    "nadpis",
    "nahlas",
    "nahnat",
    "nahodile",
    "nahradit",
    "naivita",
    "najednou",
    "najisto",
    "najmout",
    "naklonit",
    "nakonec",
    "nakrmit",
    "nalevo",
    "namazat",
    "namluvit",
    "nanometr",
    "naoko",
    "naopak",
    "naostro",
    "napadat",
    "napevno",
    "naplnit",
    "napnout",
    "naposled",
    "naprosto",
    "narodit",
    "naruby",
    "narychlo",
    "nasadit",
    "nasekat",
    "naslepo",
    "nastat",
    "natolik",
    "navenek",
    "navrch",
    "navzdory",
    "nazvat",
    "nebe",
    "nechat",
    "necky",
    "nedaleko",
    "nedbat",
    "neduh",
    "negace",
    "nehet",
    "nehoda",
    "nejen",
    "nejprve",
    "neklid",
    "nelibost",
    "nemilost",
    "nemoc",
    "neochota",
    "neonka",
    "nepokoj",
    "nerost",
    "nerv",
    "nesmysl",
    "nesoulad",
    "netvor",
    "neuron",
    "nevina",
    "nezvykle",
    "nicota",
    "nijak",
    "nikam",
    "nikdy",
    "nikl",
    "nikterak",
    "nitro",
    "nocleh",
    "nohavice",
    "nominace",
    "nora",
    "norek",
    "nositel",
    "nosnost",
    "nouze",
    "noviny",
    "novota",
    "nozdra",
    "nuda",
    "nudle",
    "nuget",
    "nutit",
    "nutnost",
    "nutrie",
    "nymfa",
    "obal",
    "obarvit",
    "obava",
    "obdiv",
    "obec",
    "obehnat",
    "obejmout",
    "obezita",
    "obhajoba",
    "obilnice",
    "objasnit",
    "objekt",
    "obklopit",
    "oblast",
    "oblek",
    "obliba",
    "obloha",
    "obluda",
    "obnos",
    "obohatit",
    "obojek",
    "obout",
    "obrazec",
    "obrna",
    "obruba",
    "obrys",
    "obsah",
    "obsluha",
    "obstarat",
    "obuv",
    "obvaz",
    "obvinit",
    "obvod",
    "obvykle",
    "obyvatel",
    "obzor",
    "ocas",
    "ocel",
    "ocenit",
    "ochladit",
    "ochota",
    "ochrana",
    "ocitnout",
    "odboj",
    "odbyt",
    "odchod",
    "odcizit",
    "odebrat",
    "odeslat",
    "odevzdat",
    "odezva",
    "odhadce",
    "odhodit",
    "odjet",
    "odjinud",
    "odkaz",
    "odkoupit",
    "odliv",
    "odluka",
    "odmlka",
    "odolnost",
    "odpad",
    "odpis",
    "odplout",
    "odpor",
    "odpustit",
    "odpykat",
    "odrazka",
    "odsoudit",
    "odstup",
    "odsun",
    "odtok",
    "odtud",
    "odvaha",
    "odveta",
    "odvolat",
    "odvracet",
    "odznak",
    "ofina",
    "ofsajd",
    "ohlas",
    "ohnisko",
    "ohrada",
    "ohrozit",
    "ohryzek",
    "okap",
    "okenice",
    "oklika",
    "okno",
    "okouzlit",
    "okovy",
    "okrasa",
    "okres",
    "okrsek",
    "okruh",
    "okupant",
    "okurka",
    "okusit",
    "olejnina",
    "olizovat",
    "omak",
    "omeleta",
    "omezit",
    "omladina",
    "omlouvat",
    "omluva",
    "omyl",
    "onehdy",
    "opakovat",
    "opasek",
    "operace",
    "opice",
    "opilost",
    "opisovat",
    "opora",
    "opozice",
    "opravdu",
    "oproti",
    "orbital",
    "orchestr",
    "orgie",
    "orlice",
    "orloj",
    "ortel",
    "osada",
    "oschnout",
    "osika",
    "osivo",
    "oslava",
    "oslepit",
    "oslnit",
    "oslovit",
    "osnova",
    "osoba",
    "osolit",
    "ospalec",
    "osten",
    "ostraha",
    "ostuda",
    "ostych",
    "osvojit",
    "oteplit",
    "otisk",
    "otop",
    "otrhat",
    "otrlost",
    "otrok",
    "otruby",
    "otvor",
    "ovanout",
    "ovar",
    "oves",
    "ovlivnit",
    "ovoce",
    "oxid",
    "ozdoba",
    "pachatel",
    "pacient",
    "padouch",
    "pahorek",
    "pakt",
    "palanda",
    "palec",
    "palivo",
    "paluba",
    "pamflet",
    "pamlsek",
    "panenka",
    "panika",
    "panna",
    "panovat",
    "panstvo",
    "pantofle",
    "paprika",
    "parketa",
    "parodie",
    "parta",
    "paruka",
    "paryba",
    "paseka",
    "pasivita",
    "pastelka",
    "patent",
    "patrona",
    "pavouk",
    "pazneht",
    "pazourek",
    "pecka",
    "pedagog",
    "pejsek",
    "peklo",
    "peloton",
    "penalta",
    "pendrek",
    "penze",
    "periskop",
    "pero",
    "pestrost",
    "petarda",
    "petice",
    "petrolej",
    "pevnina",
    "pexeso",
    "pianista",
    "piha",
    "pijavice",
    "pikle",
    "piknik",
    "pilina",
    "pilnost",
    "pilulka",
    "pinzeta",
    "pipeta",
    "pisatel",
    "pistole",
    "pitevna",
    "pivnice",
    "pivovar",
    "placenta",
    "plakat",
    "plamen",
    "planeta",
    "plastika",
    "platit",
    "plavidlo",
    "plaz",
    "plech",
    "plemeno",
    "plenta",
    "ples",
    "pletivo",
    "plevel",
    "plivat",
    "plnit",
    "plno",
    "plocha",
    "plodina",
    "plomba",
    "plout",
    "pluk",
    "plyn",
    "pobavit",
    "pobyt",
    "pochod",
    "pocit",
    "poctivec",
    "podat",
    "podcenit",
    "podepsat",
    "podhled",
    "podivit",
    "podklad",
    "podmanit",
    "podnik",
    "podoba",
    "podpora",
    "podraz",
    "podstata",
    "podvod",
    "podzim",
    "poezie",
    "pohanka",
    "pohnutka",
    "pohovor",
    "pohroma",
    "pohyb",
    "pointa",
    "pojistka",
    "pojmout",
    "pokazit",
    "pokles",
    "pokoj",
    "pokrok",
    "pokuta",
    "pokyn",
    "poledne",
    "polibek",
    "polknout",
    "poloha",
    "polynom",
    "pomalu",
    "pominout",
    "pomlka",
    "pomoc",
    "pomsta",
    "pomyslet",
    "ponechat",
    "ponorka",
    "ponurost",
    "popadat",
    "popel",
    "popisek",
    "poplach",
    "poprosit",
    "popsat",
    "popud",
    "poradce",
    "porce",
    "porod",
    "porucha",
    "poryv",
    "posadit",
    "posed",
    "posila",
    "poskok",
    "poslanec",
    "posoudit",
    "pospolu",
    "postava",
    "posudek",
    "posyp",
    "potah",
    "potkan",
    "potlesk",
    "potomek",
    "potrava",
    "potupa",
    "potvora",
    "poukaz",
    "pouto",
    "pouzdro",
    "povaha",
    "povidla",
    "povlak",
    "povoz",
    "povrch",
    "povstat",
    "povyk",
    "povzdech",
    "pozdrav",
    "pozemek",
    "poznatek",
    "pozor",
    "pozvat",
    "pracovat",
    "prahory",
    "praktika",
    "prales",
    "praotec",
    "praporek",
    "prase",
    "pravda",
    "princip",
    "prkno",
    "probudit",
    "procento",
    "prodej",
    "profese",
    "prohra",
    "projekt",
    "prolomit",
    "promile",
    "pronikat",
    "propad",
    "prorok",
    "prosba",
    "proton",
    "proutek",
    "provaz",
    "prskavka",
    "prsten",
    "prudkost",
    "prut",
    "prvek",
    "prvohory",
    "psanec",
    "psovod",
    "pstruh",
    "ptactvo",
    "puberta",
    "puch",
    "pudl",
    "pukavec",
    "puklina",
    "pukrle",
    "pult",
    "pumpa",
    "punc",
    "pupen",
    "pusa",
    "pusinka",
    "pustina",
    "putovat",
    "putyka",
    "pyramida",
    "pysk",
    "pytel",
    "racek",
    "rachot",
    "radiace",
    "radnice",
    "radon",
    "raft",
    "ragby",
    "raketa",
    "rakovina",
    "rameno",
    "rampouch",
    "rande",
    "rarach",
    "rarita",
    "rasovna",
    "rastr",
    "ratolest",
    "razance",
    "razidlo",
    "reagovat",
    "reakce",
    "recept",
    "redaktor",
    "referent",
    "reflex",
    "rejnok",
    "reklama",
    "rekord",
    "rekrut",
    "rektor",
    "reputace",
    "revize",
    "revma",
    "revolver",
    "rezerva",
    "riskovat",
    "riziko",
    "robotika",
    "rodokmen",
    "rohovka",
    "rokle",
    "rokoko",
    "romaneto",
    "ropovod",
    "ropucha",
    "rorejs",
    "rosol",
    "rostlina",
    "rotmistr",
    "rotoped",
    "rotunda",
    "roubenka",
    "roucho",
    "roup",
    "roura",
    "rovina",
    "rovnice",
    "rozbor",
    "rozchod",
    "rozdat",
    "rozeznat",
    "rozhodce",
    "rozinka",
    "rozjezd",
    "rozkaz",
    "rozloha",
    "rozmar",
    "rozpad",
    "rozruch",
    "rozsah",
    "roztok",
    "rozum",
    "rozvod",
    "rubrika",
    "ruchadlo",
    "rukavice",
    "rukopis",
    "ryba",
    "rybolov",
    "rychlost",
    "rydlo",
    "rypadlo",
    "rytina",
    "ryzost",
    "sadista",
    "sahat",
    "sako",
    "samec",
    "samizdat",
    "samota",
    "sanitka",
    "sardinka",
    "sasanka",
    "satelit",
    "sazba",
    "sazenice",
    "sbor",
    "schovat",
    "sebranka",
    "secese",
    "sedadlo",
    "sediment",
    "sedlo",
    "sehnat",
    "sejmout",
    "sekera",
    "sekta",
    "sekunda",
    "sekvoje",
    "semeno",
    "seno",
    "servis",
    "sesadit",
    "seshora",
    "seskok",
    "seslat",
    "sestra",
    "sesuv",
    "sesypat",
    "setba",
    "setina",
    "setkat",
    "setnout",
    "setrvat",
    "sever",
    "seznam",
    "shoda",
    "shrnout",
    "sifon",
    "silnice",
    "sirka",
    "sirotek",
    "sirup",
    "situace",
    "skafandr",
    "skalisko",
    "skanzen",
    "skaut",
    "skeptik",
    "skica",
    "skladba",
    "sklenice",
    "sklo",
    "skluz",
    "skoba",
    "skokan",
    "skoro",
    "skripta",
    "skrz",
    "skupina",
    "skvost",
    "skvrna",
    "slabika",
    "sladidlo",
    "slanina",
    "slast",
    "slavnost",
    "sledovat",
    "slepec",
    "sleva",
    "slezina",
    "slib",
    "slina",
    "sliznice",
    "slon",
    "sloupek",
    "slovo",
    "sluch",
    "sluha",
    "slunce",
    "slupka",
    "slza",
    "smaragd",
    "smetana",
    "smilstvo",
    "smlouva",
    "smog",
    "smrad",
    "smrk",
    "smrtka",
    "smutek",
    "smysl",
    "snad",
    "snaha",
    "snob",
    "sobota",
    "socha",
    "sodovka",
    "sokol",
    "sopka",
    "sotva",
    "souboj",
    "soucit",
    "soudce",
    "souhlas",
    "soulad",
    "soumrak",
    "souprava",
    "soused",
    "soutok",
    "souviset",
    "spalovna",
    "spasitel",
    "spis",
    "splav",
    "spodek",
    "spojenec",
    "spolu",
    "sponzor",
    "spornost",
    "spousta",
    "sprcha",
    "spustit",
    "sranda",
    "sraz",
    "srdce",
    "srna",
    "srnec",
    "srovnat",
    "srpen",
    "srst",
    "srub",
    "stanice",
    "starosta",
    "statika",
    "stavba",
    "stehno",
    "stezka",
    "stodola",
    "stolek",
    "stopa",
    "storno",
    "stoupat",
    "strach",
    "stres",
    "strhnout",
    "strom",
    "struna",
    "studna",
    "stupnice",
    "stvol",
    "styk",
    "subjekt",
    "subtropy",
    "suchar",
    "sudost",
    "sukno",
    "sundat",
    "sunout",
    "surikata",
    "surovina",
    "svah",
    "svalstvo",
    "svetr",
    "svatba",
    "svazek",
    "svisle",
    "svitek",
    "svoboda",
    "svodidlo",
    "svorka",
    "svrab",
    "sykavka",
    "sykot",
    "synek",
    "synovec",
    "sypat",
    "sypkost",
    "syrovost",
    "sysel",
    "sytost",
    "tabletka",
    "tabule",
    "tahoun",
    "tajemno",
    "tajfun",
    "tajga",
    "tajit",
    "tajnost",
    "taktika",
    "tamhle",
    "tampon",
    "tancovat",
    "tanec",
    "tanker",
    "tapeta",
    "tavenina",
    "tazatel",
    "technika",
    "tehdy",
    "tekutina",
    "telefon",
    "temnota",
    "tendence",
    "tenista",
    "tenor",
    "teplota",
    "tepna",
    "teprve",
    "terapie",
    "termoska",
    "textil",
    "ticho",
    "tiskopis",
    "titulek",
    "tkadlec",
    "tkanina",
    "tlapka",
    "tleskat",
    "tlukot",
    "tlupa",
    "tmel",
    "toaleta",
    "topinka",
    "topol",
    "torzo",
    "touha",
    "toulec",
    "tradice",
    "traktor",
    "tramp",
    "trasa",
    "traverza",
    "trefit",
    "trest",
    "trezor",
    "trhavina",
    "trhlina",
    "trochu",
    "trojice",
    "troska",
    "trouba",
    "trpce",
    "trpitel",
    "trpkost",
    "trubec",
    "truchlit",
    "truhlice",
    "trus",
    "trvat",
    "tudy",
    "tuhnout",
    "tuhost",
    "tundra",
    "turista",
    "turnaj",
    "tuzemsko",
    "tvaroh",
    "tvorba",
    "tvrdost",
    "tvrz",
    "tygr",
    "tykev",
    "ubohost",
    "uboze",
    "ubrat",
    "ubrousek",
    "ubrus",
    "ubytovna",
    "ucho",
    "uctivost",
    "udivit",
    "uhradit",
    "ujednat",
    "ujistit",
    "ujmout",
    "ukazatel",
    "uklidnit",
    "uklonit",
    "ukotvit",
    "ukrojit",
    "ulice",
    "ulita",
    "ulovit",
    "umyvadlo",
    "unavit",
    "uniforma",
    "uniknout",
    "upadnout",
    "uplatnit",
    "uplynout",
    "upoutat",
    "upravit",
    "uran",
    "urazit",
    "usednout",
    "usilovat",
    "usmrtit",
    "usnadnit",
    "usnout",
    "usoudit",
    "ustlat",
    "ustrnout",
    "utahovat",
    "utkat",
    "utlumit",
    "utonout",
    "utopenec",
    "utrousit",
    "uvalit",
    "uvolnit",
    "uvozovka",
    "uzdravit",
    "uzel",
    "uzenina",
    "uzlina",
    "uznat",
    "vagon",
    "valcha",
    "valoun",
    "vana",
    "vandal",
    "vanilka",
    "varan",
    "varhany",
    "varovat",
    "vcelku",
    "vchod",
    "vdova",
    "vedro",
    "vegetace",
    "vejce",
    "velbloud",
    "veletrh",
    "velitel",
    "velmoc",
    "velryba",
    "venkov",
    "veranda",
    "verze",
    "veselka",
    "veskrze",
    "vesnice",
    "vespodu",
    "vesta",
    "veterina",
    "veverka",
    "vibrace",
    "vichr",
    "videohra",
    "vidina",
    "vidle",
    "vila",
    "vinice",
    "viset",
    "vitalita",
    "vize",
    "vizitka",
    "vjezd",
    "vklad",
    "vkus",
    "vlajka",
    "vlak",
    "vlasec",
    "vlevo",
    "vlhkost",
    "vliv",
    "vlnovka",
    "vloupat",
    "vnucovat",
    "vnuk",
    "voda",
    "vodivost",
    "vodoznak",
    "vodstvo",
    "vojensky",
    "vojna",
    "vojsko",
    "volant",
    "volba",
    "volit",
    "volno",
    "voskovka",
    "vozidlo",
    "vozovna",
    "vpravo",
    "vrabec",
    "vracet",
    "vrah",
    "vrata",
    "vrba",
    "vrcholek",
    "vrhat",
    "vrstva",
    "vrtule",
    "vsadit",
    "vstoupit",
    "vstup",
    "vtip",
    "vybavit",
    "vybrat",
    "vychovat",
    "vydat",
    "vydra",
    "vyfotit",
    "vyhledat",
    "vyhnout",
    "vyhodit",
    "vyhradit",
    "vyhubit",
    "vyjasnit",
    "vyjet",
    "vyjmout",
    "vyklopit",
    "vykonat",
    "vylekat",
    "vymazat",
    "vymezit",
    "vymizet",
    "vymyslet",
    "vynechat",
    "vynikat",
    "vynutit",
    "vypadat",
    "vyplatit",
    "vypravit",
    "vypustit",
    "vyrazit",
    "vyrovnat",
    "vyrvat",
    "vyslovit",
    "vysoko",
    "vystavit",
    "vysunout",
    "vysypat",
    "vytasit",
    "vytesat",
    "vytratit",
    "vyvinout",
    "vyvolat",
    "vyvrhel",
    "vyzdobit",
    "vyznat",
    "vzadu",
    "vzbudit",
    "vzchopit",
    "vzdor",
    "vzduch",
    "vzdychat",
    "vzestup",
    "vzhledem",
    "vzkaz",
    "vzlykat",
    "vznik",
    "vzorek",
    "vzpoura",
    "vztah",
    "vztek",
    "xylofon",
    "zabrat",
    "zabydlet",
    "zachovat",
    "zadarmo",
    "zadusit",
    "zafoukat",
    "zahltit",
    "zahodit",
    "zahrada",
    "zahynout",
    "zajatec",
    "zajet",
    "zajistit",
    "zaklepat",
    "zakoupit",
    "zalepit",
    "zamezit",
    "zamotat",
    "zamyslet",
    "zanechat",
    "zanikat",
    "zaplatit",
    "zapojit",
    "zapsat",
    "zarazit",
    "zastavit",
    "zasunout",
    "zatajit",
    "zatemnit",
    "zatknout",
    "zaujmout",
    "zavalit",
    "zavelet",
    "zavinit",
    "zavolat",
    "zavrtat",
    "zazvonit",
    "zbavit",
    "zbrusu",
    "zbudovat",
    "zbytek",
    "zdaleka",
    "zdarma",
    "zdatnost",
    "zdivo",
    "zdobit",
    "zdroj",
    "zdvih",
    "zdymadlo",
    "zelenina",
    "zeman",
    "zemina",
    "zeptat",
    "zezadu",
    "zezdola",
    "zhatit",
    "zhltnout",
    "zhluboka",
    "zhotovit",
    "zhruba",
    "zima",
    "zimnice",
    "zjemnit",
    "zklamat",
    "zkoumat",
    "zkratka",
    "zkumavka",
    "zlato",
    "zlehka",
    "zloba",
    "zlom",
    "zlost",
    "zlozvyk",
    "zmapovat",
    "zmar",
    "zmatek",
    "zmije",
    "zmizet",
    "zmocnit",
    "zmodrat",
    "zmrzlina",
    "zmutovat",
    "znak",
    "znalost",
    "znamenat",
    "znovu",
    "zobrazit",
    "zotavit",
    "zoubek",
    "zoufale",
    "zplodit",
    "zpomalit",
    "zprava",
    "zprostit",
    "zprudka",
    "zprvu",
    "zrada",
    "zranit",
    "zrcadlo",
    "zrnitost",
    "zrno",
    "zrovna",
    "zrychlit",
    "zrzavost",
    "zticha",
    "ztratit",
    "zubovina",
    "zubr",
    "zvednout",
    "zvenku",
    "zvesela",
    "zvon",
    "zvrat",
    "zvukovod",
    "zvyk"
]

},{}],49:[function(require,module,exports){
module.exports=[
    "abandon",
    "ability",
    "able",
    "about",
    "above",
    "absent",
    "absorb",
    "abstract",
    "absurd",
    "abuse",
    "access",
    "accident",
    "account",
    "accuse",
    "achieve",
    "acid",
    "acoustic",
    "acquire",
    "across",
    "act",
    "action",
    "actor",
    "actress",
    "actual",
    "adapt",
    "add",
    "addict",
    "address",
    "adjust",
    "admit",
    "adult",
    "advance",
    "advice",
    "aerobic",
    "affair",
    "afford",
    "afraid",
    "again",
    "age",
    "agent",
    "agree",
    "ahead",
    "aim",
    "air",
    "airport",
    "aisle",
    "alarm",
    "album",
    "alcohol",
    "alert",
    "alien",
    "all",
    "alley",
    "allow",
    "almost",
    "alone",
    "alpha",
    "already",
    "also",
    "alter",
    "always",
    "amateur",
    "amazing",
    "among",
    "amount",
    "amused",
    "analyst",
    "anchor",
    "ancient",
    "anger",
    "angle",
    "angry",
    "animal",
    "ankle",
    "announce",
    "annual",
    "another",
    "answer",
    "antenna",
    "antique",
    "anxiety",
    "any",
    "apart",
    "apology",
    "appear",
    "apple",
    "approve",
    "april",
    "arch",
    "arctic",
    "area",
    "arena",
    "argue",
    "arm",
    "armed",
    "armor",
    "army",
    "around",
    "arrange",
    "arrest",
    "arrive",
    "arrow",
    "art",
    "artefact",
    "artist",
    "artwork",
    "ask",
    "aspect",
    "assault",
    "asset",
    "assist",
    "assume",
    "asthma",
    "athlete",
    "atom",
    "attack",
    "attend",
    "attitude",
    "attract",
    "auction",
    "audit",
    "august",
    "aunt",
    "author",
    "auto",
    "autumn",
    "average",
    "avocado",
    "avoid",
    "awake",
    "aware",
    "away",
    "awesome",
    "awful",
    "awkward",
    "axis",
    "baby",
    "bachelor",
    "bacon",
    "badge",
    "bag",
    "balance",
    "balcony",
    "ball",
    "bamboo",
    "banana",
    "banner",
    "bar",
    "barely",
    "bargain",
    "barrel",
    "base",
    "basic",
    "basket",
    "battle",
    "beach",
    "bean",
    "beauty",
    "because",
    "become",
    "beef",
    "before",
    "begin",
    "behave",
    "behind",
    "believe",
    "below",
    "belt",
    "bench",
    "benefit",
    "best",
    "betray",
    "better",
    "between",
    "beyond",
    "bicycle",
    "bid",
    "bike",
    "bind",
    "biology",
    "bird",
    "birth",
    "bitter",
    "black",
    "blade",
    "blame",
    "blanket",
    "blast",
    "bleak",
    "bless",
    "blind",
    "blood",
    "blossom",
    "blouse",
    "blue",
    "blur",
    "blush",
    "board",
    "boat",
    "body",
    "boil",
    "bomb",
    "bone",
    "bonus",
    "book",
    "boost",
    "border",
    "boring",
    "borrow",
    "boss",
    "bottom",
    "bounce",
    "box",
    "boy",
    "bracket",
    "brain",
    "brand",
    "brass",
    "brave",
    "bread",
    "breeze",
    "brick",
    "bridge",
    "brief",
    "bright",
    "bring",
    "brisk",
    "broccoli",
    "broken",
    "bronze",
    "broom",
    "brother",
    "brown",
    "brush",
    "bubble",
    "buddy",
    "budget",
    "buffalo",
    "build",
    "bulb",
    "bulk",
    "bullet",
    "bundle",
    "bunker",
    "burden",
    "burger",
    "burst",
    "bus",
    "business",
    "busy",
    "butter",
    "buyer",
    "buzz",
    "cabbage",
    "cabin",
    "cable",
    "cactus",
    "cage",
    "cake",
    "call",
    "calm",
    "camera",
    "camp",
    "can",
    "canal",
    "cancel",
    "candy",
    "cannon",
    "canoe",
    "canvas",
    "canyon",
    "capable",
    "capital",
    "captain",
    "car",
    "carbon",
    "card",
    "cargo",
    "carpet",
    "carry",
    "cart",
    "case",
    "cash",
    "casino",
    "castle",
    "casual",
    "cat",
    "catalog",
    "catch",
    "category",
    "cattle",
    "caught",
    "cause",
    "caution",
    "cave",
    "ceiling",
    "celery",
    "cement",
    "census",
    "century",
    "cereal",
    "certain",
    "chair",
    "chalk",
    "champion",
    "change",
    "chaos",
    "chapter",
    "charge",
    "chase",
    "chat",
    "cheap",
    "check",
    "cheese",
    "chef",
    "cherry",
    "chest",
    "chicken",
    "chief",
    "child",
    "chimney",
    "choice",
    "choose",
    "chronic",
    "chuckle",
    "chunk",
    "churn",
    "cigar",
    "cinnamon",
    "circle",
    "citizen",
    "city",
    "civil",
    "claim",
    "clap",
    "clarify",
    "claw",
    "clay",
    "clean",
    "clerk",
    "clever",
    "click",
    "client",
    "cliff",
    "climb",
    "clinic",
    "clip",
    "clock",
    "clog",
    "close",
    "cloth",
    "cloud",
    "clown",
    "club",
    "clump",
    "cluster",
    "clutch",
    "coach",
    "coast",
    "coconut",
    "code",
    "coffee",
    "coil",
    "coin",
    "collect",
    "color",
    "column",
    "combine",
    "come",
    "comfort",
    "comic",
    "common",
    "company",
    "concert",
    "conduct",
    "confirm",
    "congress",
    "connect",
    "consider",
    "control",
    "convince",
    "cook",
    "cool",
    "copper",
    "copy",
    "coral",
    "core",
    "corn",
    "correct",
    "cost",
    "cotton",
    "couch",
    "country",
    "couple",
    "course",
    "cousin",
    "cover",
    "coyote",
    "crack",
    "cradle",
    "craft",
    "cram",
    "crane",
    "crash",
    "crater",
    "crawl",
    "crazy",
    "cream",
    "credit",
    "creek",
    "crew",
    "cricket",
    "crime",
    "crisp",
    "critic",
    "crop",
    "cross",
    "crouch",
    "crowd",
    "crucial",
    "cruel",
    "cruise",
    "crumble",
    "crunch",
    "crush",
    "cry",
    "crystal",
    "cube",
    "culture",
    "cup",
    "cupboard",
    "curious",
    "current",
    "curtain",
    "curve",
    "cushion",
    "custom",
    "cute",
    "cycle",
    "dad",
    "damage",
    "damp",
    "dance",
    "danger",
    "daring",
    "dash",
    "daughter",
    "dawn",
    "day",
    "deal",
    "debate",
    "debris",
    "decade",
    "december",
    "decide",
    "decline",
    "decorate",
    "decrease",
    "deer",
    "defense",
    "define",
    "defy",
    "degree",
    "delay",
    "deliver",
    "demand",
    "demise",
    "denial",
    "dentist",
    "deny",
    "depart",
    "depend",
    "deposit",
    "depth",
    "deputy",
    "derive",
    "describe",
    "desert",
    "design",
    "desk",
    "despair",
    "destroy",
    "detail",
    "detect",
    "develop",
    "device",
    "devote",
    "diagram",
    "dial",
    "diamond",
    "diary",
    "dice",
    "diesel",
    "diet",
    "differ",
    "digital",
    "dignity",
    "dilemma",
    "dinner",
    "dinosaur",
    "direct",
    "dirt",
    "disagree",
    "discover",
    "disease",
    "dish",
    "dismiss",
    "disorder",
    "display",
    "distance",
    "divert",
    "divide",
    "divorce",
    "dizzy",
    "doctor",
    "document",
    "dog",
    "doll",
    "dolphin",
    "domain",
    "donate",
    "donkey",
    "donor",
    "door",
    "dose",
    "double",
    "dove",
    "draft",
    "dragon",
    "drama",
    "drastic",
    "draw",
    "dream",
    "dress",
    "drift",
    "drill",
    "drink",
    "drip",
    "drive",
    "drop",
    "drum",
    "dry",
    "duck",
    "dumb",
    "dune",
    "during",
    "dust",
    "dutch",
    "duty",
    "dwarf",
    "dynamic",
    "eager",
    "eagle",
    "early",
    "earn",
    "earth",
    "easily",
    "east",
    "easy",
    "echo",
    "ecology",
    "economy",
    "edge",
    "edit",
    "educate",
    "effort",
    "egg",
    "eight",
    "either",
    "elbow",
    "elder",
    "electric",
    "elegant",
    "element",
    "elephant",
    "elevator",
    "elite",
    "else",
    "embark",
    "embody",
    "embrace",
    "emerge",
    "emotion",
    "employ",
    "empower",
    "empty",
    "enable",
    "enact",
    "end",
    "endless",
    "endorse",
    "enemy",
    "energy",
    "enforce",
    "engage",
    "engine",
    "enhance",
    "enjoy",
    "enlist",
    "enough",
    "enrich",
    "enroll",
    "ensure",
    "enter",
    "entire",
    "entry",
    "envelope",
    "episode",
    "equal",
    "equip",
    "era",
    "erase",
    "erode",
    "erosion",
    "error",
    "erupt",
    "escape",
    "essay",
    "essence",
    "estate",
    "eternal",
    "ethics",
    "evidence",
    "evil",
    "evoke",
    "evolve",
    "exact",
    "example",
    "excess",
    "exchange",
    "excite",
    "exclude",
    "excuse",
    "execute",
    "exercise",
    "exhaust",
    "exhibit",
    "exile",
    "exist",
    "exit",
    "exotic",
    "expand",
    "expect",
    "expire",
    "explain",
    "expose",
    "express",
    "extend",
    "extra",
    "eye",
    "eyebrow",
    "fabric",
    "face",
    "faculty",
    "fade",
    "faint",
    "faith",
    "fall",
    "false",
    "fame",
    "family",
    "famous",
    "fan",
    "fancy",
    "fantasy",
    "farm",
    "fashion",
    "fat",
    "fatal",
    "father",
    "fatigue",
    "fault",
    "favorite",
    "feature",
    "february",
    "federal",
    "fee",
    "feed",
    "feel",
    "female",
    "fence",
    "festival",
    "fetch",
    "fever",
    "few",
    "fiber",
    "fiction",
    "field",
    "figure",
    "file",
    "film",
    "filter",
    "final",
    "find",
    "fine",
    "finger",
    "finish",
    "fire",
    "firm",
    "first",
    "fiscal",
    "fish",
    "fit",
    "fitness",
    "fix",
    "flag",
    "flame",
    "flash",
    "flat",
    "flavor",
    "flee",
    "flight",
    "flip",
    "float",
    "flock",
    "floor",
    "flower",
    "fluid",
    "flush",
    "fly",
    "foam",
    "focus",
    "fog",
    "foil",
    "fold",
    "follow",
    "food",
    "foot",
    "force",
    "forest",
    "forget",
    "fork",
    "fortune",
    "forum",
    "forward",
    "fossil",
    "foster",
    "found",
    "fox",
    "fragile",
    "frame",
    "frequent",
    "fresh",
    "friend",
    "fringe",
    "frog",
    "front",
    "frost",
    "frown",
    "frozen",
    "fruit",
    "fuel",
    "fun",
    "funny",
    "furnace",
    "fury",
    "future",
    "gadget",
    "gain",
    "galaxy",
    "gallery",
    "game",
    "gap",
    "garage",
    "garbage",
    "garden",
    "garlic",
    "garment",
    "gas",
    "gasp",
    "gate",
    "gather",
    "gauge",
    "gaze",
    "general",
    "genius",
    "genre",
    "gentle",
    "genuine",
    "gesture",
    "ghost",
    "giant",
    "gift",
    "giggle",
    "ginger",
    "giraffe",
    "girl",
    "give",
    "glad",
    "glance",
    "glare",
    "glass",
    "glide",
    "glimpse",
    "globe",
    "gloom",
    "glory",
    "glove",
    "glow",
    "glue",
    "goat",
    "goddess",
    "gold",
    "good",
    "goose",
    "gorilla",
    "gospel",
    "gossip",
    "govern",
    "gown",
    "grab",
    "grace",
    "grain",
    "grant",
    "grape",
    "grass",
    "gravity",
    "great",
    "green",
    "grid",
    "grief",
    "grit",
    "grocery",
    "group",
    "grow",
    "grunt",
    "guard",
    "guess",
    "guide",
    "guilt",
    "guitar",
    "gun",
    "gym",
    "habit",
    "hair",
    "half",
    "hammer",
    "hamster",
    "hand",
    "happy",
    "harbor",
    "hard",
    "harsh",
    "harvest",
    "hat",
    "have",
    "hawk",
    "hazard",
    "head",
    "health",
    "heart",
    "heavy",
    "hedgehog",
    "height",
    "hello",
    "helmet",
    "help",
    "hen",
    "hero",
    "hidden",
    "high",
    "hill",
    "hint",
    "hip",
    "hire",
    "history",
    "hobby",
    "hockey",
    "hold",
    "hole",
    "holiday",
    "hollow",
    "home",
    "honey",
    "hood",
    "hope",
    "horn",
    "horror",
    "horse",
    "hospital",
    "host",
    "hotel",
    "hour",
    "hover",
    "hub",
    "huge",
    "human",
    "humble",
    "humor",
    "hundred",
    "hungry",
    "hunt",
    "hurdle",
    "hurry",
    "hurt",
    "husband",
    "hybrid",
    "ice",
    "icon",
    "idea",
    "identify",
    "idle",
    "ignore",
    "ill",
    "illegal",
    "illness",
    "image",
    "imitate",
    "immense",
    "immune",
    "impact",
    "impose",
    "improve",
    "impulse",
    "inch",
    "include",
    "income",
    "increase",
    "index",
    "indicate",
    "indoor",
    "industry",
    "infant",
    "inflict",
    "inform",
    "inhale",
    "inherit",
    "initial",
    "inject",
    "injury",
    "inmate",
    "inner",
    "innocent",
    "input",
    "inquiry",
    "insane",
    "insect",
    "inside",
    "inspire",
    "install",
    "intact",
    "interest",
    "into",
    "invest",
    "invite",
    "involve",
    "iron",
    "island",
    "isolate",
    "issue",
    "item",
    "ivory",
    "jacket",
    "jaguar",
    "jar",
    "jazz",
    "jealous",
    "jeans",
    "jelly",
    "jewel",
    "job",
    "join",
    "joke",
    "journey",
    "joy",
    "judge",
    "juice",
    "jump",
    "jungle",
    "junior",
    "junk",
    "just",
    "kangaroo",
    "keen",
    "keep",
    "ketchup",
    "key",
    "kick",
    "kid",
    "kidney",
    "kind",
    "kingdom",
    "kiss",
    "kit",
    "kitchen",
    "kite",
    "kitten",
    "kiwi",
    "knee",
    "knife",
    "knock",
    "know",
    "lab",
    "label",
    "labor",
    "ladder",
    "lady",
    "lake",
    "lamp",
    "language",
    "laptop",
    "large",
    "later",
    "latin",
    "laugh",
    "laundry",
    "lava",
    "law",
    "lawn",
    "lawsuit",
    "layer",
    "lazy",
    "leader",
    "leaf",
    "learn",
    "leave",
    "lecture",
    "left",
    "leg",
    "legal",
    "legend",
    "leisure",
    "lemon",
    "lend",
    "length",
    "lens",
    "leopard",
    "lesson",
    "letter",
    "level",
    "liar",
    "liberty",
    "library",
    "license",
    "life",
    "lift",
    "light",
    "like",
    "limb",
    "limit",
    "link",
    "lion",
    "liquid",
    "list",
    "little",
    "live",
    "lizard",
    "load",
    "loan",
    "lobster",
    "local",
    "lock",
    "logic",
    "lonely",
    "long",
    "loop",
    "lottery",
    "loud",
    "lounge",
    "love",
    "loyal",
    "lucky",
    "luggage",
    "lumber",
    "lunar",
    "lunch",
    "luxury",
    "lyrics",
    "machine",
    "mad",
    "magic",
    "magnet",
    "maid",
    "mail",
    "main",
    "major",
    "make",
    "mammal",
    "man",
    "manage",
    "mandate",
    "mango",
    "mansion",
    "manual",
    "maple",
    "marble",
    "march",
    "margin",
    "marine",
    "market",
    "marriage",
    "mask",
    "mass",
    "master",
    "match",
    "material",
    "math",
    "matrix",
    "matter",
    "maximum",
    "maze",
    "meadow",
    "mean",
    "measure",
    "meat",
    "mechanic",
    "medal",
    "media",
    "melody",
    "melt",
    "member",
    "memory",
    "mention",
    "menu",
    "mercy",
    "merge",
    "merit",
    "merry",
    "mesh",
    "message",
    "metal",
    "method",
    "middle",
    "midnight",
    "milk",
    "million",
    "mimic",
    "mind",
    "minimum",
    "minor",
    "minute",
    "miracle",
    "mirror",
    "misery",
    "miss",
    "mistake",
    "mix",
    "mixed",
    "mixture",
    "mobile",
    "model",
    "modify",
    "mom",
    "moment",
    "monitor",
    "monkey",
    "monster",
    "month",
    "moon",
    "moral",
    "more",
    "morning",
    "mosquito",
    "mother",
    "motion",
    "motor",
    "mountain",
    "mouse",
    "move",
    "movie",
    "much",
    "muffin",
    "mule",
    "multiply",
    "muscle",
    "museum",
    "mushroom",
    "music",
    "must",
    "mutual",
    "myself",
    "mystery",
    "myth",
    "naive",
    "name",
    "napkin",
    "narrow",
    "nasty",
    "nation",
    "nature",
    "near",
    "neck",
    "need",
    "negative",
    "neglect",
    "neither",
    "nephew",
    "nerve",
    "nest",
    "net",
    "network",
    "neutral",
    "never",
    "news",
    "next",
    "nice",
    "night",
    "noble",
    "noise",
    "nominee",
    "noodle",
    "normal",
    "north",
    "nose",
    "notable",
    "note",
    "nothing",
    "notice",
    "novel",
    "now",
    "nuclear",
    "number",
    "nurse",
    "nut",
    "oak",
    "obey",
    "object",
    "oblige",
    "obscure",
    "observe",
    "obtain",
    "obvious",
    "occur",
    "ocean",
    "october",
    "odor",
    "off",
    "offer",
    "office",
    "often",
    "oil",
    "okay",
    "old",
    "olive",
    "olympic",
    "omit",
    "once",
    "one",
    "onion",
    "online",
    "only",
    "open",
    "opera",
    "opinion",
    "oppose",
    "option",
    "orange",
    "orbit",
    "orchard",
    "order",
    "ordinary",
    "organ",
    "orient",
    "original",
    "orphan",
    "ostrich",
    "other",
    "outdoor",
    "outer",
    "output",
    "outside",
    "oval",
    "oven",
    "over",
    "own",
    "owner",
    "oxygen",
    "oyster",
    "ozone",
    "pact",
    "paddle",
    "page",
    "pair",
    "palace",
    "palm",
    "panda",
    "panel",
    "panic",
    "panther",
    "paper",
    "parade",
    "parent",
    "park",
    "parrot",
    "party",
    "pass",
    "patch",
    "path",
    "patient",
    "patrol",
    "pattern",
    "pause",
    "pave",
    "payment",
    "peace",
    "peanut",
    "pear",
    "peasant",
    "pelican",
    "pen",
    "penalty",
    "pencil",
    "people",
    "pepper",
    "perfect",
    "permit",
    "person",
    "pet",
    "phone",
    "photo",
    "phrase",
    "physical",
    "piano",
    "picnic",
    "picture",
    "piece",
    "pig",
    "pigeon",
    "pill",
    "pilot",
    "pink",
    "pioneer",
    "pipe",
    "pistol",
    "pitch",
    "pizza",
    "place",
    "planet",
    "plastic",
    "plate",
    "play",
    "please",
    "pledge",
    "pluck",
    "plug",
    "plunge",
    "poem",
    "poet",
    "point",
    "polar",
    "pole",
    "police",
    "pond",
    "pony",
    "pool",
    "popular",
    "portion",
    "position",
    "possible",
    "post",
    "potato",
    "pottery",
    "poverty",
    "powder",
    "power",
    "practice",
    "praise",
    "predict",
    "prefer",
    "prepare",
    "present",
    "pretty",
    "prevent",
    "price",
    "pride",
    "primary",
    "print",
    "priority",
    "prison",
    "private",
    "prize",
    "problem",
    "process",
    "produce",
    "profit",
    "program",
    "project",
    "promote",
    "proof",
    "property",
    "prosper",
    "protect",
    "proud",
    "provide",
    "public",
    "pudding",
    "pull",
    "pulp",
    "pulse",
    "pumpkin",
    "punch",
    "pupil",
    "puppy",
    "purchase",
    "purity",
    "purpose",
    "purse",
    "push",
    "put",
    "puzzle",
    "pyramid",
    "quality",
    "quantum",
    "quarter",
    "question",
    "quick",
    "quit",
    "quiz",
    "quote",
    "rabbit",
    "raccoon",
    "race",
    "rack",
    "radar",
    "radio",
    "rail",
    "rain",
    "raise",
    "rally",
    "ramp",
    "ranch",
    "random",
    "range",
    "rapid",
    "rare",
    "rate",
    "rather",
    "raven",
    "raw",
    "razor",
    "ready",
    "real",
    "reason",
    "rebel",
    "rebuild",
    "recall",
    "receive",
    "recipe",
    "record",
    "recycle",
    "reduce",
    "reflect",
    "reform",
    "refuse",
    "region",
    "regret",
    "regular",
    "reject",
    "relax",
    "release",
    "relief",
    "rely",
    "remain",
    "remember",
    "remind",
    "remove",
    "render",
    "renew",
    "rent",
    "reopen",
    "repair",
    "repeat",
    "replace",
    "report",
    "require",
    "rescue",
    "resemble",
    "resist",
    "resource",
    "response",
    "result",
    "retire",
    "retreat",
    "return",
    "reunion",
    "reveal",
    "review",
    "reward",
    "rhythm",
    "rib",
    "ribbon",
    "rice",
    "rich",
    "ride",
    "ridge",
    "rifle",
    "right",
    "rigid",
    "ring",
    "riot",
    "ripple",
    "risk",
    "ritual",
    "rival",
    "river",
    "road",
    "roast",
    "robot",
    "robust",
    "rocket",
    "romance",
    "roof",
    "rookie",
    "room",
    "rose",
    "rotate",
    "rough",
    "round",
    "route",
    "royal",
    "rubber",
    "rude",
    "rug",
    "rule",
    "run",
    "runway",
    "rural",
    "sad",
    "saddle",
    "sadness",
    "safe",
    "sail",
    "salad",
    "salmon",
    "salon",
    "salt",
    "salute",
    "same",
    "sample",
    "sand",
    "satisfy",
    "satoshi",
    "sauce",
    "sausage",
    "save",
    "say",
    "scale",
    "scan",
    "scare",
    "scatter",
    "scene",
    "scheme",
    "school",
    "science",
    "scissors",
    "scorpion",
    "scout",
    "scrap",
    "screen",
    "script",
    "scrub",
    "sea",
    "search",
    "season",
    "seat",
    "second",
    "secret",
    "section",
    "security",
    "seed",
    "seek",
    "segment",
    "select",
    "sell",
    "seminar",
    "senior",
    "sense",
    "sentence",
    "series",
    "service",
    "session",
    "settle",
    "setup",
    "seven",
    "shadow",
    "shaft",
    "shallow",
    "share",
    "shed",
    "shell",
    "sheriff",
    "shield",
    "shift",
    "shine",
    "ship",
    "shiver",
    "shock",
    "shoe",
    "shoot",
    "shop",
    "short",
    "shoulder",
    "shove",
    "shrimp",
    "shrug",
    "shuffle",
    "shy",
    "sibling",
    "sick",
    "side",
    "siege",
    "sight",
    "sign",
    "silent",
    "silk",
    "silly",
    "silver",
    "similar",
    "simple",
    "since",
    "sing",
    "siren",
    "sister",
    "situate",
    "six",
    "size",
    "skate",
    "sketch",
    "ski",
    "skill",
    "skin",
    "skirt",
    "skull",
    "slab",
    "slam",
    "sleep",
    "slender",
    "slice",
    "slide",
    "slight",
    "slim",
    "slogan",
    "slot",
    "slow",
    "slush",
    "small",
    "smart",
    "smile",
    "smoke",
    "smooth",
    "snack",
    "snake",
    "snap",
    "sniff",
    "snow",
    "soap",
    "soccer",
    "social",
    "sock",
    "soda",
    "soft",
    "solar",
    "soldier",
    "solid",
    "solution",
    "solve",
    "someone",
    "song",
    "soon",
    "sorry",
    "sort",
    "soul",
    "sound",
    "soup",
    "source",
    "south",
    "space",
    "spare",
    "spatial",
    "spawn",
    "speak",
    "special",
    "speed",
    "spell",
    "spend",
    "sphere",
    "spice",
    "spider",
    "spike",
    "spin",
    "spirit",
    "split",
    "spoil",
    "sponsor",
    "spoon",
    "sport",
    "spot",
    "spray",
    "spread",
    "spring",
    "spy",
    "square",
    "squeeze",
    "squirrel",
    "stable",
    "stadium",
    "staff",
    "stage",
    "stairs",
    "stamp",
    "stand",
    "start",
    "state",
    "stay",
    "steak",
    "steel",
    "stem",
    "step",
    "stereo",
    "stick",
    "still",
    "sting",
    "stock",
    "stomach",
    "stone",
    "stool",
    "story",
    "stove",
    "strategy",
    "street",
    "strike",
    "strong",
    "struggle",
    "student",
    "stuff",
    "stumble",
    "style",
    "subject",
    "submit",
    "subway",
    "success",
    "such",
    "sudden",
    "suffer",
    "sugar",
    "suggest",
    "suit",
    "summer",
    "sun",
    "sunny",
    "sunset",
    "super",
    "supply",
    "supreme",
    "sure",
    "surface",
    "surge",
    "surprise",
    "surround",
    "survey",
    "suspect",
    "sustain",
    "swallow",
    "swamp",
    "swap",
    "swarm",
    "swear",
    "sweet",
    "swift",
    "swim",
    "swing",
    "switch",
    "sword",
    "symbol",
    "symptom",
    "syrup",
    "system",
    "table",
    "tackle",
    "tag",
    "tail",
    "talent",
    "talk",
    "tank",
    "tape",
    "target",
    "task",
    "taste",
    "tattoo",
    "taxi",
    "teach",
    "team",
    "tell",
    "ten",
    "tenant",
    "tennis",
    "tent",
    "term",
    "test",
    "text",
    "thank",
    "that",
    "theme",
    "then",
    "theory",
    "there",
    "they",
    "thing",
    "this",
    "thought",
    "three",
    "thrive",
    "throw",
    "thumb",
    "thunder",
    "ticket",
    "tide",
    "tiger",
    "tilt",
    "timber",
    "time",
    "tiny",
    "tip",
    "tired",
    "tissue",
    "title",
    "toast",
    "tobacco",
    "today",
    "toddler",
    "toe",
    "together",
    "toilet",
    "token",
    "tomato",
    "tomorrow",
    "tone",
    "tongue",
    "tonight",
    "tool",
    "tooth",
    "top",
    "topic",
    "topple",
    "torch",
    "tornado",
    "tortoise",
    "toss",
    "total",
    "tourist",
    "toward",
    "tower",
    "town",
    "toy",
    "track",
    "trade",
    "traffic",
    "tragic",
    "train",
    "transfer",
    "trap",
    "trash",
    "travel",
    "tray",
    "treat",
    "tree",
    "trend",
    "trial",
    "tribe",
    "trick",
    "trigger",
    "trim",
    "trip",
    "trophy",
    "trouble",
    "truck",
    "true",
    "truly",
    "trumpet",
    "trust",
    "truth",
    "try",
    "tube",
    "tuition",
    "tumble",
    "tuna",
    "tunnel",
    "turkey",
    "turn",
    "turtle",
    "twelve",
    "twenty",
    "twice",
    "twin",
    "twist",
    "two",
    "type",
    "typical",
    "ugly",
    "umbrella",
    "unable",
    "unaware",
    "uncle",
    "uncover",
    "under",
    "undo",
    "unfair",
    "unfold",
    "unhappy",
    "uniform",
    "unique",
    "unit",
    "universe",
    "unknown",
    "unlock",
    "until",
    "unusual",
    "unveil",
    "update",
    "upgrade",
    "uphold",
    "upon",
    "upper",
    "upset",
    "urban",
    "urge",
    "usage",
    "use",
    "used",
    "useful",
    "useless",
    "usual",
    "utility",
    "vacant",
    "vacuum",
    "vague",
    "valid",
    "valley",
    "valve",
    "van",
    "vanish",
    "vapor",
    "various",
    "vast",
    "vault",
    "vehicle",
    "velvet",
    "vendor",
    "venture",
    "venue",
    "verb",
    "verify",
    "version",
    "very",
    "vessel",
    "veteran",
    "viable",
    "vibrant",
    "vicious",
    "victory",
    "video",
    "view",
    "village",
    "vintage",
    "violin",
    "virtual",
    "virus",
    "visa",
    "visit",
    "visual",
    "vital",
    "vivid",
    "vocal",
    "voice",
    "void",
    "volcano",
    "volume",
    "vote",
    "voyage",
    "wage",
    "wagon",
    "wait",
    "walk",
    "wall",
    "walnut",
    "want",
    "warfare",
    "warm",
    "warrior",
    "wash",
    "wasp",
    "waste",
    "water",
    "wave",
    "way",
    "wealth",
    "weapon",
    "wear",
    "weasel",
    "weather",
    "web",
    "wedding",
    "weekend",
    "weird",
    "welcome",
    "west",
    "wet",
    "whale",
    "what",
    "wheat",
    "wheel",
    "when",
    "where",
    "whip",
    "whisper",
    "wide",
    "width",
    "wife",
    "wild",
    "will",
    "win",
    "window",
    "wine",
    "wing",
    "wink",
    "winner",
    "winter",
    "wire",
    "wisdom",
    "wise",
    "wish",
    "witness",
    "wolf",
    "woman",
    "wonder",
    "wood",
    "wool",
    "word",
    "work",
    "world",
    "worry",
    "worth",
    "wrap",
    "wreck",
    "wrestle",
    "wrist",
    "write",
    "wrong",
    "yard",
    "year",
    "yellow",
    "you",
    "young",
    "youth",
    "zebra",
    "zero",
    "zone",
    "zoo"
]

},{}],50:[function(require,module,exports){
module.exports=[
    "abaisser",
    "abandon",
    "abdiquer",
    "abeille",
    "abolir",
    "aborder",
    "aboutir",
    "aboyer",
    "abrasif",
    "abreuver",
    "abriter",
    "abroger",
    "abrupt",
    "absence",
    "absolu",
    "absurde",
    "abusif",
    "abyssal",
    "académie",
    "acajou",
    "acarien",
    "accabler",
    "accepter",
    "acclamer",
    "accolade",
    "accroche",
    "accuser",
    "acerbe",
    "achat",
    "acheter",
    "aciduler",
    "acier",
    "acompte",
    "acquérir",
    "acronyme",
    "acteur",
    "actif",
    "actuel",
    "adepte",
    "adéquat",
    "adhésif",
    "adjectif",
    "adjuger",
    "admettre",
    "admirer",
    "adopter",
    "adorer",
    "adoucir",
    "adresse",
    "adroit",
    "adulte",
    "adverbe",
    "aérer",
    "aéronef",
    "affaire",
    "affecter",
    "affiche",
    "affreux",
    "affubler",
    "agacer",
    "agencer",
    "agile",
    "agiter",
    "agrafer",
    "agréable",
    "agrume",
    "aider",
    "aiguille",
    "ailier",
    "aimable",
    "aisance",
    "ajouter",
    "ajuster",
    "alarmer",
    "alchimie",
    "alerte",
    "algèbre",
    "algue",
    "aliéner",
    "aliment",
    "alléger",
    "alliage",
    "allouer",
    "allumer",
    "alourdir",
    "alpaga",
    "altesse",
    "alvéole",
    "amateur",
    "ambigu",
    "ambre",
    "aménager",
    "amertume",
    "amidon",
    "amiral",
    "amorcer",
    "amour",
    "amovible",
    "amphibie",
    "ampleur",
    "amusant",
    "analyse",
    "anaphore",
    "anarchie",
    "anatomie",
    "ancien",
    "anéantir",
    "angle",
    "angoisse",
    "anguleux",
    "animal",
    "annexer",
    "annonce",
    "annuel",
    "anodin",
    "anomalie",
    "anonyme",
    "anormal",
    "antenne",
    "antidote",
    "anxieux",
    "apaiser",
    "apéritif",
    "aplanir",
    "apologie",
    "appareil",
    "appeler",
    "apporter",
    "appuyer",
    "aquarium",
    "aqueduc",
    "arbitre",
    "arbuste",
    "ardeur",
    "ardoise",
    "argent",
    "arlequin",
    "armature",
    "armement",
    "armoire",
    "armure",
    "arpenter",
    "arracher",
    "arriver",
    "arroser",
    "arsenic",
    "artériel",
    "article",
    "aspect",
    "asphalte",
    "aspirer",
    "assaut",
    "asservir",
    "assiette",
    "associer",
    "assurer",
    "asticot",
    "astre",
    "astuce",
    "atelier",
    "atome",
    "atrium",
    "atroce",
    "attaque",
    "attentif",
    "attirer",
    "attraper",
    "aubaine",
    "auberge",
    "audace",
    "audible",
    "augurer",
    "aurore",
    "automne",
    "autruche",
    "avaler",
    "avancer",
    "avarice",
    "avenir",
    "averse",
    "aveugle",
    "aviateur",
    "avide",
    "avion",
    "aviser",
    "avoine",
    "avouer",
    "avril",
    "axial",
    "axiome",
    "badge",
    "bafouer",
    "bagage",
    "baguette",
    "baignade",
    "balancer",
    "balcon",
    "baleine",
    "balisage",
    "bambin",
    "bancaire",
    "bandage",
    "banlieue",
    "bannière",
    "banquier",
    "barbier",
    "baril",
    "baron",
    "barque",
    "barrage",
    "bassin",
    "bastion",
    "bataille",
    "bateau",
    "batterie",
    "baudrier",
    "bavarder",
    "belette",
    "bélier",
    "belote",
    "bénéfice",
    "berceau",
    "berger",
    "berline",
    "bermuda",
    "besace",
    "besogne",
    "bétail",
    "beurre",
    "biberon",
    "bicycle",
    "bidule",
    "bijou",
    "bilan",
    "bilingue",
    "billard",
    "binaire",
    "biologie",
    "biopsie",
    "biotype",
    "biscuit",
    "bison",
    "bistouri",
    "bitume",
    "bizarre",
    "blafard",
    "blague",
    "blanchir",
    "blessant",
    "blinder",
    "blond",
    "bloquer",
    "blouson",
    "bobard",
    "bobine",
    "boire",
    "boiser",
    "bolide",
    "bonbon",
    "bondir",
    "bonheur",
    "bonifier",
    "bonus",
    "bordure",
    "borne",
    "botte",
    "boucle",
    "boueux",
    "bougie",
    "boulon",
    "bouquin",
    "bourse",
    "boussole",
    "boutique",
    "boxeur",
    "branche",
    "brasier",
    "brave",
    "brebis",
    "brèche",
    "breuvage",
    "bricoler",
    "brigade",
    "brillant",
    "brioche",
    "brique",
    "brochure",
    "broder",
    "bronzer",
    "brousse",
    "broyeur",
    "brume",
    "brusque",
    "brutal",
    "bruyant",
    "buffle",
    "buisson",
    "bulletin",
    "bureau",
    "burin",
    "bustier",
    "butiner",
    "butoir",
    "buvable",
    "buvette",
    "cabanon",
    "cabine",
    "cachette",
    "cadeau",
    "cadre",
    "caféine",
    "caillou",
    "caisson",
    "calculer",
    "calepin",
    "calibre",
    "calmer",
    "calomnie",
    "calvaire",
    "camarade",
    "caméra",
    "camion",
    "campagne",
    "canal",
    "caneton",
    "canon",
    "cantine",
    "canular",
    "capable",
    "caporal",
    "caprice",
    "capsule",
    "capter",
    "capuche",
    "carabine",
    "carbone",
    "caresser",
    "caribou",
    "carnage",
    "carotte",
    "carreau",
    "carton",
    "cascade",
    "casier",
    "casque",
    "cassure",
    "causer",
    "caution",
    "cavalier",
    "caverne",
    "caviar",
    "cédille",
    "ceinture",
    "céleste",
    "cellule",
    "cendrier",
    "censurer",
    "central",
    "cercle",
    "cérébral",
    "cerise",
    "cerner",
    "cerveau",
    "cesser",
    "chagrin",
    "chaise",
    "chaleur",
    "chambre",
    "chance",
    "chapitre",
    "charbon",
    "chasseur",
    "chaton",
    "chausson",
    "chavirer",
    "chemise",
    "chenille",
    "chéquier",
    "chercher",
    "cheval",
    "chien",
    "chiffre",
    "chignon",
    "chimère",
    "chiot",
    "chlorure",
    "chocolat",
    "choisir",
    "chose",
    "chouette",
    "chrome",
    "chute",
    "cigare",
    "cigogne",
    "cimenter",
    "cinéma",
    "cintrer",
    "circuler",
    "cirer",
    "cirque",
    "citerne",
    "citoyen",
    "citron",
    "civil",
    "clairon",
    "clameur",
    "claquer",
    "classe",
    "clavier",
    "client",
    "cligner",
    "climat",
    "clivage",
    "cloche",
    "clonage",
    "cloporte",
    "cobalt",
    "cobra",
    "cocasse",
    "cocotier",
    "coder",
    "codifier",
    "coffre",
    "cogner",
    "cohésion",
    "coiffer",
    "coincer",
    "colère",
    "colibri",
    "colline",
    "colmater",
    "colonel",
    "combat",
    "comédie",
    "commande",
    "compact",
    "concert",
    "conduire",
    "confier",
    "congeler",
    "connoter",
    "consonne",
    "contact",
    "convexe",
    "copain",
    "copie",
    "corail",
    "corbeau",
    "cordage",
    "corniche",
    "corpus",
    "correct",
    "cortège",
    "cosmique",
    "costume",
    "coton",
    "coude",
    "coupure",
    "courage",
    "couteau",
    "couvrir",
    "coyote",
    "crabe",
    "crainte",
    "cravate",
    "crayon",
    "créature",
    "créditer",
    "crémeux",
    "creuser",
    "crevette",
    "cribler",
    "crier",
    "cristal",
    "critère",
    "croire",
    "croquer",
    "crotale",
    "crucial",
    "cruel",
    "crypter",
    "cubique",
    "cueillir",
    "cuillère",
    "cuisine",
    "cuivre",
    "culminer",
    "cultiver",
    "cumuler",
    "cupide",
    "curatif",
    "curseur",
    "cyanure",
    "cycle",
    "cylindre",
    "cynique",
    "daigner",
    "damier",
    "danger",
    "danseur",
    "dauphin",
    "débattre",
    "débiter",
    "déborder",
    "débrider",
    "débutant",
    "décaler",
    "décembre",
    "déchirer",
    "décider",
    "déclarer",
    "décorer",
    "décrire",
    "décupler",
    "dédale",
    "déductif",
    "déesse",
    "défensif",
    "défiler",
    "défrayer",
    "dégager",
    "dégivrer",
    "déglutir",
    "dégrafer",
    "déjeuner",
    "délice",
    "déloger",
    "demander",
    "demeurer",
    "démolir",
    "dénicher",
    "dénouer",
    "dentelle",
    "dénuder",
    "départ",
    "dépenser",
    "déphaser",
    "déplacer",
    "déposer",
    "déranger",
    "dérober",
    "désastre",
    "descente",
    "désert",
    "désigner",
    "désobéir",
    "dessiner",
    "destrier",
    "détacher",
    "détester",
    "détourer",
    "détresse",
    "devancer",
    "devenir",
    "deviner",
    "devoir",
    "diable",
    "dialogue",
    "diamant",
    "dicter",
    "différer",
    "digérer",
    "digital",
    "digne",
    "diluer",
    "dimanche",
    "diminuer",
    "dioxyde",
    "directif",
    "diriger",
    "discuter",
    "disposer",
    "dissiper",
    "distance",
    "divertir",
    "diviser",
    "docile",
    "docteur",
    "dogme",
    "doigt",
    "domaine",
    "domicile",
    "dompter",
    "donateur",
    "donjon",
    "donner",
    "dopamine",
    "dortoir",
    "dorure",
    "dosage",
    "doseur",
    "dossier",
    "dotation",
    "douanier",
    "double",
    "douceur",
    "douter",
    "doyen",
    "dragon",
    "draper",
    "dresser",
    "dribbler",
    "droiture",
    "duperie",
    "duplexe",
    "durable",
    "durcir",
    "dynastie",
    "éblouir",
    "écarter",
    "écharpe",
    "échelle",
    "éclairer",
    "éclipse",
    "éclore",
    "écluse",
    "école",
    "économie",
    "écorce",
    "écouter",
    "écraser",
    "écrémer",
    "écrivain",
    "écrou",
    "écume",
    "écureuil",
    "édifier",
    "éduquer",
    "effacer",
    "effectif",
    "effigie",
    "effort",
    "effrayer",
    "effusion",
    "égaliser",
    "égarer",
    "éjecter",
    "élaborer",
    "élargir",
    "électron",
    "élégant",
    "éléphant",
    "élève",
    "éligible",
    "élitisme",
    "éloge",
    "élucider",
    "éluder",
    "emballer",
    "embellir",
    "embryon",
    "émeraude",
    "émission",
    "emmener",
    "émotion",
    "émouvoir",
    "empereur",
    "employer",
    "emporter",
    "emprise",
    "émulsion",
    "encadrer",
    "enchère",
    "enclave",
    "encoche",
    "endiguer",
    "endosser",
    "endroit",
    "enduire",
    "énergie",
    "enfance",
    "enfermer",
    "enfouir",
    "engager",
    "engin",
    "englober",
    "énigme",
    "enjamber",
    "enjeu",
    "enlever",
    "ennemi",
    "ennuyeux",
    "enrichir",
    "enrobage",
    "enseigne",
    "entasser",
    "entendre",
    "entier",
    "entourer",
    "entraver",
    "énumérer",
    "envahir",
    "enviable",
    "envoyer",
    "enzyme",
    "éolien",
    "épaissir",
    "épargne",
    "épatant",
    "épaule",
    "épicerie",
    "épidémie",
    "épier",
    "épilogue",
    "épine",
    "épisode",
    "épitaphe",
    "époque",
    "épreuve",
    "éprouver",
    "épuisant",
    "équerre",
    "équipe",
    "ériger",
    "érosion",
    "erreur",
    "éruption",
    "escalier",
    "espadon",
    "espèce",
    "espiègle",
    "espoir",
    "esprit",
    "esquiver",
    "essayer",
    "essence",
    "essieu",
    "essorer",
    "estime",
    "estomac",
    "estrade",
    "étagère",
    "étaler",
    "étanche",
    "étatique",
    "éteindre",
    "étendoir",
    "éternel",
    "éthanol",
    "éthique",
    "ethnie",
    "étirer",
    "étoffer",
    "étoile",
    "étonnant",
    "étourdir",
    "étrange",
    "étroit",
    "étude",
    "euphorie",
    "évaluer",
    "évasion",
    "éventail",
    "évidence",
    "éviter",
    "évolutif",
    "évoquer",
    "exact",
    "exagérer",
    "exaucer",
    "exceller",
    "excitant",
    "exclusif",
    "excuse",
    "exécuter",
    "exemple",
    "exercer",
    "exhaler",
    "exhorter",
    "exigence",
    "exiler",
    "exister",
    "exotique",
    "expédier",
    "explorer",
    "exposer",
    "exprimer",
    "exquis",
    "extensif",
    "extraire",
    "exulter",
    "fable",
    "fabuleux",
    "facette",
    "facile",
    "facture",
    "faiblir",
    "falaise",
    "fameux",
    "famille",
    "farceur",
    "farfelu",
    "farine",
    "farouche",
    "fasciner",
    "fatal",
    "fatigue",
    "faucon",
    "fautif",
    "faveur",
    "favori",
    "fébrile",
    "féconder",
    "fédérer",
    "félin",
    "femme",
    "fémur",
    "fendoir",
    "féodal",
    "fermer",
    "féroce",
    "ferveur",
    "festival",
    "feuille",
    "feutre",
    "février",
    "fiasco",
    "ficeler",
    "fictif",
    "fidèle",
    "figure",
    "filature",
    "filetage",
    "filière",
    "filleul",
    "filmer",
    "filou",
    "filtrer",
    "financer",
    "finir",
    "fiole",
    "firme",
    "fissure",
    "fixer",
    "flairer",
    "flamme",
    "flasque",
    "flatteur",
    "fléau",
    "flèche",
    "fleur",
    "flexion",
    "flocon",
    "flore",
    "fluctuer",
    "fluide",
    "fluvial",
    "folie",
    "fonderie",
    "fongible",
    "fontaine",
    "forcer",
    "forgeron",
    "formuler",
    "fortune",
    "fossile",
    "foudre",
    "fougère",
    "fouiller",
    "foulure",
    "fourmi",
    "fragile",
    "fraise",
    "franchir",
    "frapper",
    "frayeur",
    "frégate",
    "freiner",
    "frelon",
    "frémir",
    "frénésie",
    "frère",
    "friable",
    "friction",
    "frisson",
    "frivole",
    "froid",
    "fromage",
    "frontal",
    "frotter",
    "fruit",
    "fugitif",
    "fuite",
    "fureur",
    "furieux",
    "furtif",
    "fusion",
    "futur",
    "gagner",
    "galaxie",
    "galerie",
    "gambader",
    "garantir",
    "gardien",
    "garnir",
    "garrigue",
    "gazelle",
    "gazon",
    "géant",
    "gélatine",
    "gélule",
    "gendarme",
    "général",
    "génie",
    "genou",
    "gentil",
    "géologie",
    "géomètre",
    "géranium",
    "germe",
    "gestuel",
    "geyser",
    "gibier",
    "gicler",
    "girafe",
    "givre",
    "glace",
    "glaive",
    "glisser",
    "globe",
    "gloire",
    "glorieux",
    "golfeur",
    "gomme",
    "gonfler",
    "gorge",
    "gorille",
    "goudron",
    "gouffre",
    "goulot",
    "goupille",
    "gourmand",
    "goutte",
    "graduel",
    "graffiti",
    "graine",
    "grand",
    "grappin",
    "gratuit",
    "gravir",
    "grenat",
    "griffure",
    "griller",
    "grimper",
    "grogner",
    "gronder",
    "grotte",
    "groupe",
    "gruger",
    "grutier",
    "gruyère",
    "guépard",
    "guerrier",
    "guide",
    "guimauve",
    "guitare",
    "gustatif",
    "gymnaste",
    "gyrostat",
    "habitude",
    "hachoir",
    "halte",
    "hameau",
    "hangar",
    "hanneton",
    "haricot",
    "harmonie",
    "harpon",
    "hasard",
    "hélium",
    "hématome",
    "herbe",
    "hérisson",
    "hermine",
    "héron",
    "hésiter",
    "heureux",
    "hiberner",
    "hibou",
    "hilarant",
    "histoire",
    "hiver",
    "homard",
    "hommage",
    "homogène",
    "honneur",
    "honorer",
    "honteux",
    "horde",
    "horizon",
    "horloge",
    "hormone",
    "horrible",
    "houleux",
    "housse",
    "hublot",
    "huileux",
    "humain",
    "humble",
    "humide",
    "humour",
    "hurler",
    "hydromel",
    "hygiène",
    "hymne",
    "hypnose",
    "idylle",
    "ignorer",
    "iguane",
    "illicite",
    "illusion",
    "image",
    "imbiber",
    "imiter",
    "immense",
    "immobile",
    "immuable",
    "impact",
    "impérial",
    "implorer",
    "imposer",
    "imprimer",
    "imputer",
    "incarner",
    "incendie",
    "incident",
    "incliner",
    "incolore",
    "indexer",
    "indice",
    "inductif",
    "inédit",
    "ineptie",
    "inexact",
    "infini",
    "infliger",
    "informer",
    "infusion",
    "ingérer",
    "inhaler",
    "inhiber",
    "injecter",
    "injure",
    "innocent",
    "inoculer",
    "inonder",
    "inscrire",
    "insecte",
    "insigne",
    "insolite",
    "inspirer",
    "instinct",
    "insulter",
    "intact",
    "intense",
    "intime",
    "intrigue",
    "intuitif",
    "inutile",
    "invasion",
    "inventer",
    "inviter",
    "invoquer",
    "ironique",
    "irradier",
    "irréel",
    "irriter",
    "isoler",
    "ivoire",
    "ivresse",
    "jaguar",
    "jaillir",
    "jambe",
    "janvier",
    "jardin",
    "jauger",
    "jaune",
    "javelot",
    "jetable",
    "jeton",
    "jeudi",
    "jeunesse",
    "joindre",
    "joncher",
    "jongler",
    "joueur",
    "jouissif",
    "journal",
    "jovial",
    "joyau",
    "joyeux",
    "jubiler",
    "jugement",
    "junior",
    "jupon",
    "juriste",
    "justice",
    "juteux",
    "juvénile",
    "kayak",
    "kimono",
    "kiosque",
    "label",
    "labial",
    "labourer",
    "lacérer",
    "lactose",
    "lagune",
    "laine",
    "laisser",
    "laitier",
    "lambeau",
    "lamelle",
    "lampe",
    "lanceur",
    "langage",
    "lanterne",
    "lapin",
    "largeur",
    "larme",
    "laurier",
    "lavabo",
    "lavoir",
    "lecture",
    "légal",
    "léger",
    "légume",
    "lessive",
    "lettre",
    "levier",
    "lexique",
    "lézard",
    "liasse",
    "libérer",
    "libre",
    "licence",
    "licorne",
    "liège",
    "lièvre",
    "ligature",
    "ligoter",
    "ligue",
    "limer",
    "limite",
    "limonade",
    "limpide",
    "linéaire",
    "lingot",
    "lionceau",
    "liquide",
    "lisière",
    "lister",
    "lithium",
    "litige",
    "littoral",
    "livreur",
    "logique",
    "lointain",
    "loisir",
    "lombric",
    "loterie",
    "louer",
    "lourd",
    "loutre",
    "louve",
    "loyal",
    "lubie",
    "lucide",
    "lucratif",
    "lueur",
    "lugubre",
    "luisant",
    "lumière",
    "lunaire",
    "lundi",
    "luron",
    "lutter",
    "luxueux",
    "machine",
    "magasin",
    "magenta",
    "magique",
    "maigre",
    "maillon",
    "maintien",
    "mairie",
    "maison",
    "majorer",
    "malaxer",
    "maléfice",
    "malheur",
    "malice",
    "mallette",
    "mammouth",
    "mandater",
    "maniable",
    "manquant",
    "manteau",
    "manuel",
    "marathon",
    "marbre",
    "marchand",
    "mardi",
    "maritime",
    "marqueur",
    "marron",
    "marteler",
    "mascotte",
    "massif",
    "matériel",
    "matière",
    "matraque",
    "maudire",
    "maussade",
    "mauve",
    "maximal",
    "méchant",
    "méconnu",
    "médaille",
    "médecin",
    "méditer",
    "méduse",
    "meilleur",
    "mélange",
    "mélodie",
    "membre",
    "mémoire",
    "menacer",
    "mener",
    "menhir",
    "mensonge",
    "mentor",
    "mercredi",
    "mérite",
    "merle",
    "messager",
    "mesure",
    "métal",
    "météore",
    "méthode",
    "métier",
    "meuble",
    "miauler",
    "microbe",
    "miette",
    "mignon",
    "migrer",
    "milieu",
    "million",
    "mimique",
    "mince",
    "minéral",
    "minimal",
    "minorer",
    "minute",
    "miracle",
    "miroiter",
    "missile",
    "mixte",
    "mobile",
    "moderne",
    "moelleux",
    "mondial",
    "moniteur",
    "monnaie",
    "monotone",
    "monstre",
    "montagne",
    "monument",
    "moqueur",
    "morceau",
    "morsure",
    "mortier",
    "moteur",
    "motif",
    "mouche",
    "moufle",
    "moulin",
    "mousson",
    "mouton",
    "mouvant",
    "multiple",
    "munition",
    "muraille",
    "murène",
    "murmure",
    "muscle",
    "muséum",
    "musicien",
    "mutation",
    "muter",
    "mutuel",
    "myriade",
    "myrtille",
    "mystère",
    "mythique",
    "nageur",
    "nappe",
    "narquois",
    "narrer",
    "natation",
    "nation",
    "nature",
    "naufrage",
    "nautique",
    "navire",
    "nébuleux",
    "nectar",
    "néfaste",
    "négation",
    "négliger",
    "négocier",
    "neige",
    "nerveux",
    "nettoyer",
    "neurone",
    "neutron",
    "neveu",
    "niche",
    "nickel",
    "nitrate",
    "niveau",
    "noble",
    "nocif",
    "nocturne",
    "noirceur",
    "noisette",
    "nomade",
    "nombreux",
    "nommer",
    "normatif",
    "notable",
    "notifier",
    "notoire",
    "nourrir",
    "nouveau",
    "novateur",
    "novembre",
    "novice",
    "nuage",
    "nuancer",
    "nuire",
    "nuisible",
    "numéro",
    "nuptial",
    "nuque",
    "nutritif",
    "obéir",
    "objectif",
    "obliger",
    "obscur",
    "observer",
    "obstacle",
    "obtenir",
    "obturer",
    "occasion",
    "occuper",
    "océan",
    "octobre",
    "octroyer",
    "octupler",
    "oculaire",
    "odeur",
    "odorant",
    "offenser",
    "officier",
    "offrir",
    "ogive",
    "oiseau",
    "oisillon",
    "olfactif",
    "olivier",
    "ombrage",
    "omettre",
    "onctueux",
    "onduler",
    "onéreux",
    "onirique",
    "opale",
    "opaque",
    "opérer",
    "opinion",
    "opportun",
    "opprimer",
    "opter",
    "optique",
    "orageux",
    "orange",
    "orbite",
    "ordonner",
    "oreille",
    "organe",
    "orgueil",
    "orifice",
    "ornement",
    "orque",
    "ortie",
    "osciller",
    "osmose",
    "ossature",
    "otarie",
    "ouragan",
    "ourson",
    "outil",
    "outrager",
    "ouvrage",
    "ovation",
    "oxyde",
    "oxygène",
    "ozone",
    "paisible",
    "palace",
    "palmarès",
    "palourde",
    "palper",
    "panache",
    "panda",
    "pangolin",
    "paniquer",
    "panneau",
    "panorama",
    "pantalon",
    "papaye",
    "papier",
    "papoter",
    "papyrus",
    "paradoxe",
    "parcelle",
    "paresse",
    "parfumer",
    "parler",
    "parole",
    "parrain",
    "parsemer",
    "partager",
    "parure",
    "parvenir",
    "passion",
    "pastèque",
    "paternel",
    "patience",
    "patron",
    "pavillon",
    "pavoiser",
    "payer",
    "paysage",
    "peigne",
    "peintre",
    "pelage",
    "pélican",
    "pelle",
    "pelouse",
    "peluche",
    "pendule",
    "pénétrer",
    "pénible",
    "pensif",
    "pénurie",
    "pépite",
    "péplum",
    "perdrix",
    "perforer",
    "période",
    "permuter",
    "perplexe",
    "persil",
    "perte",
    "peser",
    "pétale",
    "petit",
    "pétrir",
    "peuple",
    "pharaon",
    "phobie",
    "phoque",
    "photon",
    "phrase",
    "physique",
    "piano",
    "pictural",
    "pièce",
    "pierre",
    "pieuvre",
    "pilote",
    "pinceau",
    "pipette",
    "piquer",
    "pirogue",
    "piscine",
    "piston",
    "pivoter",
    "pixel",
    "pizza",
    "placard",
    "plafond",
    "plaisir",
    "planer",
    "plaque",
    "plastron",
    "plateau",
    "pleurer",
    "plexus",
    "pliage",
    "plomb",
    "plonger",
    "pluie",
    "plumage",
    "pochette",
    "poésie",
    "poète",
    "pointe",
    "poirier",
    "poisson",
    "poivre",
    "polaire",
    "policier",
    "pollen",
    "polygone",
    "pommade",
    "pompier",
    "ponctuel",
    "pondérer",
    "poney",
    "portique",
    "position",
    "posséder",
    "posture",
    "potager",
    "poteau",
    "potion",
    "pouce",
    "poulain",
    "poumon",
    "pourpre",
    "poussin",
    "pouvoir",
    "prairie",
    "pratique",
    "précieux",
    "prédire",
    "préfixe",
    "prélude",
    "prénom",
    "présence",
    "prétexte",
    "prévoir",
    "primitif",
    "prince",
    "prison",
    "priver",
    "problème",
    "procéder",
    "prodige",
    "profond",
    "progrès",
    "proie",
    "projeter",
    "prologue",
    "promener",
    "propre",
    "prospère",
    "protéger",
    "prouesse",
    "proverbe",
    "prudence",
    "pruneau",
    "psychose",
    "public",
    "puceron",
    "puiser",
    "pulpe",
    "pulsar",
    "punaise",
    "punitif",
    "pupitre",
    "purifier",
    "puzzle",
    "pyramide",
    "quasar",
    "querelle",
    "question",
    "quiétude",
    "quitter",
    "quotient",
    "racine",
    "raconter",
    "radieux",
    "ragondin",
    "raideur",
    "raisin",
    "ralentir",
    "rallonge",
    "ramasser",
    "rapide",
    "rasage",
    "ratisser",
    "ravager",
    "ravin",
    "rayonner",
    "réactif",
    "réagir",
    "réaliser",
    "réanimer",
    "recevoir",
    "réciter",
    "réclamer",
    "récolter",
    "recruter",
    "reculer",
    "recycler",
    "rédiger",
    "redouter",
    "refaire",
    "réflexe",
    "réformer",
    "refrain",
    "refuge",
    "régalien",
    "région",
    "réglage",
    "régulier",
    "réitérer",
    "rejeter",
    "rejouer",
    "relatif",
    "relever",
    "relief",
    "remarque",
    "remède",
    "remise",
    "remonter",
    "remplir",
    "remuer",
    "renard",
    "renfort",
    "renifler",
    "renoncer",
    "rentrer",
    "renvoi",
    "replier",
    "reporter",
    "reprise",
    "reptile",
    "requin",
    "réserve",
    "résineux",
    "résoudre",
    "respect",
    "rester",
    "résultat",
    "rétablir",
    "retenir",
    "réticule",
    "retomber",
    "retracer",
    "réunion",
    "réussir",
    "revanche",
    "revivre",
    "révolte",
    "révulsif",
    "richesse",
    "rideau",
    "rieur",
    "rigide",
    "rigoler",
    "rincer",
    "riposter",
    "risible",
    "risque",
    "rituel",
    "rival",
    "rivière",
    "rocheux",
    "romance",
    "rompre",
    "ronce",
    "rondin",
    "roseau",
    "rosier",
    "rotatif",
    "rotor",
    "rotule",
    "rouge",
    "rouille",
    "rouleau",
    "routine",
    "royaume",
    "ruban",
    "rubis",
    "ruche",
    "ruelle",
    "rugueux",
    "ruiner",
    "ruisseau",
    "ruser",
    "rustique",
    "rythme",
    "sabler",
    "saboter",
    "sabre",
    "sacoche",
    "safari",
    "sagesse",
    "saisir",
    "salade",
    "salive",
    "salon",
    "saluer",
    "samedi",
    "sanction",
    "sanglier",
    "sarcasme",
    "sardine",
    "saturer",
    "saugrenu",
    "saumon",
    "sauter",
    "sauvage",
    "savant",
    "savonner",
    "scalpel",
    "scandale",
    "scélérat",
    "scénario",
    "sceptre",
    "schéma",
    "science",
    "scinder",
    "score",
    "scrutin",
    "sculpter",
    "séance",
    "sécable",
    "sécher",
    "secouer",
    "sécréter",
    "sédatif",
    "séduire",
    "seigneur",
    "séjour",
    "sélectif",
    "semaine",
    "sembler",
    "semence",
    "séminal",
    "sénateur",
    "sensible",
    "sentence",
    "séparer",
    "séquence",
    "serein",
    "sergent",
    "sérieux",
    "serrure",
    "sérum",
    "service",
    "sésame",
    "sévir",
    "sevrage",
    "sextuple",
    "sidéral",
    "siècle",
    "siéger",
    "siffler",
    "sigle",
    "signal",
    "silence",
    "silicium",
    "simple",
    "sincère",
    "sinistre",
    "siphon",
    "sirop",
    "sismique",
    "situer",
    "skier",
    "social",
    "socle",
    "sodium",
    "soigneux",
    "soldat",
    "soleil",
    "solitude",
    "soluble",
    "sombre",
    "sommeil",
    "somnoler",
    "sonde",
    "songeur",
    "sonnette",
    "sonore",
    "sorcier",
    "sortir",
    "sosie",
    "sottise",
    "soucieux",
    "soudure",
    "souffle",
    "soulever",
    "soupape",
    "source",
    "soutirer",
    "souvenir",
    "spacieux",
    "spatial",
    "spécial",
    "sphère",
    "spiral",
    "stable",
    "station",
    "sternum",
    "stimulus",
    "stipuler",
    "strict",
    "studieux",
    "stupeur",
    "styliste",
    "sublime",
    "substrat",
    "subtil",
    "subvenir",
    "succès",
    "sucre",
    "suffixe",
    "suggérer",
    "suiveur",
    "sulfate",
    "superbe",
    "supplier",
    "surface",
    "suricate",
    "surmener",
    "surprise",
    "sursaut",
    "survie",
    "suspect",
    "syllabe",
    "symbole",
    "symétrie",
    "synapse",
    "syntaxe",
    "système",
    "tabac",
    "tablier",
    "tactile",
    "tailler",
    "talent",
    "talisman",
    "talonner",
    "tambour",
    "tamiser",
    "tangible",
    "tapis",
    "taquiner",
    "tarder",
    "tarif",
    "tartine",
    "tasse",
    "tatami",
    "tatouage",
    "taupe",
    "taureau",
    "taxer",
    "témoin",
    "temporel",
    "tenaille",
    "tendre",
    "teneur",
    "tenir",
    "tension",
    "terminer",
    "terne",
    "terrible",
    "tétine",
    "texte",
    "thème",
    "théorie",
    "thérapie",
    "thorax",
    "tibia",
    "tiède",
    "timide",
    "tirelire",
    "tiroir",
    "tissu",
    "titane",
    "titre",
    "tituber",
    "toboggan",
    "tolérant",
    "tomate",
    "tonique",
    "tonneau",
    "toponyme",
    "torche",
    "tordre",
    "tornade",
    "torpille",
    "torrent",
    "torse",
    "tortue",
    "totem",
    "toucher",
    "tournage",
    "tousser",
    "toxine",
    "traction",
    "trafic",
    "tragique",
    "trahir",
    "train",
    "trancher",
    "travail",
    "trèfle",
    "tremper",
    "trésor",
    "treuil",
    "triage",
    "tribunal",
    "tricoter",
    "trilogie",
    "triomphe",
    "tripler",
    "triturer",
    "trivial",
    "trombone",
    "tronc",
    "tropical",
    "troupeau",
    "tuile",
    "tulipe",
    "tumulte",
    "tunnel",
    "turbine",
    "tuteur",
    "tutoyer",
    "tuyau",
    "tympan",
    "typhon",
    "typique",
    "tyran",
    "ubuesque",
    "ultime",
    "ultrason",
    "unanime",
    "unifier",
    "union",
    "unique",
    "unitaire",
    "univers",
    "uranium",
    "urbain",
    "urticant",
    "usage",
    "usine",
    "usuel",
    "usure",
    "utile",
    "utopie",
    "vacarme",
    "vaccin",
    "vagabond",
    "vague",
    "vaillant",
    "vaincre",
    "vaisseau",
    "valable",
    "valise",
    "vallon",
    "valve",
    "vampire",
    "vanille",
    "vapeur",
    "varier",
    "vaseux",
    "vassal",
    "vaste",
    "vecteur",
    "vedette",
    "végétal",
    "véhicule",
    "veinard",
    "véloce",
    "vendredi",
    "vénérer",
    "venger",
    "venimeux",
    "ventouse",
    "verdure",
    "vérin",
    "vernir",
    "verrou",
    "verser",
    "vertu",
    "veston",
    "vétéran",
    "vétuste",
    "vexant",
    "vexer",
    "viaduc",
    "viande",
    "victoire",
    "vidange",
    "vidéo",
    "vignette",
    "vigueur",
    "vilain",
    "village",
    "vinaigre",
    "violon",
    "vipère",
    "virement",
    "virtuose",
    "virus",
    "visage",
    "viseur",
    "vision",
    "visqueux",
    "visuel",
    "vital",
    "vitesse",
    "viticole",
    "vitrine",
    "vivace",
    "vivipare",
    "vocation",
    "voguer",
    "voile",
    "voisin",
    "voiture",
    "volaille",
    "volcan",
    "voltiger",
    "volume",
    "vorace",
    "vortex",
    "voter",
    "vouloir",
    "voyage",
    "voyelle",
    "wagon",
    "xénon",
    "yacht",
    "zèbre",
    "zénith",
    "zeste",
    "zoologie"
]

},{}],51:[function(require,module,exports){
module.exports=[
    "abaco",
    "abbaglio",
    "abbinato",
    "abete",
    "abisso",
    "abolire",
    "abrasivo",
    "abrogato",
    "accadere",
    "accenno",
    "accusato",
    "acetone",
    "achille",
    "acido",
    "acqua",
    "acre",
    "acrilico",
    "acrobata",
    "acuto",
    "adagio",
    "addebito",
    "addome",
    "adeguato",
    "aderire",
    "adipe",
    "adottare",
    "adulare",
    "affabile",
    "affetto",
    "affisso",
    "affranto",
    "aforisma",
    "afoso",
    "africano",
    "agave",
    "agente",
    "agevole",
    "aggancio",
    "agire",
    "agitare",
    "agonismo",
    "agricolo",
    "agrumeto",
    "aguzzo",
    "alabarda",
    "alato",
    "albatro",
    "alberato",
    "albo",
    "albume",
    "alce",
    "alcolico",
    "alettone",
    "alfa",
    "algebra",
    "aliante",
    "alibi",
    "alimento",
    "allagato",
    "allegro",
    "allievo",
    "allodola",
    "allusivo",
    "almeno",
    "alogeno",
    "alpaca",
    "alpestre",
    "altalena",
    "alterno",
    "alticcio",
    "altrove",
    "alunno",
    "alveolo",
    "alzare",
    "amalgama",
    "amanita",
    "amarena",
    "ambito",
    "ambrato",
    "ameba",
    "america",
    "ametista",
    "amico",
    "ammasso",
    "ammenda",
    "ammirare",
    "ammonito",
    "amore",
    "ampio",
    "ampliare",
    "amuleto",
    "anacardo",
    "anagrafe",
    "analista",
    "anarchia",
    "anatra",
    "anca",
    "ancella",
    "ancora",
    "andare",
    "andrea",
    "anello",
    "angelo",
    "angolare",
    "angusto",
    "anima",
    "annegare",
    "annidato",
    "anno",
    "annuncio",
    "anonimo",
    "anticipo",
    "anzi",
    "apatico",
    "apertura",
    "apode",
    "apparire",
    "appetito",
    "appoggio",
    "approdo",
    "appunto",
    "aprile",
    "arabica",
    "arachide",
    "aragosta",
    "araldica",
    "arancio",
    "aratura",
    "arazzo",
    "arbitro",
    "archivio",
    "ardito",
    "arenile",
    "argento",
    "argine",
    "arguto",
    "aria",
    "armonia",
    "arnese",
    "arredato",
    "arringa",
    "arrosto",
    "arsenico",
    "arso",
    "artefice",
    "arzillo",
    "asciutto",
    "ascolto",
    "asepsi",
    "asettico",
    "asfalto",
    "asino",
    "asola",
    "aspirato",
    "aspro",
    "assaggio",
    "asse",
    "assoluto",
    "assurdo",
    "asta",
    "astenuto",
    "astice",
    "astratto",
    "atavico",
    "ateismo",
    "atomico",
    "atono",
    "attesa",
    "attivare",
    "attorno",
    "attrito",
    "attuale",
    "ausilio",
    "austria",
    "autista",
    "autonomo",
    "autunno",
    "avanzato",
    "avere",
    "avvenire",
    "avviso",
    "avvolgere",
    "azione",
    "azoto",
    "azzimo",
    "azzurro",
    "babele",
    "baccano",
    "bacino",
    "baco",
    "badessa",
    "badilata",
    "bagnato",
    "baita",
    "balcone",
    "baldo",
    "balena",
    "ballata",
    "balzano",
    "bambino",
    "bandire",
    "baraonda",
    "barbaro",
    "barca",
    "baritono",
    "barlume",
    "barocco",
    "basilico",
    "basso",
    "batosta",
    "battuto",
    "baule",
    "bava",
    "bavosa",
    "becco",
    "beffa",
    "belgio",
    "belva",
    "benda",
    "benevole",
    "benigno",
    "benzina",
    "bere",
    "berlina",
    "beta",
    "bibita",
    "bici",
    "bidone",
    "bifido",
    "biga",
    "bilancia",
    "bimbo",
    "binocolo",
    "biologo",
    "bipede",
    "bipolare",
    "birbante",
    "birra",
    "biscotto",
    "bisesto",
    "bisnonno",
    "bisonte",
    "bisturi",
    "bizzarro",
    "blando",
    "blatta",
    "bollito",
    "bonifico",
    "bordo",
    "bosco",
    "botanico",
    "bottino",
    "bozzolo",
    "braccio",
    "bradipo",
    "brama",
    "branca",
    "bravura",
    "bretella",
    "brevetto",
    "brezza",
    "briglia",
    "brillante",
    "brindare",
    "broccolo",
    "brodo",
    "bronzina",
    "brullo",
    "bruno",
    "bubbone",
    "buca",
    "budino",
    "buffone",
    "buio",
    "bulbo",
    "buono",
    "burlone",
    "burrasca",
    "bussola",
    "busta",
    "cadetto",
    "caduco",
    "calamaro",
    "calcolo",
    "calesse",
    "calibro",
    "calmo",
    "caloria",
    "cambusa",
    "camerata",
    "camicia",
    "cammino",
    "camola",
    "campale",
    "canapa",
    "candela",
    "cane",
    "canino",
    "canotto",
    "cantina",
    "capace",
    "capello",
    "capitolo",
    "capogiro",
    "cappero",
    "capra",
    "capsula",
    "carapace",
    "carcassa",
    "cardo",
    "carisma",
    "carovana",
    "carretto",
    "cartolina",
    "casaccio",
    "cascata",
    "caserma",
    "caso",
    "cassone",
    "castello",
    "casuale",
    "catasta",
    "catena",
    "catrame",
    "cauto",
    "cavillo",
    "cedibile",
    "cedrata",
    "cefalo",
    "celebre",
    "cellulare",
    "cena",
    "cenone",
    "centesimo",
    "ceramica",
    "cercare",
    "certo",
    "cerume",
    "cervello",
    "cesoia",
    "cespo",
    "ceto",
    "chela",
    "chiaro",
    "chicca",
    "chiedere",
    "chimera",
    "china",
    "chirurgo",
    "chitarra",
    "ciao",
    "ciclismo",
    "cifrare",
    "cigno",
    "cilindro",
    "ciottolo",
    "circa",
    "cirrosi",
    "citrico",
    "cittadino",
    "ciuffo",
    "civetta",
    "civile",
    "classico",
    "clinica",
    "cloro",
    "cocco",
    "codardo",
    "codice",
    "coerente",
    "cognome",
    "collare",
    "colmato",
    "colore",
    "colposo",
    "coltivato",
    "colza",
    "coma",
    "cometa",
    "commando",
    "comodo",
    "computer",
    "comune",
    "conciso",
    "condurre",
    "conferma",
    "congelare",
    "coniuge",
    "connesso",
    "conoscere",
    "consumo",
    "continuo",
    "convegno",
    "coperto",
    "copione",
    "coppia",
    "copricapo",
    "corazza",
    "cordata",
    "coricato",
    "cornice",
    "corolla",
    "corpo",
    "corredo",
    "corsia",
    "cortese",
    "cosmico",
    "costante",
    "cottura",
    "covato",
    "cratere",
    "cravatta",
    "creato",
    "credere",
    "cremoso",
    "crescita",
    "creta",
    "criceto",
    "crinale",
    "crisi",
    "critico",
    "croce",
    "cronaca",
    "crostata",
    "cruciale",
    "crusca",
    "cucire",
    "cuculo",
    "cugino",
    "cullato",
    "cupola",
    "curatore",
    "cursore",
    "curvo",
    "cuscino",
    "custode",
    "dado",
    "daino",
    "dalmata",
    "damerino",
    "daniela",
    "dannoso",
    "danzare",
    "datato",
    "davanti",
    "davvero",
    "debutto",
    "decennio",
    "deciso",
    "declino",
    "decollo",
    "decreto",
    "dedicato",
    "definito",
    "deforme",
    "degno",
    "delegare",
    "delfino",
    "delirio",
    "delta",
    "demenza",
    "denotato",
    "dentro",
    "deposito",
    "derapata",
    "derivare",
    "deroga",
    "descritto",
    "deserto",
    "desiderio",
    "desumere",
    "detersivo",
    "devoto",
    "diametro",
    "dicembre",
    "diedro",
    "difeso",
    "diffuso",
    "digerire",
    "digitale",
    "diluvio",
    "dinamico",
    "dinnanzi",
    "dipinto",
    "diploma",
    "dipolo",
    "diradare",
    "dire",
    "dirotto",
    "dirupo",
    "disagio",
    "discreto",
    "disfare",
    "disgelo",
    "disposto",
    "distanza",
    "disumano",
    "dito",
    "divano",
    "divelto",
    "dividere",
    "divorato",
    "doblone",
    "docente",
    "doganale",
    "dogma",
    "dolce",
    "domato",
    "domenica",
    "dominare",
    "dondolo",
    "dono",
    "dormire",
    "dote",
    "dottore",
    "dovuto",
    "dozzina",
    "drago",
    "druido",
    "dubbio",
    "dubitare",
    "ducale",
    "duna",
    "duomo",
    "duplice",
    "duraturo",
    "ebano",
    "eccesso",
    "ecco",
    "eclissi",
    "economia",
    "edera",
    "edicola",
    "edile",
    "editoria",
    "educare",
    "egemonia",
    "egli",
    "egoismo",
    "egregio",
    "elaborato",
    "elargire",
    "elegante",
    "elencato",
    "eletto",
    "elevare",
    "elfico",
    "elica",
    "elmo",
    "elsa",
    "eluso",
    "emanato",
    "emblema",
    "emesso",
    "emiro",
    "emotivo",
    "emozione",
    "empirico",
    "emulo",
    "endemico",
    "enduro",
    "energia",
    "enfasi",
    "enoteca",
    "entrare",
    "enzima",
    "epatite",
    "epilogo",
    "episodio",
    "epocale",
    "eppure",
    "equatore",
    "erario",
    "erba",
    "erboso",
    "erede",
    "eremita",
    "erigere",
    "ermetico",
    "eroe",
    "erosivo",
    "errante",
    "esagono",
    "esame",
    "esanime",
    "esaudire",
    "esca",
    "esempio",
    "esercito",
    "esibito",
    "esigente",
    "esistere",
    "esito",
    "esofago",
    "esortato",
    "esoso",
    "espanso",
    "espresso",
    "essenza",
    "esso",
    "esteso",
    "estimare",
    "estonia",
    "estroso",
    "esultare",
    "etilico",
    "etnico",
    "etrusco",
    "etto",
    "euclideo",
    "europa",
    "evaso",
    "evidenza",
    "evitato",
    "evoluto",
    "evviva",
    "fabbrica",
    "faccenda",
    "fachiro",
    "falco",
    "famiglia",
    "fanale",
    "fanfara",
    "fango",
    "fantasma",
    "fare",
    "farfalla",
    "farinoso",
    "farmaco",
    "fascia",
    "fastoso",
    "fasullo",
    "faticare",
    "fato",
    "favoloso",
    "febbre",
    "fecola",
    "fede",
    "fegato",
    "felpa",
    "feltro",
    "femmina",
    "fendere",
    "fenomeno",
    "fermento",
    "ferro",
    "fertile",
    "fessura",
    "festivo",
    "fetta",
    "feudo",
    "fiaba",
    "fiducia",
    "fifa",
    "figurato",
    "filo",
    "finanza",
    "finestra",
    "finire",
    "fiore",
    "fiscale",
    "fisico",
    "fiume",
    "flacone",
    "flamenco",
    "flebo",
    "flemma",
    "florido",
    "fluente",
    "fluoro",
    "fobico",
    "focaccia",
    "focoso",
    "foderato",
    "foglio",
    "folata",
    "folclore",
    "folgore",
    "fondente",
    "fonetico",
    "fonia",
    "fontana",
    "forbito",
    "forchetta",
    "foresta",
    "formica",
    "fornaio",
    "foro",
    "fortezza",
    "forzare",
    "fosfato",
    "fosso",
    "fracasso",
    "frana",
    "frassino",
    "fratello",
    "freccetta",
    "frenata",
    "fresco",
    "frigo",
    "frollino",
    "fronde",
    "frugale",
    "frutta",
    "fucilata",
    "fucsia",
    "fuggente",
    "fulmine",
    "fulvo",
    "fumante",
    "fumetto",
    "fumoso",
    "fune",
    "funzione",
    "fuoco",
    "furbo",
    "furgone",
    "furore",
    "fuso",
    "futile",
    "gabbiano",
    "gaffe",
    "galateo",
    "gallina",
    "galoppo",
    "gambero",
    "gamma",
    "garanzia",
    "garbo",
    "garofano",
    "garzone",
    "gasdotto",
    "gasolio",
    "gastrico",
    "gatto",
    "gaudio",
    "gazebo",
    "gazzella",
    "geco",
    "gelatina",
    "gelso",
    "gemello",
    "gemmato",
    "gene",
    "genitore",
    "gennaio",
    "genotipo",
    "gergo",
    "ghepardo",
    "ghiaccio",
    "ghisa",
    "giallo",
    "gilda",
    "ginepro",
    "giocare",
    "gioiello",
    "giorno",
    "giove",
    "girato",
    "girone",
    "gittata",
    "giudizio",
    "giurato",
    "giusto",
    "globulo",
    "glutine",
    "gnomo",
    "gobba",
    "golf",
    "gomito",
    "gommone",
    "gonfio",
    "gonna",
    "governo",
    "gracile",
    "grado",
    "grafico",
    "grammo",
    "grande",
    "grattare",
    "gravoso",
    "grazia",
    "greca",
    "gregge",
    "grifone",
    "grigio",
    "grinza",
    "grotta",
    "gruppo",
    "guadagno",
    "guaio",
    "guanto",
    "guardare",
    "gufo",
    "guidare",
    "ibernato",
    "icona",
    "identico",
    "idillio",
    "idolo",
    "idra",
    "idrico",
    "idrogeno",
    "igiene",
    "ignaro",
    "ignorato",
    "ilare",
    "illeso",
    "illogico",
    "illudere",
    "imballo",
    "imbevuto",
    "imbocco",
    "imbuto",
    "immane",
    "immerso",
    "immolato",
    "impacco",
    "impeto",
    "impiego",
    "importo",
    "impronta",
    "inalare",
    "inarcare",
    "inattivo",
    "incanto",
    "incendio",
    "inchino",
    "incisivo",
    "incluso",
    "incontro",
    "incrocio",
    "incubo",
    "indagine",
    "india",
    "indole",
    "inedito",
    "infatti",
    "infilare",
    "inflitto",
    "ingaggio",
    "ingegno",
    "inglese",
    "ingordo",
    "ingrosso",
    "innesco",
    "inodore",
    "inoltrare",
    "inondato",
    "insano",
    "insetto",
    "insieme",
    "insonnia",
    "insulina",
    "intasato",
    "intero",
    "intonaco",
    "intuito",
    "inumidire",
    "invalido",
    "invece",
    "invito",
    "iperbole",
    "ipnotico",
    "ipotesi",
    "ippica",
    "iride",
    "irlanda",
    "ironico",
    "irrigato",
    "irrorare",
    "isolato",
    "isotopo",
    "isterico",
    "istituto",
    "istrice",
    "italia",
    "iterare",
    "labbro",
    "labirinto",
    "lacca",
    "lacerato",
    "lacrima",
    "lacuna",
    "laddove",
    "lago",
    "lampo",
    "lancetta",
    "lanterna",
    "lardoso",
    "larga",
    "laringe",
    "lastra",
    "latenza",
    "latino",
    "lattuga",
    "lavagna",
    "lavoro",
    "legale",
    "leggero",
    "lembo",
    "lentezza",
    "lenza",
    "leone",
    "lepre",
    "lesivo",
    "lessato",
    "lesto",
    "letterale",
    "leva",
    "levigato",
    "libero",
    "lido",
    "lievito",
    "lilla",
    "limatura",
    "limitare",
    "limpido",
    "lineare",
    "lingua",
    "liquido",
    "lira",
    "lirica",
    "lisca",
    "lite",
    "litigio",
    "livrea",
    "locanda",
    "lode",
    "logica",
    "lombare",
    "londra",
    "longevo",
    "loquace",
    "lorenzo",
    "loto",
    "lotteria",
    "luce",
    "lucidato",
    "lumaca",
    "luminoso",
    "lungo",
    "lupo",
    "luppolo",
    "lusinga",
    "lusso",
    "lutto",
    "macabro",
    "macchina",
    "macero",
    "macinato",
    "madama",
    "magico",
    "maglia",
    "magnete",
    "magro",
    "maiolica",
    "malafede",
    "malgrado",
    "malinteso",
    "malsano",
    "malto",
    "malumore",
    "mana",
    "mancia",
    "mandorla",
    "mangiare",
    "manifesto",
    "mannaro",
    "manovra",
    "mansarda",
    "mantide",
    "manubrio",
    "mappa",
    "maratona",
    "marcire",
    "maretta",
    "marmo",
    "marsupio",
    "maschera",
    "massaia",
    "mastino",
    "materasso",
    "matricola",
    "mattone",
    "maturo",
    "mazurca",
    "meandro",
    "meccanico",
    "mecenate",
    "medesimo",
    "meditare",
    "mega",
    "melassa",
    "melis",
    "melodia",
    "meninge",
    "meno",
    "mensola",
    "mercurio",
    "merenda",
    "merlo",
    "meschino",
    "mese",
    "messere",
    "mestolo",
    "metallo",
    "metodo",
    "mettere",
    "miagolare",
    "mica",
    "micelio",
    "michele",
    "microbo",
    "midollo",
    "miele",
    "migliore",
    "milano",
    "milite",
    "mimosa",
    "minerale",
    "mini",
    "minore",
    "mirino",
    "mirtillo",
    "miscela",
    "missiva",
    "misto",
    "misurare",
    "mitezza",
    "mitigare",
    "mitra",
    "mittente",
    "mnemonico",
    "modello",
    "modifica",
    "modulo",
    "mogano",
    "mogio",
    "mole",
    "molosso",
    "monastero",
    "monco",
    "mondina",
    "monetario",
    "monile",
    "monotono",
    "monsone",
    "montato",
    "monviso",
    "mora",
    "mordere",
    "morsicato",
    "mostro",
    "motivato",
    "motosega",
    "motto",
    "movenza",
    "movimento",
    "mozzo",
    "mucca",
    "mucosa",
    "muffa",
    "mughetto",
    "mugnaio",
    "mulatto",
    "mulinello",
    "multiplo",
    "mummia",
    "munto",
    "muovere",
    "murale",
    "musa",
    "muscolo",
    "musica",
    "mutevole",
    "muto",
    "nababbo",
    "nafta",
    "nanometro",
    "narciso",
    "narice",
    "narrato",
    "nascere",
    "nastrare",
    "naturale",
    "nautica",
    "naviglio",
    "nebulosa",
    "necrosi",
    "negativo",
    "negozio",
    "nemmeno",
    "neofita",
    "neretto",
    "nervo",
    "nessuno",
    "nettuno",
    "neutrale",
    "neve",
    "nevrotico",
    "nicchia",
    "ninfa",
    "nitido",
    "nobile",
    "nocivo",
    "nodo",
    "nome",
    "nomina",
    "nordico",
    "normale",
    "norvegese",
    "nostrano",
    "notare",
    "notizia",
    "notturno",
    "novella",
    "nucleo",
    "nulla",
    "numero",
    "nuovo",
    "nutrire",
    "nuvola",
    "nuziale",
    "oasi",
    "obbedire",
    "obbligo",
    "obelisco",
    "oblio",
    "obolo",
    "obsoleto",
    "occasione",
    "occhio",
    "occidente",
    "occorrere",
    "occultare",
    "ocra",
    "oculato",
    "odierno",
    "odorare",
    "offerta",
    "offrire",
    "offuscato",
    "oggetto",
    "oggi",
    "ognuno",
    "olandese",
    "olfatto",
    "oliato",
    "oliva",
    "ologramma",
    "oltre",
    "omaggio",
    "ombelico",
    "ombra",
    "omega",
    "omissione",
    "ondoso",
    "onere",
    "onice",
    "onnivoro",
    "onorevole",
    "onta",
    "operato",
    "opinione",
    "opposto",
    "oracolo",
    "orafo",
    "ordine",
    "orecchino",
    "orefice",
    "orfano",
    "organico",
    "origine",
    "orizzonte",
    "orma",
    "ormeggio",
    "ornativo",
    "orologio",
    "orrendo",
    "orribile",
    "ortensia",
    "ortica",
    "orzata",
    "orzo",
    "osare",
    "oscurare",
    "osmosi",
    "ospedale",
    "ospite",
    "ossa",
    "ossidare",
    "ostacolo",
    "oste",
    "otite",
    "otre",
    "ottagono",
    "ottimo",
    "ottobre",
    "ovale",
    "ovest",
    "ovino",
    "oviparo",
    "ovocito",
    "ovunque",
    "ovviare",
    "ozio",
    "pacchetto",
    "pace",
    "pacifico",
    "padella",
    "padrone",
    "paese",
    "paga",
    "pagina",
    "palazzina",
    "palesare",
    "pallido",
    "palo",
    "palude",
    "pandoro",
    "pannello",
    "paolo",
    "paonazzo",
    "paprica",
    "parabola",
    "parcella",
    "parere",
    "pargolo",
    "pari",
    "parlato",
    "parola",
    "partire",
    "parvenza",
    "parziale",
    "passivo",
    "pasticca",
    "patacca",
    "patologia",
    "pattume",
    "pavone",
    "peccato",
    "pedalare",
    "pedonale",
    "peggio",
    "peloso",
    "penare",
    "pendice",
    "penisola",
    "pennuto",
    "penombra",
    "pensare",
    "pentola",
    "pepe",
    "pepita",
    "perbene",
    "percorso",
    "perdonato",
    "perforare",
    "pergamena",
    "periodo",
    "permesso",
    "perno",
    "perplesso",
    "persuaso",
    "pertugio",
    "pervaso",
    "pesatore",
    "pesista",
    "peso",
    "pestifero",
    "petalo",
    "pettine",
    "petulante",
    "pezzo",
    "piacere",
    "pianta",
    "piattino",
    "piccino",
    "picozza",
    "piega",
    "pietra",
    "piffero",
    "pigiama",
    "pigolio",
    "pigro",
    "pila",
    "pilifero",
    "pillola",
    "pilota",
    "pimpante",
    "pineta",
    "pinna",
    "pinolo",
    "pioggia",
    "piombo",
    "piramide",
    "piretico",
    "pirite",
    "pirolisi",
    "pitone",
    "pizzico",
    "placebo",
    "planare",
    "plasma",
    "platano",
    "plenario",
    "pochezza",
    "poderoso",
    "podismo",
    "poesia",
    "poggiare",
    "polenta",
    "poligono",
    "pollice",
    "polmonite",
    "polpetta",
    "polso",
    "poltrona",
    "polvere",
    "pomice",
    "pomodoro",
    "ponte",
    "popoloso",
    "porfido",
    "poroso",
    "porpora",
    "porre",
    "portata",
    "posa",
    "positivo",
    "possesso",
    "postulato",
    "potassio",
    "potere",
    "pranzo",
    "prassi",
    "pratica",
    "precluso",
    "predica",
    "prefisso",
    "pregiato",
    "prelievo",
    "premere",
    "prenotare",
    "preparato",
    "presenza",
    "pretesto",
    "prevalso",
    "prima",
    "principe",
    "privato",
    "problema",
    "procura",
    "produrre",
    "profumo",
    "progetto",
    "prolunga",
    "promessa",
    "pronome",
    "proposta",
    "proroga",
    "proteso",
    "prova",
    "prudente",
    "prugna",
    "prurito",
    "psiche",
    "pubblico",
    "pudica",
    "pugilato",
    "pugno",
    "pulce",
    "pulito",
    "pulsante",
    "puntare",
    "pupazzo",
    "pupilla",
    "puro",
    "quadro",
    "qualcosa",
    "quasi",
    "querela",
    "quota",
    "raccolto",
    "raddoppio",
    "radicale",
    "radunato",
    "raffica",
    "ragazzo",
    "ragione",
    "ragno",
    "ramarro",
    "ramingo",
    "ramo",
    "randagio",
    "rantolare",
    "rapato",
    "rapina",
    "rappreso",
    "rasatura",
    "raschiato",
    "rasente",
    "rassegna",
    "rastrello",
    "rata",
    "ravveduto",
    "reale",
    "recepire",
    "recinto",
    "recluta",
    "recondito",
    "recupero",
    "reddito",
    "redimere",
    "regalato",
    "registro",
    "regola",
    "regresso",
    "relazione",
    "remare",
    "remoto",
    "renna",
    "replica",
    "reprimere",
    "reputare",
    "resa",
    "residente",
    "responso",
    "restauro",
    "rete",
    "retina",
    "retorica",
    "rettifica",
    "revocato",
    "riassunto",
    "ribadire",
    "ribelle",
    "ribrezzo",
    "ricarica",
    "ricco",
    "ricevere",
    "riciclato",
    "ricordo",
    "ricreduto",
    "ridicolo",
    "ridurre",
    "rifasare",
    "riflesso",
    "riforma",
    "rifugio",
    "rigare",
    "rigettato",
    "righello",
    "rilassato",
    "rilevato",
    "rimanere",
    "rimbalzo",
    "rimedio",
    "rimorchio",
    "rinascita",
    "rincaro",
    "rinforzo",
    "rinnovo",
    "rinomato",
    "rinsavito",
    "rintocco",
    "rinuncia",
    "rinvenire",
    "riparato",
    "ripetuto",
    "ripieno",
    "riportare",
    "ripresa",
    "ripulire",
    "risata",
    "rischio",
    "riserva",
    "risibile",
    "riso",
    "rispetto",
    "ristoro",
    "risultato",
    "risvolto",
    "ritardo",
    "ritegno",
    "ritmico",
    "ritrovo",
    "riunione",
    "riva",
    "riverso",
    "rivincita",
    "rivolto",
    "rizoma",
    "roba",
    "robotico",
    "robusto",
    "roccia",
    "roco",
    "rodaggio",
    "rodere",
    "roditore",
    "rogito",
    "rollio",
    "romantico",
    "rompere",
    "ronzio",
    "rosolare",
    "rospo",
    "rotante",
    "rotondo",
    "rotula",
    "rovescio",
    "rubizzo",
    "rubrica",
    "ruga",
    "rullino",
    "rumine",
    "rumoroso",
    "ruolo",
    "rupe",
    "russare",
    "rustico",
    "sabato",
    "sabbiare",
    "sabotato",
    "sagoma",
    "salasso",
    "saldatura",
    "salgemma",
    "salivare",
    "salmone",
    "salone",
    "saltare",
    "saluto",
    "salvo",
    "sapere",
    "sapido",
    "saporito",
    "saraceno",
    "sarcasmo",
    "sarto",
    "sassoso",
    "satellite",
    "satira",
    "satollo",
    "saturno",
    "savana",
    "savio",
    "saziato",
    "sbadiglio",
    "sbalzo",
    "sbancato",
    "sbarra",
    "sbattere",
    "sbavare",
    "sbendare",
    "sbirciare",
    "sbloccato",
    "sbocciato",
    "sbrinare",
    "sbruffone",
    "sbuffare",
    "scabroso",
    "scadenza",
    "scala",
    "scambiare",
    "scandalo",
    "scapola",
    "scarso",
    "scatenare",
    "scavato",
    "scelto",
    "scenico",
    "scettro",
    "scheda",
    "schiena",
    "sciarpa",
    "scienza",
    "scindere",
    "scippo",
    "sciroppo",
    "scivolo",
    "sclerare",
    "scodella",
    "scolpito",
    "scomparto",
    "sconforto",
    "scoprire",
    "scorta",
    "scossone",
    "scozzese",
    "scriba",
    "scrollare",
    "scrutinio",
    "scuderia",
    "scultore",
    "scuola",
    "scuro",
    "scusare",
    "sdebitare",
    "sdoganare",
    "seccatura",
    "secondo",
    "sedano",
    "seggiola",
    "segnalato",
    "segregato",
    "seguito",
    "selciato",
    "selettivo",
    "sella",
    "selvaggio",
    "semaforo",
    "sembrare",
    "seme",
    "seminato",
    "sempre",
    "senso",
    "sentire",
    "sepolto",
    "sequenza",
    "serata",
    "serbato",
    "sereno",
    "serio",
    "serpente",
    "serraglio",
    "servire",
    "sestina",
    "setola",
    "settimana",
    "sfacelo",
    "sfaldare",
    "sfamato",
    "sfarzoso",
    "sfaticato",
    "sfera",
    "sfida",
    "sfilato",
    "sfinge",
    "sfocato",
    "sfoderare",
    "sfogo",
    "sfoltire",
    "sforzato",
    "sfratto",
    "sfruttato",
    "sfuggito",
    "sfumare",
    "sfuso",
    "sgabello",
    "sgarbato",
    "sgonfiare",
    "sgorbio",
    "sgrassato",
    "sguardo",
    "sibilo",
    "siccome",
    "sierra",
    "sigla",
    "signore",
    "silenzio",
    "sillaba",
    "simbolo",
    "simpatico",
    "simulato",
    "sinfonia",
    "singolo",
    "sinistro",
    "sino",
    "sintesi",
    "sinusoide",
    "sipario",
    "sisma",
    "sistole",
    "situato",
    "slitta",
    "slogatura",
    "sloveno",
    "smarrito",
    "smemorato",
    "smentito",
    "smeraldo",
    "smilzo",
    "smontare",
    "smottato",
    "smussato",
    "snellire",
    "snervato",
    "snodo",
    "sobbalzo",
    "sobrio",
    "soccorso",
    "sociale",
    "sodale",
    "soffitto",
    "sogno",
    "soldato",
    "solenne",
    "solido",
    "sollazzo",
    "solo",
    "solubile",
    "solvente",
    "somatico",
    "somma",
    "sonda",
    "sonetto",
    "sonnifero",
    "sopire",
    "soppeso",
    "sopra",
    "sorgere",
    "sorpasso",
    "sorriso",
    "sorso",
    "sorteggio",
    "sorvolato",
    "sospiro",
    "sosta",
    "sottile",
    "spada",
    "spalla",
    "spargere",
    "spatola",
    "spavento",
    "spazzola",
    "specie",
    "spedire",
    "spegnere",
    "spelatura",
    "speranza",
    "spessore",
    "spettrale",
    "spezzato",
    "spia",
    "spigoloso",
    "spillato",
    "spinoso",
    "spirale",
    "splendido",
    "sportivo",
    "sposo",
    "spranga",
    "sprecare",
    "spronato",
    "spruzzo",
    "spuntino",
    "squillo",
    "sradicare",
    "srotolato",
    "stabile",
    "stacco",
    "staffa",
    "stagnare",
    "stampato",
    "stantio",
    "starnuto",
    "stasera",
    "statuto",
    "stelo",
    "steppa",
    "sterzo",
    "stiletto",
    "stima",
    "stirpe",
    "stivale",
    "stizzoso",
    "stonato",
    "storico",
    "strappo",
    "stregato",
    "stridulo",
    "strozzare",
    "strutto",
    "stuccare",
    "stufo",
    "stupendo",
    "subentro",
    "succoso",
    "sudore",
    "suggerito",
    "sugo",
    "sultano",
    "suonare",
    "superbo",
    "supporto",
    "surgelato",
    "surrogato",
    "sussurro",
    "sutura",
    "svagare",
    "svedese",
    "sveglio",
    "svelare",
    "svenuto",
    "svezia",
    "sviluppo",
    "svista",
    "svizzera",
    "svolta",
    "svuotare",
    "tabacco",
    "tabulato",
    "tacciare",
    "taciturno",
    "tale",
    "talismano",
    "tampone",
    "tannino",
    "tara",
    "tardivo",
    "targato",
    "tariffa",
    "tarpare",
    "tartaruga",
    "tasto",
    "tattico",
    "taverna",
    "tavolata",
    "tazza",
    "teca",
    "tecnico",
    "telefono",
    "temerario",
    "tempo",
    "temuto",
    "tendone",
    "tenero",
    "tensione",
    "tentacolo",
    "teorema",
    "terme",
    "terrazzo",
    "terzetto",
    "tesi",
    "tesserato",
    "testato",
    "tetro",
    "tettoia",
    "tifare",
    "tigella",
    "timbro",
    "tinto",
    "tipico",
    "tipografo",
    "tiraggio",
    "tiro",
    "titanio",
    "titolo",
    "titubante",
    "tizio",
    "tizzone",
    "toccare",
    "tollerare",
    "tolto",
    "tombola",
    "tomo",
    "tonfo",
    "tonsilla",
    "topazio",
    "topologia",
    "toppa",
    "torba",
    "tornare",
    "torrone",
    "tortora",
    "toscano",
    "tossire",
    "tostatura",
    "totano",
    "trabocco",
    "trachea",
    "trafila",
    "tragedia",
    "tralcio",
    "tramonto",
    "transito",
    "trapano",
    "trarre",
    "trasloco",
    "trattato",
    "trave",
    "treccia",
    "tremolio",
    "trespolo",
    "tributo",
    "tricheco",
    "trifoglio",
    "trillo",
    "trincea",
    "trio",
    "tristezza",
    "triturato",
    "trivella",
    "tromba",
    "trono",
    "troppo",
    "trottola",
    "trovare",
    "truccato",
    "tubatura",
    "tuffato",
    "tulipano",
    "tumulto",
    "tunisia",
    "turbare",
    "turchino",
    "tuta",
    "tutela",
    "ubicato",
    "uccello",
    "uccisore",
    "udire",
    "uditivo",
    "uffa",
    "ufficio",
    "uguale",
    "ulisse",
    "ultimato",
    "umano",
    "umile",
    "umorismo",
    "uncinetto",
    "ungere",
    "ungherese",
    "unicorno",
    "unificato",
    "unisono",
    "unitario",
    "unte",
    "uovo",
    "upupa",
    "uragano",
    "urgenza",
    "urlo",
    "usanza",
    "usato",
    "uscito",
    "usignolo",
    "usuraio",
    "utensile",
    "utilizzo",
    "utopia",
    "vacante",
    "vaccinato",
    "vagabondo",
    "vagliato",
    "valanga",
    "valgo",
    "valico",
    "valletta",
    "valoroso",
    "valutare",
    "valvola",
    "vampata",
    "vangare",
    "vanitoso",
    "vano",
    "vantaggio",
    "vanvera",
    "vapore",
    "varano",
    "varcato",
    "variante",
    "vasca",
    "vedetta",
    "vedova",
    "veduto",
    "vegetale",
    "veicolo",
    "velcro",
    "velina",
    "velluto",
    "veloce",
    "venato",
    "vendemmia",
    "vento",
    "verace",
    "verbale",
    "vergogna",
    "verifica",
    "vero",
    "verruca",
    "verticale",
    "vescica",
    "vessillo",
    "vestale",
    "veterano",
    "vetrina",
    "vetusto",
    "viandante",
    "vibrante",
    "vicenda",
    "vichingo",
    "vicinanza",
    "vidimare",
    "vigilia",
    "vigneto",
    "vigore",
    "vile",
    "villano",
    "vimini",
    "vincitore",
    "viola",
    "vipera",
    "virgola",
    "virologo",
    "virulento",
    "viscoso",
    "visione",
    "vispo",
    "vissuto",
    "visura",
    "vita",
    "vitello",
    "vittima",
    "vivanda",
    "vivido",
    "viziare",
    "voce",
    "voga",
    "volatile",
    "volere",
    "volpe",
    "voragine",
    "vulcano",
    "zampogna",
    "zanna",
    "zappato",
    "zattera",
    "zavorra",
    "zefiro",
    "zelante",
    "zelo",
    "zenzero",
    "zerbino",
    "zibetto",
    "zinco",
    "zircone",
    "zitto",
    "zolla",
    "zotico",
    "zucchero",
    "zufolo",
    "zulu",
    "zuppa"
]

},{}],52:[function(require,module,exports){
module.exports=[
    "あいこくしん",
    "あいさつ",
    "あいだ",
    "あおぞら",
    "あかちゃん",
    "あきる",
    "あけがた",
    "あける",
    "あこがれる",
    "あさい",
    "あさひ",
    "あしあと",
    "あじわう",
    "あずかる",
    "あずき",
    "あそぶ",
    "あたえる",
    "あたためる",
    "あたりまえ",
    "あたる",
    "あつい",
    "あつかう",
    "あっしゅく",
    "あつまり",
    "あつめる",
    "あてな",
    "あてはまる",
    "あひる",
    "あぶら",
    "あぶる",
    "あふれる",
    "あまい",
    "あまど",
    "あまやかす",
    "あまり",
    "あみもの",
    "あめりか",
    "あやまる",
    "あゆむ",
    "あらいぐま",
    "あらし",
    "あらすじ",
    "あらためる",
    "あらゆる",
    "あらわす",
    "ありがとう",
    "あわせる",
    "あわてる",
    "あんい",
    "あんがい",
    "あんこ",
    "あんぜん",
    "あんてい",
    "あんない",
    "あんまり",
    "いいだす",
    "いおん",
    "いがい",
    "いがく",
    "いきおい",
    "いきなり",
    "いきもの",
    "いきる",
    "いくじ",
    "いくぶん",
    "いけばな",
    "いけん",
    "いこう",
    "いこく",
    "いこつ",
    "いさましい",
    "いさん",
    "いしき",
    "いじゅう",
    "いじょう",
    "いじわる",
    "いずみ",
    "いずれ",
    "いせい",
    "いせえび",
    "いせかい",
    "いせき",
    "いぜん",
    "いそうろう",
    "いそがしい",
    "いだい",
    "いだく",
    "いたずら",
    "いたみ",
    "いたりあ",
    "いちおう",
    "いちじ",
    "いちど",
    "いちば",
    "いちぶ",
    "いちりゅう",
    "いつか",
    "いっしゅん",
    "いっせい",
    "いっそう",
    "いったん",
    "いっち",
    "いってい",
    "いっぽう",
    "いてざ",
    "いてん",
    "いどう",
    "いとこ",
    "いない",
    "いなか",
    "いねむり",
    "いのち",
    "いのる",
    "いはつ",
    "いばる",
    "いはん",
    "いびき",
    "いひん",
    "いふく",
    "いへん",
    "いほう",
    "いみん",
    "いもうと",
    "いもたれ",
    "いもり",
    "いやがる",
    "いやす",
    "いよかん",
    "いよく",
    "いらい",
    "いらすと",
    "いりぐち",
    "いりょう",
    "いれい",
    "いれもの",
    "いれる",
    "いろえんぴつ",
    "いわい",
    "いわう",
    "いわかん",
    "いわば",
    "いわゆる",
    "いんげんまめ",
    "いんさつ",
    "いんしょう",
    "いんよう",
    "うえき",
    "うえる",
    "うおざ",
    "うがい",
    "うかぶ",
    "うかべる",
    "うきわ",
    "うくらいな",
    "うくれれ",
    "うけたまわる",
    "うけつけ",
    "うけとる",
    "うけもつ",
    "うける",
    "うごかす",
    "うごく",
    "うこん",
    "うさぎ",
    "うしなう",
    "うしろがみ",
    "うすい",
    "うすぎ",
    "うすぐらい",
    "うすめる",
    "うせつ",
    "うちあわせ",
    "うちがわ",
    "うちき",
    "うちゅう",
    "うっかり",
    "うつくしい",
    "うったえる",
    "うつる",
    "うどん",
    "うなぎ",
    "うなじ",
    "うなずく",
    "うなる",
    "うねる",
    "うのう",
    "うぶげ",
    "うぶごえ",
    "うまれる",
    "うめる",
    "うもう",
    "うやまう",
    "うよく",
    "うらがえす",
    "うらぐち",
    "うらない",
    "うりあげ",
    "うりきれ",
    "うるさい",
    "うれしい",
    "うれゆき",
    "うれる",
    "うろこ",
    "うわき",
    "うわさ",
    "うんこう",
    "うんちん",
    "うんてん",
    "うんどう",
    "えいえん",
    "えいが",
    "えいきょう",
    "えいご",
    "えいせい",
    "えいぶん",
    "えいよう",
    "えいわ",
    "えおり",
    "えがお",
    "えがく",
    "えきたい",
    "えくせる",
    "えしゃく",
    "えすて",
    "えつらん",
    "えのぐ",
    "えほうまき",
    "えほん",
    "えまき",
    "えもじ",
    "えもの",
    "えらい",
    "えらぶ",
    "えりあ",
    "えんえん",
    "えんかい",
    "えんぎ",
    "えんげき",
    "えんしゅう",
    "えんぜつ",
    "えんそく",
    "えんちょう",
    "えんとつ",
    "おいかける",
    "おいこす",
    "おいしい",
    "おいつく",
    "おうえん",
    "おうさま",
    "おうじ",
    "おうせつ",
    "おうたい",
    "おうふく",
    "おうべい",
    "おうよう",
    "おえる",
    "おおい",
    "おおう",
    "おおどおり",
    "おおや",
    "おおよそ",
    "おかえり",
    "おかず",
    "おがむ",
    "おかわり",
    "おぎなう",
    "おきる",
    "おくさま",
    "おくじょう",
    "おくりがな",
    "おくる",
    "おくれる",
    "おこす",
    "おこなう",
    "おこる",
    "おさえる",
    "おさない",
    "おさめる",
    "おしいれ",
    "おしえる",
    "おじぎ",
    "おじさん",
    "おしゃれ",
    "おそらく",
    "おそわる",
    "おたがい",
    "おたく",
    "おだやか",
    "おちつく",
    "おっと",
    "おつり",
    "おでかけ",
    "おとしもの",
    "おとなしい",
    "おどり",
    "おどろかす",
    "おばさん",
    "おまいり",
    "おめでとう",
    "おもいで",
    "おもう",
    "おもたい",
    "おもちゃ",
    "おやつ",
    "おやゆび",
    "およぼす",
    "おらんだ",
    "おろす",
    "おんがく",
    "おんけい",
    "おんしゃ",
    "おんせん",
    "おんだん",
    "おんちゅう",
    "おんどけい",
    "かあつ",
    "かいが",
    "がいき",
    "がいけん",
    "がいこう",
    "かいさつ",
    "かいしゃ",
    "かいすいよく",
    "かいぜん",
    "かいぞうど",
    "かいつう",
    "かいてん",
    "かいとう",
    "かいふく",
    "がいへき",
    "かいほう",
    "かいよう",
    "がいらい",
    "かいわ",
    "かえる",
    "かおり",
    "かかえる",
    "かがく",
    "かがし",
    "かがみ",
    "かくご",
    "かくとく",
    "かざる",
    "がぞう",
    "かたい",
    "かたち",
    "がちょう",
    "がっきゅう",
    "がっこう",
    "がっさん",
    "がっしょう",
    "かなざわし",
    "かのう",
    "がはく",
    "かぶか",
    "かほう",
    "かほご",
    "かまう",
    "かまぼこ",
    "かめれおん",
    "かゆい",
    "かようび",
    "からい",
    "かるい",
    "かろう",
    "かわく",
    "かわら",
    "がんか",
    "かんけい",
    "かんこう",
    "かんしゃ",
    "かんそう",
    "かんたん",
    "かんち",
    "がんばる",
    "きあい",
    "きあつ",
    "きいろ",
    "ぎいん",
    "きうい",
    "きうん",
    "きえる",
    "きおう",
    "きおく",
    "きおち",
    "きおん",
    "きかい",
    "きかく",
    "きかんしゃ",
    "ききて",
    "きくばり",
    "きくらげ",
    "きけんせい",
    "きこう",
    "きこえる",
    "きこく",
    "きさい",
    "きさく",
    "きさま",
    "きさらぎ",
    "ぎじかがく",
    "ぎしき",
    "ぎじたいけん",
    "ぎじにってい",
    "ぎじゅつしゃ",
    "きすう",
    "きせい",
    "きせき",
    "きせつ",
    "きそう",
    "きぞく",
    "きぞん",
    "きたえる",
    "きちょう",
    "きつえん",
    "ぎっちり",
    "きつつき",
    "きつね",
    "きてい",
    "きどう",
    "きどく",
    "きない",
    "きなが",
    "きなこ",
    "きぬごし",
    "きねん",
    "きのう",
    "きのした",
    "きはく",
    "きびしい",
    "きひん",
    "きふく",
    "きぶん",
    "きぼう",
    "きほん",
    "きまる",
    "きみつ",
    "きむずかしい",
    "きめる",
    "きもだめし",
    "きもち",
    "きもの",
    "きゃく",
    "きやく",
    "ぎゅうにく",
    "きよう",
    "きょうりゅう",
    "きらい",
    "きらく",
    "きりん",
    "きれい",
    "きれつ",
    "きろく",
    "ぎろん",
    "きわめる",
    "ぎんいろ",
    "きんかくじ",
    "きんじょ",
    "きんようび",
    "ぐあい",
    "くいず",
    "くうかん",
    "くうき",
    "くうぐん",
    "くうこう",
    "ぐうせい",
    "くうそう",
    "ぐうたら",
    "くうふく",
    "くうぼ",
    "くかん",
    "くきょう",
    "くげん",
    "ぐこう",
    "くさい",
    "くさき",
    "くさばな",
    "くさる",
    "くしゃみ",
    "くしょう",
    "くすのき",
    "くすりゆび",
    "くせげ",
    "くせん",
    "ぐたいてき",
    "くださる",
    "くたびれる",
    "くちこみ",
    "くちさき",
    "くつした",
    "ぐっすり",
    "くつろぐ",
    "くとうてん",
    "くどく",
    "くなん",
    "くねくね",
    "くのう",
    "くふう",
    "くみあわせ",
    "くみたてる",
    "くめる",
    "くやくしょ",
    "くらす",
    "くらべる",
    "くるま",
    "くれる",
    "くろう",
    "くわしい",
    "ぐんかん",
    "ぐんしょく",
    "ぐんたい",
    "ぐんて",
    "けあな",
    "けいかく",
    "けいけん",
    "けいこ",
    "けいさつ",
    "げいじゅつ",
    "けいたい",
    "げいのうじん",
    "けいれき",
    "けいろ",
    "けおとす",
    "けおりもの",
    "げきか",
    "げきげん",
    "げきだん",
    "げきちん",
    "げきとつ",
    "げきは",
    "げきやく",
    "げこう",
    "げこくじょう",
    "げざい",
    "けさき",
    "げざん",
    "けしき",
    "けしごむ",
    "けしょう",
    "げすと",
    "けたば",
    "けちゃっぷ",
    "けちらす",
    "けつあつ",
    "けつい",
    "けつえき",
    "けっこん",
    "けつじょ",
    "けっせき",
    "けってい",
    "けつまつ",
    "げつようび",
    "げつれい",
    "けつろん",
    "げどく",
    "けとばす",
    "けとる",
    "けなげ",
    "けなす",
    "けなみ",
    "けぬき",
    "げねつ",
    "けねん",
    "けはい",
    "げひん",
    "けぶかい",
    "げぼく",
    "けまり",
    "けみかる",
    "けむし",
    "けむり",
    "けもの",
    "けらい",
    "けろけろ",
    "けわしい",
    "けんい",
    "けんえつ",
    "けんお",
    "けんか",
    "げんき",
    "けんげん",
    "けんこう",
    "けんさく",
    "けんしゅう",
    "けんすう",
    "げんそう",
    "けんちく",
    "けんてい",
    "けんとう",
    "けんない",
    "けんにん",
    "げんぶつ",
    "けんま",
    "けんみん",
    "けんめい",
    "けんらん",
    "けんり",
    "こあくま",
    "こいぬ",
    "こいびと",
    "ごうい",
    "こうえん",
    "こうおん",
    "こうかん",
    "ごうきゅう",
    "ごうけい",
    "こうこう",
    "こうさい",
    "こうじ",
    "こうすい",
    "ごうせい",
    "こうそく",
    "こうたい",
    "こうちゃ",
    "こうつう",
    "こうてい",
    "こうどう",
    "こうない",
    "こうはい",
    "ごうほう",
    "ごうまん",
    "こうもく",
    "こうりつ",
    "こえる",
    "こおり",
    "ごかい",
    "ごがつ",
    "ごかん",
    "こくご",
    "こくさい",
    "こくとう",
    "こくない",
    "こくはく",
    "こぐま",
    "こけい",
    "こける",
    "ここのか",
    "こころ",
    "こさめ",
    "こしつ",
    "こすう",
    "こせい",
    "こせき",
    "こぜん",
    "こそだて",
    "こたい",
    "こたえる",
    "こたつ",
    "こちょう",
    "こっか",
    "こつこつ",
    "こつばん",
    "こつぶ",
    "こてい",
    "こてん",
    "ことがら",
    "ことし",
    "ことば",
    "ことり",
    "こなごな",
    "こねこね",
    "このまま",
    "このみ",
    "このよ",
    "ごはん",
    "こひつじ",
    "こふう",
    "こふん",
    "こぼれる",
    "ごまあぶら",
    "こまかい",
    "ごますり",
    "こまつな",
    "こまる",
    "こむぎこ",
    "こもじ",
    "こもち",
    "こもの",
    "こもん",
    "こやく",
    "こやま",
    "こゆう",
    "こゆび",
    "こよい",
    "こよう",
    "こりる",
    "これくしょん",
    "ころっけ",
    "こわもて",
    "こわれる",
    "こんいん",
    "こんかい",
    "こんき",
    "こんしゅう",
    "こんすい",
    "こんだて",
    "こんとん",
    "こんなん",
    "こんびに",
    "こんぽん",
    "こんまけ",
    "こんや",
    "こんれい",
    "こんわく",
    "ざいえき",
    "さいかい",
    "さいきん",
    "ざいげん",
    "ざいこ",
    "さいしょ",
    "さいせい",
    "ざいたく",
    "ざいちゅう",
    "さいてき",
    "ざいりょう",
    "さうな",
    "さかいし",
    "さがす",
    "さかな",
    "さかみち",
    "さがる",
    "さぎょう",
    "さくし",
    "さくひん",
    "さくら",
    "さこく",
    "さこつ",
    "さずかる",
    "ざせき",
    "さたん",
    "さつえい",
    "ざつおん",
    "ざっか",
    "ざつがく",
    "さっきょく",
    "ざっし",
    "さつじん",
    "ざっそう",
    "さつたば",
    "さつまいも",
    "さてい",
    "さといも",
    "さとう",
    "さとおや",
    "さとし",
    "さとる",
    "さのう",
    "さばく",
    "さびしい",
    "さべつ",
    "さほう",
    "さほど",
    "さます",
    "さみしい",
    "さみだれ",
    "さむけ",
    "さめる",
    "さやえんどう",
    "さゆう",
    "さよう",
    "さよく",
    "さらだ",
    "ざるそば",
    "さわやか",
    "さわる",
    "さんいん",
    "さんか",
    "さんきゃく",
    "さんこう",
    "さんさい",
    "ざんしょ",
    "さんすう",
    "さんせい",
    "さんそ",
    "さんち",
    "さんま",
    "さんみ",
    "さんらん",
    "しあい",
    "しあげ",
    "しあさって",
    "しあわせ",
    "しいく",
    "しいん",
    "しうち",
    "しえい",
    "しおけ",
    "しかい",
    "しかく",
    "じかん",
    "しごと",
    "しすう",
    "じだい",
    "したうけ",
    "したぎ",
    "したて",
    "したみ",
    "しちょう",
    "しちりん",
    "しっかり",
    "しつじ",
    "しつもん",
    "してい",
    "してき",
    "してつ",
    "じてん",
    "じどう",
    "しなぎれ",
    "しなもの",
    "しなん",
    "しねま",
    "しねん",
    "しのぐ",
    "しのぶ",
    "しはい",
    "しばかり",
    "しはつ",
    "しはらい",
    "しはん",
    "しひょう",
    "しふく",
    "じぶん",
    "しへい",
    "しほう",
    "しほん",
    "しまう",
    "しまる",
    "しみん",
    "しむける",
    "じむしょ",
    "しめい",
    "しめる",
    "しもん",
    "しゃいん",
    "しゃうん",
    "しゃおん",
    "じゃがいも",
    "しやくしょ",
    "しゃくほう",
    "しゃけん",
    "しゃこ",
    "しゃざい",
    "しゃしん",
    "しゃせん",
    "しゃそう",
    "しゃたい",
    "しゃちょう",
    "しゃっきん",
    "じゃま",
    "しゃりん",
    "しゃれい",
    "じゆう",
    "じゅうしょ",
    "しゅくはく",
    "じゅしん",
    "しゅっせき",
    "しゅみ",
    "しゅらば",
    "じゅんばん",
    "しょうかい",
    "しょくたく",
    "しょっけん",
    "しょどう",
    "しょもつ",
    "しらせる",
    "しらべる",
    "しんか",
    "しんこう",
    "じんじゃ",
    "しんせいじ",
    "しんちく",
    "しんりん",
    "すあげ",
    "すあし",
    "すあな",
    "ずあん",
    "すいえい",
    "すいか",
    "すいとう",
    "ずいぶん",
    "すいようび",
    "すうがく",
    "すうじつ",
    "すうせん",
    "すおどり",
    "すきま",
    "すくう",
    "すくない",
    "すける",
    "すごい",
    "すこし",
    "ずさん",
    "すずしい",
    "すすむ",
    "すすめる",
    "すっかり",
    "ずっしり",
    "ずっと",
    "すてき",
    "すてる",
    "すねる",
    "すのこ",
    "すはだ",
    "すばらしい",
    "ずひょう",
    "ずぶぬれ",
    "すぶり",
    "すふれ",
    "すべて",
    "すべる",
    "ずほう",
    "すぼん",
    "すまい",
    "すめし",
    "すもう",
    "すやき",
    "すらすら",
    "するめ",
    "すれちがう",
    "すろっと",
    "すわる",
    "すんぜん",
    "すんぽう",
    "せあぶら",
    "せいかつ",
    "せいげん",
    "せいじ",
    "せいよう",
    "せおう",
    "せかいかん",
    "せきにん",
    "せきむ",
    "せきゆ",
    "せきらんうん",
    "せけん",
    "せこう",
    "せすじ",
    "せたい",
    "せたけ",
    "せっかく",
    "せっきゃく",
    "ぜっく",
    "せっけん",
    "せっこつ",
    "せっさたくま",
    "せつぞく",
    "せつだん",
    "せつでん",
    "せっぱん",
    "せつび",
    "せつぶん",
    "せつめい",
    "せつりつ",
    "せなか",
    "せのび",
    "せはば",
    "せびろ",
    "せぼね",
    "せまい",
    "せまる",
    "せめる",
    "せもたれ",
    "せりふ",
    "ぜんあく",
    "せんい",
    "せんえい",
    "せんか",
    "せんきょ",
    "せんく",
    "せんげん",
    "ぜんご",
    "せんさい",
    "せんしゅ",
    "せんすい",
    "せんせい",
    "せんぞ",
    "せんたく",
    "せんちょう",
    "せんてい",
    "せんとう",
    "せんぬき",
    "せんねん",
    "せんぱい",
    "ぜんぶ",
    "ぜんぽう",
    "せんむ",
    "せんめんじょ",
    "せんもん",
    "せんやく",
    "せんゆう",
    "せんよう",
    "ぜんら",
    "ぜんりゃく",
    "せんれい",
    "せんろ",
    "そあく",
    "そいとげる",
    "そいね",
    "そうがんきょう",
    "そうき",
    "そうご",
    "そうしん",
    "そうだん",
    "そうなん",
    "そうび",
    "そうめん",
    "そうり",
    "そえもの",
    "そえん",
    "そがい",
    "そげき",
    "そこう",
    "そこそこ",
    "そざい",
    "そしな",
    "そせい",
    "そせん",
    "そそぐ",
    "そだてる",
    "そつう",
    "そつえん",
    "そっかん",
    "そつぎょう",
    "そっけつ",
    "そっこう",
    "そっせん",
    "そっと",
    "そとがわ",
    "そとづら",
    "そなえる",
    "そなた",
    "そふぼ",
    "そぼく",
    "そぼろ",
    "そまつ",
    "そまる",
    "そむく",
    "そむりえ",
    "そめる",
    "そもそも",
    "そよかぜ",
    "そらまめ",
    "そろう",
    "そんかい",
    "そんけい",
    "そんざい",
    "そんしつ",
    "そんぞく",
    "そんちょう",
    "ぞんび",
    "ぞんぶん",
    "そんみん",
    "たあい",
    "たいいん",
    "たいうん",
    "たいえき",
    "たいおう",
    "だいがく",
    "たいき",
    "たいぐう",
    "たいけん",
    "たいこ",
    "たいざい",
    "だいじょうぶ",
    "だいすき",
    "たいせつ",
    "たいそう",
    "だいたい",
    "たいちょう",
    "たいてい",
    "だいどころ",
    "たいない",
    "たいねつ",
    "たいのう",
    "たいはん",
    "だいひょう",
    "たいふう",
    "たいへん",
    "たいほ",
    "たいまつばな",
    "たいみんぐ",
    "たいむ",
    "たいめん",
    "たいやき",
    "たいよう",
    "たいら",
    "たいりょく",
    "たいる",
    "たいわん",
    "たうえ",
    "たえる",
    "たおす",
    "たおる",
    "たおれる",
    "たかい",
    "たかね",
    "たきび",
    "たくさん",
    "たこく",
    "たこやき",
    "たさい",
    "たしざん",
    "だじゃれ",
    "たすける",
    "たずさわる",
    "たそがれ",
    "たたかう",
    "たたく",
    "ただしい",
    "たたみ",
    "たちばな",
    "だっかい",
    "だっきゃく",
    "だっこ",
    "だっしゅつ",
    "だったい",
    "たてる",
    "たとえる",
    "たなばた",
    "たにん",
    "たぬき",
    "たのしみ",
    "たはつ",
    "たぶん",
    "たべる",
    "たぼう",
    "たまご",
    "たまる",
    "だむる",
    "ためいき",
    "ためす",
    "ためる",
    "たもつ",
    "たやすい",
    "たよる",
    "たらす",
    "たりきほんがん",
    "たりょう",
    "たりる",
    "たると",
    "たれる",
    "たれんと",
    "たろっと",
    "たわむれる",
    "だんあつ",
    "たんい",
    "たんおん",
    "たんか",
    "たんき",
    "たんけん",
    "たんご",
    "たんさん",
    "たんじょうび",
    "だんせい",
    "たんそく",
    "たんたい",
    "だんち",
    "たんてい",
    "たんとう",
    "だんな",
    "たんにん",
    "だんねつ",
    "たんのう",
    "たんぴん",
    "だんぼう",
    "たんまつ",
    "たんめい",
    "だんれつ",
    "だんろ",
    "だんわ",
    "ちあい",
    "ちあん",
    "ちいき",
    "ちいさい",
    "ちえん",
    "ちかい",
    "ちから",
    "ちきゅう",
    "ちきん",
    "ちけいず",
    "ちけん",
    "ちこく",
    "ちさい",
    "ちしき",
    "ちしりょう",
    "ちせい",
    "ちそう",
    "ちたい",
    "ちたん",
    "ちちおや",
    "ちつじょ",
    "ちてき",
    "ちてん",
    "ちぬき",
    "ちぬり",
    "ちのう",
    "ちひょう",
    "ちへいせん",
    "ちほう",
    "ちまた",
    "ちみつ",
    "ちみどろ",
    "ちめいど",
    "ちゃんこなべ",
    "ちゅうい",
    "ちゆりょく",
    "ちょうし",
    "ちょさくけん",
    "ちらし",
    "ちらみ",
    "ちりがみ",
    "ちりょう",
    "ちるど",
    "ちわわ",
    "ちんたい",
    "ちんもく",
    "ついか",
    "ついたち",
    "つうか",
    "つうじょう",
    "つうはん",
    "つうわ",
    "つかう",
    "つかれる",
    "つくね",
    "つくる",
    "つけね",
    "つける",
    "つごう",
    "つたえる",
    "つづく",
    "つつじ",
    "つつむ",
    "つとめる",
    "つながる",
    "つなみ",
    "つねづね",
    "つのる",
    "つぶす",
    "つまらない",
    "つまる",
    "つみき",
    "つめたい",
    "つもり",
    "つもる",
    "つよい",
    "つるぼ",
    "つるみく",
    "つわもの",
    "つわり",
    "てあし",
    "てあて",
    "てあみ",
    "ていおん",
    "ていか",
    "ていき",
    "ていけい",
    "ていこく",
    "ていさつ",
    "ていし",
    "ていせい",
    "ていたい",
    "ていど",
    "ていねい",
    "ていひょう",
    "ていへん",
    "ていぼう",
    "てうち",
    "ておくれ",
    "てきとう",
    "てくび",
    "でこぼこ",
    "てさぎょう",
    "てさげ",
    "てすり",
    "てそう",
    "てちがい",
    "てちょう",
    "てつがく",
    "てつづき",
    "でっぱ",
    "てつぼう",
    "てつや",
    "でぬかえ",
    "てぬき",
    "てぬぐい",
    "てのひら",
    "てはい",
    "てぶくろ",
    "てふだ",
    "てほどき",
    "てほん",
    "てまえ",
    "てまきずし",
    "てみじか",
    "てみやげ",
    "てらす",
    "てれび",
    "てわけ",
    "てわたし",
    "でんあつ",
    "てんいん",
    "てんかい",
    "てんき",
    "てんぐ",
    "てんけん",
    "てんごく",
    "てんさい",
    "てんし",
    "てんすう",
    "でんち",
    "てんてき",
    "てんとう",
    "てんない",
    "てんぷら",
    "てんぼうだい",
    "てんめつ",
    "てんらんかい",
    "でんりょく",
    "でんわ",
    "どあい",
    "といれ",
    "どうかん",
    "とうきゅう",
    "どうぐ",
    "とうし",
    "とうむぎ",
    "とおい",
    "とおか",
    "とおく",
    "とおす",
    "とおる",
    "とかい",
    "とかす",
    "ときおり",
    "ときどき",
    "とくい",
    "とくしゅう",
    "とくてん",
    "とくに",
    "とくべつ",
    "とけい",
    "とける",
    "とこや",
    "とさか",
    "としょかん",
    "とそう",
    "とたん",
    "とちゅう",
    "とっきゅう",
    "とっくん",
    "とつぜん",
    "とつにゅう",
    "とどける",
    "ととのえる",
    "とない",
    "となえる",
    "となり",
    "とのさま",
    "とばす",
    "どぶがわ",
    "とほう",
    "とまる",
    "とめる",
    "ともだち",
    "ともる",
    "どようび",
    "とらえる",
    "とんかつ",
    "どんぶり",
    "ないかく",
    "ないこう",
    "ないしょ",
    "ないす",
    "ないせん",
    "ないそう",
    "なおす",
    "ながい",
    "なくす",
    "なげる",
    "なこうど",
    "なさけ",
    "なたでここ",
    "なっとう",
    "なつやすみ",
    "ななおし",
    "なにごと",
    "なにもの",
    "なにわ",
    "なのか",
    "なふだ",
    "なまいき",
    "なまえ",
    "なまみ",
    "なみだ",
    "なめらか",
    "なめる",
    "なやむ",
    "ならう",
    "ならび",
    "ならぶ",
    "なれる",
    "なわとび",
    "なわばり",
    "にあう",
    "にいがた",
    "にうけ",
    "におい",
    "にかい",
    "にがて",
    "にきび",
    "にくしみ",
    "にくまん",
    "にげる",
    "にさんかたんそ",
    "にしき",
    "にせもの",
    "にちじょう",
    "にちようび",
    "にっか",
    "にっき",
    "にっけい",
    "にっこう",
    "にっさん",
    "にっしょく",
    "にっすう",
    "にっせき",
    "にってい",
    "になう",
    "にほん",
    "にまめ",
    "にもつ",
    "にやり",
    "にゅういん",
    "にりんしゃ",
    "にわとり",
    "にんい",
    "にんか",
    "にんき",
    "にんげん",
    "にんしき",
    "にんずう",
    "にんそう",
    "にんたい",
    "にんち",
    "にんてい",
    "にんにく",
    "にんぷ",
    "にんまり",
    "にんむ",
    "にんめい",
    "にんよう",
    "ぬいくぎ",
    "ぬかす",
    "ぬぐいとる",
    "ぬぐう",
    "ぬくもり",
    "ぬすむ",
    "ぬまえび",
    "ぬめり",
    "ぬらす",
    "ぬんちゃく",
    "ねあげ",
    "ねいき",
    "ねいる",
    "ねいろ",
    "ねぐせ",
    "ねくたい",
    "ねくら",
    "ねこぜ",
    "ねこむ",
    "ねさげ",
    "ねすごす",
    "ねそべる",
    "ねだん",
    "ねつい",
    "ねっしん",
    "ねつぞう",
    "ねったいぎょ",
    "ねぶそく",
    "ねふだ",
    "ねぼう",
    "ねほりはほり",
    "ねまき",
    "ねまわし",
    "ねみみ",
    "ねむい",
    "ねむたい",
    "ねもと",
    "ねらう",
    "ねわざ",
    "ねんいり",
    "ねんおし",
    "ねんかん",
    "ねんきん",
    "ねんぐ",
    "ねんざ",
    "ねんし",
    "ねんちゃく",
    "ねんど",
    "ねんぴ",
    "ねんぶつ",
    "ねんまつ",
    "ねんりょう",
    "ねんれい",
    "のいず",
    "のおづま",
    "のがす",
    "のきなみ",
    "のこぎり",
    "のこす",
    "のこる",
    "のせる",
    "のぞく",
    "のぞむ",
    "のたまう",
    "のちほど",
    "のっく",
    "のばす",
    "のはら",
    "のべる",
    "のぼる",
    "のみもの",
    "のやま",
    "のらいぬ",
    "のらねこ",
    "のりもの",
    "のりゆき",
    "のれん",
    "のんき",
    "ばあい",
    "はあく",
    "ばあさん",
    "ばいか",
    "ばいく",
    "はいけん",
    "はいご",
    "はいしん",
    "はいすい",
    "はいせん",
    "はいそう",
    "はいち",
    "ばいばい",
    "はいれつ",
    "はえる",
    "はおる",
    "はかい",
    "ばかり",
    "はかる",
    "はくしゅ",
    "はけん",
    "はこぶ",
    "はさみ",
    "はさん",
    "はしご",
    "ばしょ",
    "はしる",
    "はせる",
    "ぱそこん",
    "はそん",
    "はたん",
    "はちみつ",
    "はつおん",
    "はっかく",
    "はづき",
    "はっきり",
    "はっくつ",
    "はっけん",
    "はっこう",
    "はっさん",
    "はっしん",
    "はったつ",
    "はっちゅう",
    "はってん",
    "はっぴょう",
    "はっぽう",
    "はなす",
    "はなび",
    "はにかむ",
    "はぶらし",
    "はみがき",
    "はむかう",
    "はめつ",
    "はやい",
    "はやし",
    "はらう",
    "はろうぃん",
    "はわい",
    "はんい",
    "はんえい",
    "はんおん",
    "はんかく",
    "はんきょう",
    "ばんぐみ",
    "はんこ",
    "はんしゃ",
    "はんすう",
    "はんだん",
    "ぱんち",
    "ぱんつ",
    "はんてい",
    "はんとし",
    "はんのう",
    "はんぱ",
    "はんぶん",
    "はんぺん",
    "はんぼうき",
    "はんめい",
    "はんらん",
    "はんろん",
    "ひいき",
    "ひうん",
    "ひえる",
    "ひかく",
    "ひかり",
    "ひかる",
    "ひかん",
    "ひくい",
    "ひけつ",
    "ひこうき",
    "ひこく",
    "ひさい",
    "ひさしぶり",
    "ひさん",
    "びじゅつかん",
    "ひしょ",
    "ひそか",
    "ひそむ",
    "ひたむき",
    "ひだり",
    "ひたる",
    "ひつぎ",
    "ひっこし",
    "ひっし",
    "ひつじゅひん",
    "ひっす",
    "ひつぜん",
    "ぴったり",
    "ぴっちり",
    "ひつよう",
    "ひてい",
    "ひとごみ",
    "ひなまつり",
    "ひなん",
    "ひねる",
    "ひはん",
    "ひびく",
    "ひひょう",
    "ひほう",
    "ひまわり",
    "ひまん",
    "ひみつ",
    "ひめい",
    "ひめじし",
    "ひやけ",
    "ひやす",
    "ひよう",
    "びょうき",
    "ひらがな",
    "ひらく",
    "ひりつ",
    "ひりょう",
    "ひるま",
    "ひるやすみ",
    "ひれい",
    "ひろい",
    "ひろう",
    "ひろき",
    "ひろゆき",
    "ひんかく",
    "ひんけつ",
    "ひんこん",
    "ひんしゅ",
    "ひんそう",
    "ぴんち",
    "ひんぱん",
    "びんぼう",
    "ふあん",
    "ふいうち",
    "ふうけい",
    "ふうせん",
    "ぷうたろう",
    "ふうとう",
    "ふうふ",
    "ふえる",
    "ふおん",
    "ふかい",
    "ふきん",
    "ふくざつ",
    "ふくぶくろ",
    "ふこう",
    "ふさい",
    "ふしぎ",
    "ふじみ",
    "ふすま",
    "ふせい",
    "ふせぐ",
    "ふそく",
    "ぶたにく",
    "ふたん",
    "ふちょう",
    "ふつう",
    "ふつか",
    "ふっかつ",
    "ふっき",
    "ふっこく",
    "ぶどう",
    "ふとる",
    "ふとん",
    "ふのう",
    "ふはい",
    "ふひょう",
    "ふへん",
    "ふまん",
    "ふみん",
    "ふめつ",
    "ふめん",
    "ふよう",
    "ふりこ",
    "ふりる",
    "ふるい",
    "ふんいき",
    "ぶんがく",
    "ぶんぐ",
    "ふんしつ",
    "ぶんせき",
    "ふんそう",
    "ぶんぽう",
    "へいあん",
    "へいおん",
    "へいがい",
    "へいき",
    "へいげん",
    "へいこう",
    "へいさ",
    "へいしゃ",
    "へいせつ",
    "へいそ",
    "へいたく",
    "へいてん",
    "へいねつ",
    "へいわ",
    "へきが",
    "へこむ",
    "べにいろ",
    "べにしょうが",
    "へらす",
    "へんかん",
    "べんきょう",
    "べんごし",
    "へんさい",
    "へんたい",
    "べんり",
    "ほあん",
    "ほいく",
    "ぼうぎょ",
    "ほうこく",
    "ほうそう",
    "ほうほう",
    "ほうもん",
    "ほうりつ",
    "ほえる",
    "ほおん",
    "ほかん",
    "ほきょう",
    "ぼきん",
    "ほくろ",
    "ほけつ",
    "ほけん",
    "ほこう",
    "ほこる",
    "ほしい",
    "ほしつ",
    "ほしゅ",
    "ほしょう",
    "ほせい",
    "ほそい",
    "ほそく",
    "ほたて",
    "ほたる",
    "ぽちぶくろ",
    "ほっきょく",
    "ほっさ",
    "ほったん",
    "ほとんど",
    "ほめる",
    "ほんい",
    "ほんき",
    "ほんけ",
    "ほんしつ",
    "ほんやく",
    "まいにち",
    "まかい",
    "まかせる",
    "まがる",
    "まける",
    "まこと",
    "まさつ",
    "まじめ",
    "ますく",
    "まぜる",
    "まつり",
    "まとめ",
    "まなぶ",
    "まぬけ",
    "まねく",
    "まほう",
    "まもる",
    "まゆげ",
    "まよう",
    "まろやか",
    "まわす",
    "まわり",
    "まわる",
    "まんが",
    "まんきつ",
    "まんぞく",
    "まんなか",
    "みいら",
    "みうち",
    "みえる",
    "みがく",
    "みかた",
    "みかん",
    "みけん",
    "みこん",
    "みじかい",
    "みすい",
    "みすえる",
    "みせる",
    "みっか",
    "みつかる",
    "みつける",
    "みてい",
    "みとめる",
    "みなと",
    "みなみかさい",
    "みねらる",
    "みのう",
    "みのがす",
    "みほん",
    "みもと",
    "みやげ",
    "みらい",
    "みりょく",
    "みわく",
    "みんか",
    "みんぞく",
    "むいか",
    "むえき",
    "むえん",
    "むかい",
    "むかう",
    "むかえ",
    "むかし",
    "むぎちゃ",
    "むける",
    "むげん",
    "むさぼる",
    "むしあつい",
    "むしば",
    "むじゅん",
    "むしろ",
    "むすう",
    "むすこ",
    "むすぶ",
    "むすめ",
    "むせる",
    "むせん",
    "むちゅう",
    "むなしい",
    "むのう",
    "むやみ",
    "むよう",
    "むらさき",
    "むりょう",
    "むろん",
    "めいあん",
    "めいうん",
    "めいえん",
    "めいかく",
    "めいきょく",
    "めいさい",
    "めいし",
    "めいそう",
    "めいぶつ",
    "めいれい",
    "めいわく",
    "めぐまれる",
    "めざす",
    "めした",
    "めずらしい",
    "めだつ",
    "めまい",
    "めやす",
    "めんきょ",
    "めんせき",
    "めんどう",
    "もうしあげる",
    "もうどうけん",
    "もえる",
    "もくし",
    "もくてき",
    "もくようび",
    "もちろん",
    "もどる",
    "もらう",
    "もんく",
    "もんだい",
    "やおや",
    "やける",
    "やさい",
    "やさしい",
    "やすい",
    "やすたろう",
    "やすみ",
    "やせる",
    "やそう",
    "やたい",
    "やちん",
    "やっと",
    "やっぱり",
    "やぶる",
    "やめる",
    "ややこしい",
    "やよい",
    "やわらかい",
    "ゆうき",
    "ゆうびんきょく",
    "ゆうべ",
    "ゆうめい",
    "ゆけつ",
    "ゆしゅつ",
    "ゆせん",
    "ゆそう",
    "ゆたか",
    "ゆちゃく",
    "ゆでる",
    "ゆにゅう",
    "ゆびわ",
    "ゆらい",
    "ゆれる",
    "ようい",
    "ようか",
    "ようきゅう",
    "ようじ",
    "ようす",
    "ようちえん",
    "よかぜ",
    "よかん",
    "よきん",
    "よくせい",
    "よくぼう",
    "よけい",
    "よごれる",
    "よさん",
    "よしゅう",
    "よそう",
    "よそく",
    "よっか",
    "よてい",
    "よどがわく",
    "よねつ",
    "よやく",
    "よゆう",
    "よろこぶ",
    "よろしい",
    "らいう",
    "らくがき",
    "らくご",
    "らくさつ",
    "らくだ",
    "らしんばん",
    "らせん",
    "らぞく",
    "らたい",
    "らっか",
    "られつ",
    "りえき",
    "りかい",
    "りきさく",
    "りきせつ",
    "りくぐん",
    "りくつ",
    "りけん",
    "りこう",
    "りせい",
    "りそう",
    "りそく",
    "りてん",
    "りねん",
    "りゆう",
    "りゅうがく",
    "りよう",
    "りょうり",
    "りょかん",
    "りょくちゃ",
    "りょこう",
    "りりく",
    "りれき",
    "りろん",
    "りんご",
    "るいけい",
    "るいさい",
    "るいじ",
    "るいせき",
    "るすばん",
    "るりがわら",
    "れいかん",
    "れいぎ",
    "れいせい",
    "れいぞうこ",
    "れいとう",
    "れいぼう",
    "れきし",
    "れきだい",
    "れんあい",
    "れんけい",
    "れんこん",
    "れんさい",
    "れんしゅう",
    "れんぞく",
    "れんらく",
    "ろうか",
    "ろうご",
    "ろうじん",
    "ろうそく",
    "ろくが",
    "ろこつ",
    "ろじうら",
    "ろしゅつ",
    "ろせん",
    "ろてん",
    "ろめん",
    "ろれつ",
    "ろんぎ",
    "ろんぱ",
    "ろんぶん",
    "ろんり",
    "わかす",
    "わかめ",
    "わかやま",
    "わかれる",
    "わしつ",
    "わじまし",
    "わすれもの",
    "わらう",
    "われる"
]

},{}],53:[function(require,module,exports){
module.exports=[
    "가격",
    "가끔",
    "가난",
    "가능",
    "가득",
    "가르침",
    "가뭄",
    "가방",
    "가상",
    "가슴",
    "가운데",
    "가을",
    "가이드",
    "가입",
    "가장",
    "가정",
    "가족",
    "가죽",
    "각오",
    "각자",
    "간격",
    "간부",
    "간섭",
    "간장",
    "간접",
    "간판",
    "갈등",
    "갈비",
    "갈색",
    "갈증",
    "감각",
    "감기",
    "감소",
    "감수성",
    "감자",
    "감정",
    "갑자기",
    "강남",
    "강당",
    "강도",
    "강력히",
    "강변",
    "강북",
    "강사",
    "강수량",
    "강아지",
    "강원도",
    "강의",
    "강제",
    "강조",
    "같이",
    "개구리",
    "개나리",
    "개방",
    "개별",
    "개선",
    "개성",
    "개인",
    "객관적",
    "거실",
    "거액",
    "거울",
    "거짓",
    "거품",
    "걱정",
    "건강",
    "건물",
    "건설",
    "건조",
    "건축",
    "걸음",
    "검사",
    "검토",
    "게시판",
    "게임",
    "겨울",
    "견해",
    "결과",
    "결국",
    "결론",
    "결석",
    "결승",
    "결심",
    "결정",
    "결혼",
    "경계",
    "경고",
    "경기",
    "경력",
    "경복궁",
    "경비",
    "경상도",
    "경영",
    "경우",
    "경쟁",
    "경제",
    "경주",
    "경찰",
    "경치",
    "경향",
    "경험",
    "계곡",
    "계단",
    "계란",
    "계산",
    "계속",
    "계약",
    "계절",
    "계층",
    "계획",
    "고객",
    "고구려",
    "고궁",
    "고급",
    "고등학생",
    "고무신",
    "고민",
    "고양이",
    "고장",
    "고전",
    "고집",
    "고춧가루",
    "고통",
    "고향",
    "곡식",
    "골목",
    "골짜기",
    "골프",
    "공간",
    "공개",
    "공격",
    "공군",
    "공급",
    "공기",
    "공동",
    "공무원",
    "공부",
    "공사",
    "공식",
    "공업",
    "공연",
    "공원",
    "공장",
    "공짜",
    "공책",
    "공통",
    "공포",
    "공항",
    "공휴일",
    "과목",
    "과일",
    "과장",
    "과정",
    "과학",
    "관객",
    "관계",
    "관광",
    "관념",
    "관람",
    "관련",
    "관리",
    "관습",
    "관심",
    "관점",
    "관찰",
    "광경",
    "광고",
    "광장",
    "광주",
    "괴로움",
    "굉장히",
    "교과서",
    "교문",
    "교복",
    "교실",
    "교양",
    "교육",
    "교장",
    "교직",
    "교통",
    "교환",
    "교훈",
    "구경",
    "구름",
    "구멍",
    "구별",
    "구분",
    "구석",
    "구성",
    "구속",
    "구역",
    "구입",
    "구청",
    "구체적",
    "국가",
    "국기",
    "국내",
    "국립",
    "국물",
    "국민",
    "국수",
    "국어",
    "국왕",
    "국적",
    "국제",
    "국회",
    "군대",
    "군사",
    "군인",
    "궁극적",
    "권리",
    "권위",
    "권투",
    "귀국",
    "귀신",
    "규정",
    "규칙",
    "균형",
    "그날",
    "그냥",
    "그늘",
    "그러나",
    "그룹",
    "그릇",
    "그림",
    "그제서야",
    "그토록",
    "극복",
    "극히",
    "근거",
    "근교",
    "근래",
    "근로",
    "근무",
    "근본",
    "근원",
    "근육",
    "근처",
    "글씨",
    "글자",
    "금강산",
    "금고",
    "금년",
    "금메달",
    "금액",
    "금연",
    "금요일",
    "금지",
    "긍정적",
    "기간",
    "기관",
    "기념",
    "기능",
    "기독교",
    "기둥",
    "기록",
    "기름",
    "기법",
    "기본",
    "기분",
    "기쁨",
    "기숙사",
    "기술",
    "기억",
    "기업",
    "기온",
    "기운",
    "기원",
    "기적",
    "기준",
    "기침",
    "기혼",
    "기획",
    "긴급",
    "긴장",
    "길이",
    "김밥",
    "김치",
    "김포공항",
    "깍두기",
    "깜빡",
    "깨달음",
    "깨소금",
    "껍질",
    "꼭대기",
    "꽃잎",
    "나들이",
    "나란히",
    "나머지",
    "나물",
    "나침반",
    "나흘",
    "낙엽",
    "난방",
    "날개",
    "날씨",
    "날짜",
    "남녀",
    "남대문",
    "남매",
    "남산",
    "남자",
    "남편",
    "남학생",
    "낭비",
    "낱말",
    "내년",
    "내용",
    "내일",
    "냄비",
    "냄새",
    "냇물",
    "냉동",
    "냉면",
    "냉방",
    "냉장고",
    "넥타이",
    "넷째",
    "노동",
    "노란색",
    "노력",
    "노인",
    "녹음",
    "녹차",
    "녹화",
    "논리",
    "논문",
    "논쟁",
    "놀이",
    "농구",
    "농담",
    "농민",
    "농부",
    "농업",
    "농장",
    "농촌",
    "높이",
    "눈동자",
    "눈물",
    "눈썹",
    "뉴욕",
    "느낌",
    "늑대",
    "능동적",
    "능력",
    "다방",
    "다양성",
    "다음",
    "다이어트",
    "다행",
    "단계",
    "단골",
    "단독",
    "단맛",
    "단순",
    "단어",
    "단위",
    "단점",
    "단체",
    "단추",
    "단편",
    "단풍",
    "달걀",
    "달러",
    "달력",
    "달리",
    "닭고기",
    "담당",
    "담배",
    "담요",
    "담임",
    "답변",
    "답장",
    "당근",
    "당분간",
    "당연히",
    "당장",
    "대규모",
    "대낮",
    "대단히",
    "대답",
    "대도시",
    "대략",
    "대량",
    "대륙",
    "대문",
    "대부분",
    "대신",
    "대응",
    "대장",
    "대전",
    "대접",
    "대중",
    "대책",
    "대출",
    "대충",
    "대통령",
    "대학",
    "대한민국",
    "대합실",
    "대형",
    "덩어리",
    "데이트",
    "도대체",
    "도덕",
    "도둑",
    "도망",
    "도서관",
    "도심",
    "도움",
    "도입",
    "도자기",
    "도저히",
    "도전",
    "도중",
    "도착",
    "독감",
    "독립",
    "독서",
    "독일",
    "독창적",
    "동화책",
    "뒷모습",
    "뒷산",
    "딸아이",
    "마누라",
    "마늘",
    "마당",
    "마라톤",
    "마련",
    "마무리",
    "마사지",
    "마약",
    "마요네즈",
    "마을",
    "마음",
    "마이크",
    "마중",
    "마지막",
    "마찬가지",
    "마찰",
    "마흔",
    "막걸리",
    "막내",
    "막상",
    "만남",
    "만두",
    "만세",
    "만약",
    "만일",
    "만점",
    "만족",
    "만화",
    "많이",
    "말기",
    "말씀",
    "말투",
    "맘대로",
    "망원경",
    "매년",
    "매달",
    "매력",
    "매번",
    "매스컴",
    "매일",
    "매장",
    "맥주",
    "먹이",
    "먼저",
    "먼지",
    "멀리",
    "메일",
    "며느리",
    "며칠",
    "면담",
    "멸치",
    "명단",
    "명령",
    "명예",
    "명의",
    "명절",
    "명칭",
    "명함",
    "모금",
    "모니터",
    "모델",
    "모든",
    "모범",
    "모습",
    "모양",
    "모임",
    "모조리",
    "모집",
    "모퉁이",
    "목걸이",
    "목록",
    "목사",
    "목소리",
    "목숨",
    "목적",
    "목표",
    "몰래",
    "몸매",
    "몸무게",
    "몸살",
    "몸속",
    "몸짓",
    "몸통",
    "몹시",
    "무관심",
    "무궁화",
    "무더위",
    "무덤",
    "무릎",
    "무슨",
    "무엇",
    "무역",
    "무용",
    "무조건",
    "무지개",
    "무척",
    "문구",
    "문득",
    "문법",
    "문서",
    "문제",
    "문학",
    "문화",
    "물가",
    "물건",
    "물결",
    "물고기",
    "물론",
    "물리학",
    "물음",
    "물질",
    "물체",
    "미국",
    "미디어",
    "미사일",
    "미술",
    "미역",
    "미용실",
    "미움",
    "미인",
    "미팅",
    "미혼",
    "민간",
    "민족",
    "민주",
    "믿음",
    "밀가루",
    "밀리미터",
    "밑바닥",
    "바가지",
    "바구니",
    "바나나",
    "바늘",
    "바닥",
    "바닷가",
    "바람",
    "바이러스",
    "바탕",
    "박물관",
    "박사",
    "박수",
    "반대",
    "반드시",
    "반말",
    "반발",
    "반성",
    "반응",
    "반장",
    "반죽",
    "반지",
    "반찬",
    "받침",
    "발가락",
    "발걸음",
    "발견",
    "발달",
    "발레",
    "발목",
    "발바닥",
    "발생",
    "발음",
    "발자국",
    "발전",
    "발톱",
    "발표",
    "밤하늘",
    "밥그릇",
    "밥맛",
    "밥상",
    "밥솥",
    "방금",
    "방면",
    "방문",
    "방바닥",
    "방법",
    "방송",
    "방식",
    "방안",
    "방울",
    "방지",
    "방학",
    "방해",
    "방향",
    "배경",
    "배꼽",
    "배달",
    "배드민턴",
    "백두산",
    "백색",
    "백성",
    "백인",
    "백제",
    "백화점",
    "버릇",
    "버섯",
    "버튼",
    "번개",
    "번역",
    "번지",
    "번호",
    "벌금",
    "벌레",
    "벌써",
    "범위",
    "범인",
    "범죄",
    "법률",
    "법원",
    "법적",
    "법칙",
    "베이징",
    "벨트",
    "변경",
    "변동",
    "변명",
    "변신",
    "변호사",
    "변화",
    "별도",
    "별명",
    "별일",
    "병실",
    "병아리",
    "병원",
    "보관",
    "보너스",
    "보라색",
    "보람",
    "보름",
    "보상",
    "보안",
    "보자기",
    "보장",
    "보전",
    "보존",
    "보통",
    "보편적",
    "보험",
    "복도",
    "복사",
    "복숭아",
    "복습",
    "볶음",
    "본격적",
    "본래",
    "본부",
    "본사",
    "본성",
    "본인",
    "본질",
    "볼펜",
    "봉사",
    "봉지",
    "봉투",
    "부근",
    "부끄러움",
    "부담",
    "부동산",
    "부문",
    "부분",
    "부산",
    "부상",
    "부엌",
    "부인",
    "부작용",
    "부장",
    "부정",
    "부족",
    "부지런히",
    "부친",
    "부탁",
    "부품",
    "부회장",
    "북부",
    "북한",
    "분노",
    "분량",
    "분리",
    "분명",
    "분석",
    "분야",
    "분위기",
    "분필",
    "분홍색",
    "불고기",
    "불과",
    "불교",
    "불꽃",
    "불만",
    "불법",
    "불빛",
    "불안",
    "불이익",
    "불행",
    "브랜드",
    "비극",
    "비난",
    "비닐",
    "비둘기",
    "비디오",
    "비로소",
    "비만",
    "비명",
    "비밀",
    "비바람",
    "비빔밥",
    "비상",
    "비용",
    "비율",
    "비중",
    "비타민",
    "비판",
    "빌딩",
    "빗물",
    "빗방울",
    "빗줄기",
    "빛깔",
    "빨간색",
    "빨래",
    "빨리",
    "사건",
    "사계절",
    "사나이",
    "사냥",
    "사람",
    "사랑",
    "사립",
    "사모님",
    "사물",
    "사방",
    "사상",
    "사생활",
    "사설",
    "사슴",
    "사실",
    "사업",
    "사용",
    "사월",
    "사장",
    "사전",
    "사진",
    "사촌",
    "사춘기",
    "사탕",
    "사투리",
    "사흘",
    "산길",
    "산부인과",
    "산업",
    "산책",
    "살림",
    "살인",
    "살짝",
    "삼계탕",
    "삼국",
    "삼십",
    "삼월",
    "삼촌",
    "상관",
    "상금",
    "상대",
    "상류",
    "상반기",
    "상상",
    "상식",
    "상업",
    "상인",
    "상자",
    "상점",
    "상처",
    "상추",
    "상태",
    "상표",
    "상품",
    "상황",
    "새벽",
    "색깔",
    "색연필",
    "생각",
    "생명",
    "생물",
    "생방송",
    "생산",
    "생선",
    "생신",
    "생일",
    "생활",
    "서랍",
    "서른",
    "서명",
    "서민",
    "서비스",
    "서양",
    "서울",
    "서적",
    "서점",
    "서쪽",
    "서클",
    "석사",
    "석유",
    "선거",
    "선물",
    "선배",
    "선생",
    "선수",
    "선원",
    "선장",
    "선전",
    "선택",
    "선풍기",
    "설거지",
    "설날",
    "설렁탕",
    "설명",
    "설문",
    "설사",
    "설악산",
    "설치",
    "설탕",
    "섭씨",
    "성공",
    "성당",
    "성명",
    "성별",
    "성인",
    "성장",
    "성적",
    "성질",
    "성함",
    "세금",
    "세미나",
    "세상",
    "세월",
    "세종대왕",
    "세탁",
    "센터",
    "센티미터",
    "셋째",
    "소규모",
    "소극적",
    "소금",
    "소나기",
    "소년",
    "소득",
    "소망",
    "소문",
    "소설",
    "소속",
    "소아과",
    "소용",
    "소원",
    "소음",
    "소중히",
    "소지품",
    "소질",
    "소풍",
    "소형",
    "속담",
    "속도",
    "속옷",
    "손가락",
    "손길",
    "손녀",
    "손님",
    "손등",
    "손목",
    "손뼉",
    "손실",
    "손질",
    "손톱",
    "손해",
    "솔직히",
    "솜씨",
    "송아지",
    "송이",
    "송편",
    "쇠고기",
    "쇼핑",
    "수건",
    "수년",
    "수단",
    "수돗물",
    "수동적",
    "수면",
    "수명",
    "수박",
    "수상",
    "수석",
    "수술",
    "수시로",
    "수업",
    "수염",
    "수영",
    "수입",
    "수준",
    "수집",
    "수출",
    "수컷",
    "수필",
    "수학",
    "수험생",
    "수화기",
    "숙녀",
    "숙소",
    "숙제",
    "순간",
    "순서",
    "순수",
    "순식간",
    "순위",
    "숟가락",
    "술병",
    "술집",
    "숫자",
    "스님",
    "스물",
    "스스로",
    "스승",
    "스웨터",
    "스위치",
    "스케이트",
    "스튜디오",
    "스트레스",
    "스포츠",
    "슬쩍",
    "슬픔",
    "습관",
    "습기",
    "승객",
    "승리",
    "승부",
    "승용차",
    "승진",
    "시각",
    "시간",
    "시골",
    "시금치",
    "시나리오",
    "시댁",
    "시리즈",
    "시멘트",
    "시민",
    "시부모",
    "시선",
    "시설",
    "시스템",
    "시아버지",
    "시어머니",
    "시월",
    "시인",
    "시일",
    "시작",
    "시장",
    "시절",
    "시점",
    "시중",
    "시즌",
    "시집",
    "시청",
    "시합",
    "시험",
    "식구",
    "식기",
    "식당",
    "식량",
    "식료품",
    "식물",
    "식빵",
    "식사",
    "식생활",
    "식초",
    "식탁",
    "식품",
    "신고",
    "신규",
    "신념",
    "신문",
    "신발",
    "신비",
    "신사",
    "신세",
    "신용",
    "신제품",
    "신청",
    "신체",
    "신화",
    "실감",
    "실내",
    "실력",
    "실례",
    "실망",
    "실수",
    "실습",
    "실시",
    "실장",
    "실정",
    "실질적",
    "실천",
    "실체",
    "실컷",
    "실태",
    "실패",
    "실험",
    "실현",
    "심리",
    "심부름",
    "심사",
    "심장",
    "심정",
    "심판",
    "쌍둥이",
    "씨름",
    "씨앗",
    "아가씨",
    "아나운서",
    "아드님",
    "아들",
    "아쉬움",
    "아스팔트",
    "아시아",
    "아울러",
    "아저씨",
    "아줌마",
    "아직",
    "아침",
    "아파트",
    "아프리카",
    "아픔",
    "아홉",
    "아흔",
    "악기",
    "악몽",
    "악수",
    "안개",
    "안경",
    "안과",
    "안내",
    "안녕",
    "안동",
    "안방",
    "안부",
    "안주",
    "알루미늄",
    "알코올",
    "암시",
    "암컷",
    "압력",
    "앞날",
    "앞문",
    "애인",
    "애정",
    "액수",
    "앨범",
    "야간",
    "야단",
    "야옹",
    "약간",
    "약국",
    "약속",
    "약수",
    "약점",
    "약품",
    "약혼녀",
    "양념",
    "양력",
    "양말",
    "양배추",
    "양주",
    "양파",
    "어둠",
    "어려움",
    "어른",
    "어젯밤",
    "어쨌든",
    "어쩌다가",
    "어쩐지",
    "언니",
    "언덕",
    "언론",
    "언어",
    "얼굴",
    "얼른",
    "얼음",
    "얼핏",
    "엄마",
    "업무",
    "업종",
    "업체",
    "엉덩이",
    "엉망",
    "엉터리",
    "엊그제",
    "에너지",
    "에어컨",
    "엔진",
    "여건",
    "여고생",
    "여관",
    "여군",
    "여권",
    "여대생",
    "여덟",
    "여동생",
    "여든",
    "여론",
    "여름",
    "여섯",
    "여성",
    "여왕",
    "여인",
    "여전히",
    "여직원",
    "여학생",
    "여행",
    "역사",
    "역시",
    "역할",
    "연결",
    "연구",
    "연극",
    "연기",
    "연락",
    "연설",
    "연세",
    "연속",
    "연습",
    "연애",
    "연예인",
    "연인",
    "연장",
    "연주",
    "연출",
    "연필",
    "연합",
    "연휴",
    "열기",
    "열매",
    "열쇠",
    "열심히",
    "열정",
    "열차",
    "열흘",
    "염려",
    "엽서",
    "영국",
    "영남",
    "영상",
    "영양",
    "영역",
    "영웅",
    "영원히",
    "영하",
    "영향",
    "영혼",
    "영화",
    "옆구리",
    "옆방",
    "옆집",
    "예감",
    "예금",
    "예방",
    "예산",
    "예상",
    "예선",
    "예술",
    "예습",
    "예식장",
    "예약",
    "예전",
    "예절",
    "예정",
    "예컨대",
    "옛날",
    "오늘",
    "오락",
    "오랫동안",
    "오렌지",
    "오로지",
    "오른발",
    "오븐",
    "오십",
    "오염",
    "오월",
    "오전",
    "오직",
    "오징어",
    "오페라",
    "오피스텔",
    "오히려",
    "옥상",
    "옥수수",
    "온갖",
    "온라인",
    "온몸",
    "온종일",
    "온통",
    "올가을",
    "올림픽",
    "올해",
    "옷차림",
    "와이셔츠",
    "와인",
    "완성",
    "완전",
    "왕비",
    "왕자",
    "왜냐하면",
    "왠지",
    "외갓집",
    "외국",
    "외로움",
    "외삼촌",
    "외출",
    "외침",
    "외할머니",
    "왼발",
    "왼손",
    "왼쪽",
    "요금",
    "요일",
    "요즘",
    "요청",
    "용기",
    "용서",
    "용어",
    "우산",
    "우선",
    "우승",
    "우연히",
    "우정",
    "우체국",
    "우편",
    "운동",
    "운명",
    "운반",
    "운전",
    "운행",
    "울산",
    "울음",
    "움직임",
    "웃어른",
    "웃음",
    "워낙",
    "원고",
    "원래",
    "원서",
    "원숭이",
    "원인",
    "원장",
    "원피스",
    "월급",
    "월드컵",
    "월세",
    "월요일",
    "웨이터",
    "위반",
    "위법",
    "위성",
    "위원",
    "위험",
    "위협",
    "윗사람",
    "유난히",
    "유럽",
    "유명",
    "유물",
    "유산",
    "유적",
    "유치원",
    "유학",
    "유행",
    "유형",
    "육군",
    "육상",
    "육십",
    "육체",
    "은행",
    "음력",
    "음료",
    "음반",
    "음성",
    "음식",
    "음악",
    "음주",
    "의견",
    "의논",
    "의문",
    "의복",
    "의식",
    "의심",
    "의외로",
    "의욕",
    "의원",
    "의학",
    "이것",
    "이곳",
    "이념",
    "이놈",
    "이달",
    "이대로",
    "이동",
    "이렇게",
    "이력서",
    "이론적",
    "이름",
    "이민",
    "이발소",
    "이별",
    "이불",
    "이빨",
    "이상",
    "이성",
    "이슬",
    "이야기",
    "이용",
    "이웃",
    "이월",
    "이윽고",
    "이익",
    "이전",
    "이중",
    "이튿날",
    "이틀",
    "이혼",
    "인간",
    "인격",
    "인공",
    "인구",
    "인근",
    "인기",
    "인도",
    "인류",
    "인물",
    "인생",
    "인쇄",
    "인연",
    "인원",
    "인재",
    "인종",
    "인천",
    "인체",
    "인터넷",
    "인하",
    "인형",
    "일곱",
    "일기",
    "일단",
    "일대",
    "일등",
    "일반",
    "일본",
    "일부",
    "일상",
    "일생",
    "일손",
    "일요일",
    "일월",
    "일정",
    "일종",
    "일주일",
    "일찍",
    "일체",
    "일치",
    "일행",
    "일회용",
    "임금",
    "임무",
    "입대",
    "입력",
    "입맛",
    "입사",
    "입술",
    "입시",
    "입원",
    "입장",
    "입학",
    "자가용",
    "자격",
    "자극",
    "자동",
    "자랑",
    "자부심",
    "자식",
    "자신",
    "자연",
    "자원",
    "자율",
    "자전거",
    "자정",
    "자존심",
    "자판",
    "작가",
    "작년",
    "작성",
    "작업",
    "작용",
    "작은딸",
    "작품",
    "잔디",
    "잔뜩",
    "잔치",
    "잘못",
    "잠깐",
    "잠수함",
    "잠시",
    "잠옷",
    "잠자리",
    "잡지",
    "장관",
    "장군",
    "장기간",
    "장래",
    "장례",
    "장르",
    "장마",
    "장면",
    "장모",
    "장미",
    "장비",
    "장사",
    "장소",
    "장식",
    "장애인",
    "장인",
    "장점",
    "장차",
    "장학금",
    "재능",
    "재빨리",
    "재산",
    "재생",
    "재작년",
    "재정",
    "재채기",
    "재판",
    "재학",
    "재활용",
    "저것",
    "저고리",
    "저곳",
    "저녁",
    "저런",
    "저렇게",
    "저번",
    "저울",
    "저절로",
    "저축",
    "적극",
    "적당히",
    "적성",
    "적용",
    "적응",
    "전개",
    "전공",
    "전기",
    "전달",
    "전라도",
    "전망",
    "전문",
    "전반",
    "전부",
    "전세",
    "전시",
    "전용",
    "전자",
    "전쟁",
    "전주",
    "전철",
    "전체",
    "전통",
    "전혀",
    "전후",
    "절대",
    "절망",
    "절반",
    "절약",
    "절차",
    "점검",
    "점수",
    "점심",
    "점원",
    "점점",
    "점차",
    "접근",
    "접시",
    "접촉",
    "젓가락",
    "정거장",
    "정도",
    "정류장",
    "정리",
    "정말",
    "정면",
    "정문",
    "정반대",
    "정보",
    "정부",
    "정비",
    "정상",
    "정성",
    "정오",
    "정원",
    "정장",
    "정지",
    "정치",
    "정확히",
    "제공",
    "제과점",
    "제대로",
    "제목",
    "제발",
    "제법",
    "제삿날",
    "제안",
    "제일",
    "제작",
    "제주도",
    "제출",
    "제품",
    "제한",
    "조각",
    "조건",
    "조금",
    "조깅",
    "조명",
    "조미료",
    "조상",
    "조선",
    "조용히",
    "조절",
    "조정",
    "조직",
    "존댓말",
    "존재",
    "졸업",
    "졸음",
    "종교",
    "종로",
    "종류",
    "종소리",
    "종업원",
    "종종",
    "종합",
    "좌석",
    "죄인",
    "주관적",
    "주름",
    "주말",
    "주머니",
    "주먹",
    "주문",
    "주민",
    "주방",
    "주변",
    "주식",
    "주인",
    "주일",
    "주장",
    "주전자",
    "주택",
    "준비",
    "줄거리",
    "줄기",
    "줄무늬",
    "중간",
    "중계방송",
    "중국",
    "중년",
    "중단",
    "중독",
    "중반",
    "중부",
    "중세",
    "중소기업",
    "중순",
    "중앙",
    "중요",
    "중학교",
    "즉석",
    "즉시",
    "즐거움",
    "증가",
    "증거",
    "증권",
    "증상",
    "증세",
    "지각",
    "지갑",
    "지경",
    "지극히",
    "지금",
    "지급",
    "지능",
    "지름길",
    "지리산",
    "지방",
    "지붕",
    "지식",
    "지역",
    "지우개",
    "지원",
    "지적",
    "지점",
    "지진",
    "지출",
    "직선",
    "직업",
    "직원",
    "직장",
    "진급",
    "진동",
    "진로",
    "진료",
    "진리",
    "진짜",
    "진찰",
    "진출",
    "진통",
    "진행",
    "질문",
    "질병",
    "질서",
    "짐작",
    "집단",
    "집안",
    "집중",
    "짜증",
    "찌꺼기",
    "차남",
    "차라리",
    "차량",
    "차림",
    "차별",
    "차선",
    "차츰",
    "착각",
    "찬물",
    "찬성",
    "참가",
    "참기름",
    "참새",
    "참석",
    "참여",
    "참외",
    "참조",
    "찻잔",
    "창가",
    "창고",
    "창구",
    "창문",
    "창밖",
    "창작",
    "창조",
    "채널",
    "채점",
    "책가방",
    "책방",
    "책상",
    "책임",
    "챔피언",
    "처벌",
    "처음",
    "천국",
    "천둥",
    "천장",
    "천재",
    "천천히",
    "철도",
    "철저히",
    "철학",
    "첫날",
    "첫째",
    "청년",
    "청바지",
    "청소",
    "청춘",
    "체계",
    "체력",
    "체온",
    "체육",
    "체중",
    "체험",
    "초등학생",
    "초반",
    "초밥",
    "초상화",
    "초순",
    "초여름",
    "초원",
    "초저녁",
    "초점",
    "초청",
    "초콜릿",
    "촛불",
    "총각",
    "총리",
    "총장",
    "촬영",
    "최근",
    "최상",
    "최선",
    "최신",
    "최악",
    "최종",
    "추석",
    "추억",
    "추진",
    "추천",
    "추측",
    "축구",
    "축소",
    "축제",
    "축하",
    "출근",
    "출발",
    "출산",
    "출신",
    "출연",
    "출입",
    "출장",
    "출판",
    "충격",
    "충고",
    "충돌",
    "충분히",
    "충청도",
    "취업",
    "취직",
    "취향",
    "치약",
    "친구",
    "친척",
    "칠십",
    "칠월",
    "칠판",
    "침대",
    "침묵",
    "침실",
    "칫솔",
    "칭찬",
    "카메라",
    "카운터",
    "칼국수",
    "캐릭터",
    "캠퍼스",
    "캠페인",
    "커튼",
    "컨디션",
    "컬러",
    "컴퓨터",
    "코끼리",
    "코미디",
    "콘서트",
    "콜라",
    "콤플렉스",
    "콩나물",
    "쾌감",
    "쿠데타",
    "크림",
    "큰길",
    "큰딸",
    "큰소리",
    "큰아들",
    "큰어머니",
    "큰일",
    "큰절",
    "클래식",
    "클럽",
    "킬로",
    "타입",
    "타자기",
    "탁구",
    "탁자",
    "탄생",
    "태권도",
    "태양",
    "태풍",
    "택시",
    "탤런트",
    "터널",
    "터미널",
    "테니스",
    "테스트",
    "테이블",
    "텔레비전",
    "토론",
    "토마토",
    "토요일",
    "통계",
    "통과",
    "통로",
    "통신",
    "통역",
    "통일",
    "통장",
    "통제",
    "통증",
    "통합",
    "통화",
    "퇴근",
    "퇴원",
    "퇴직금",
    "튀김",
    "트럭",
    "특급",
    "특별",
    "특성",
    "특수",
    "특징",
    "특히",
    "튼튼히",
    "티셔츠",
    "파란색",
    "파일",
    "파출소",
    "판결",
    "판단",
    "판매",
    "판사",
    "팔십",
    "팔월",
    "팝송",
    "패션",
    "팩스",
    "팩시밀리",
    "팬티",
    "퍼센트",
    "페인트",
    "편견",
    "편의",
    "편지",
    "편히",
    "평가",
    "평균",
    "평생",
    "평소",
    "평양",
    "평일",
    "평화",
    "포스터",
    "포인트",
    "포장",
    "포함",
    "표면",
    "표정",
    "표준",
    "표현",
    "품목",
    "품질",
    "풍경",
    "풍속",
    "풍습",
    "프랑스",
    "프린터",
    "플라스틱",
    "피곤",
    "피망",
    "피아노",
    "필름",
    "필수",
    "필요",
    "필자",
    "필통",
    "핑계",
    "하느님",
    "하늘",
    "하드웨어",
    "하룻밤",
    "하반기",
    "하숙집",
    "하순",
    "하여튼",
    "하지만",
    "하천",
    "하품",
    "하필",
    "학과",
    "학교",
    "학급",
    "학기",
    "학년",
    "학력",
    "학번",
    "학부모",
    "학비",
    "학생",
    "학술",
    "학습",
    "학용품",
    "학원",
    "학위",
    "학자",
    "학점",
    "한계",
    "한글",
    "한꺼번에",
    "한낮",
    "한눈",
    "한동안",
    "한때",
    "한라산",
    "한마디",
    "한문",
    "한번",
    "한복",
    "한식",
    "한여름",
    "한쪽",
    "할머니",
    "할아버지",
    "할인",
    "함께",
    "함부로",
    "합격",
    "합리적",
    "항공",
    "항구",
    "항상",
    "항의",
    "해결",
    "해군",
    "해답",
    "해당",
    "해물",
    "해석",
    "해설",
    "해수욕장",
    "해안",
    "핵심",
    "핸드백",
    "햄버거",
    "햇볕",
    "햇살",
    "행동",
    "행복",
    "행사",
    "행운",
    "행위",
    "향기",
    "향상",
    "향수",
    "허락",
    "허용",
    "헬기",
    "현관",
    "현금",
    "현대",
    "현상",
    "현실",
    "현장",
    "현재",
    "현지",
    "혈액",
    "협력",
    "형부",
    "형사",
    "형수",
    "형식",
    "형제",
    "형태",
    "형편",
    "혜택",
    "호기심",
    "호남",
    "호랑이",
    "호박",
    "호텔",
    "호흡",
    "혹시",
    "홀로",
    "홈페이지",
    "홍보",
    "홍수",
    "홍차",
    "화면",
    "화분",
    "화살",
    "화요일",
    "화장",
    "화학",
    "확보",
    "확인",
    "확장",
    "확정",
    "환갑",
    "환경",
    "환영",
    "환율",
    "환자",
    "활기",
    "활동",
    "활발히",
    "활용",
    "활짝",
    "회견",
    "회관",
    "회복",
    "회색",
    "회원",
    "회장",
    "회전",
    "횟수",
    "횡단보도",
    "효율적",
    "후반",
    "후춧가루",
    "훈련",
    "훨씬",
    "휴식",
    "휴일",
    "흉내",
    "흐름",
    "흑백",
    "흑인",
    "흔적",
    "흔히",
    "흥미",
    "흥분",
    "희곡",
    "희망",
    "희생",
    "흰색",
    "힘껏"
]

},{}],54:[function(require,module,exports){
module.exports=[
    "abacate",
    "abaixo",
    "abalar",
    "abater",
    "abduzir",
    "abelha",
    "aberto",
    "abismo",
    "abotoar",
    "abranger",
    "abreviar",
    "abrigar",
    "abrupto",
    "absinto",
    "absoluto",
    "absurdo",
    "abutre",
    "acabado",
    "acalmar",
    "acampar",
    "acanhar",
    "acaso",
    "aceitar",
    "acelerar",
    "acenar",
    "acervo",
    "acessar",
    "acetona",
    "achatar",
    "acidez",
    "acima",
    "acionado",
    "acirrar",
    "aclamar",
    "aclive",
    "acolhida",
    "acomodar",
    "acoplar",
    "acordar",
    "acumular",
    "acusador",
    "adaptar",
    "adega",
    "adentro",
    "adepto",
    "adequar",
    "aderente",
    "adesivo",
    "adeus",
    "adiante",
    "aditivo",
    "adjetivo",
    "adjunto",
    "admirar",
    "adorar",
    "adquirir",
    "adubo",
    "adverso",
    "advogado",
    "aeronave",
    "afastar",
    "aferir",
    "afetivo",
    "afinador",
    "afivelar",
    "aflito",
    "afluente",
    "afrontar",
    "agachar",
    "agarrar",
    "agasalho",
    "agenciar",
    "agilizar",
    "agiota",
    "agitado",
    "agora",
    "agradar",
    "agreste",
    "agrupar",
    "aguardar",
    "agulha",
    "ajoelhar",
    "ajudar",
    "ajustar",
    "alameda",
    "alarme",
    "alastrar",
    "alavanca",
    "albergue",
    "albino",
    "alcatra",
    "aldeia",
    "alecrim",
    "alegria",
    "alertar",
    "alface",
    "alfinete",
    "algum",
    "alheio",
    "aliar",
    "alicate",
    "alienar",
    "alinhar",
    "aliviar",
    "almofada",
    "alocar",
    "alpiste",
    "alterar",
    "altitude",
    "alucinar",
    "alugar",
    "aluno",
    "alusivo",
    "alvo",
    "amaciar",
    "amador",
    "amarelo",
    "amassar",
    "ambas",
    "ambiente",
    "ameixa",
    "amenizar",
    "amido",
    "amistoso",
    "amizade",
    "amolador",
    "amontoar",
    "amoroso",
    "amostra",
    "amparar",
    "ampliar",
    "ampola",
    "anagrama",
    "analisar",
    "anarquia",
    "anatomia",
    "andaime",
    "anel",
    "anexo",
    "angular",
    "animar",
    "anjo",
    "anomalia",
    "anotado",
    "ansioso",
    "anterior",
    "anuidade",
    "anunciar",
    "anzol",
    "apagador",
    "apalpar",
    "apanhado",
    "apego",
    "apelido",
    "apertada",
    "apesar",
    "apetite",
    "apito",
    "aplauso",
    "aplicada",
    "apoio",
    "apontar",
    "aposta",
    "aprendiz",
    "aprovar",
    "aquecer",
    "arame",
    "aranha",
    "arara",
    "arcada",
    "ardente",
    "areia",
    "arejar",
    "arenito",
    "aresta",
    "argiloso",
    "argola",
    "arma",
    "arquivo",
    "arraial",
    "arrebate",
    "arriscar",
    "arroba",
    "arrumar",
    "arsenal",
    "arterial",
    "artigo",
    "arvoredo",
    "asfaltar",
    "asilado",
    "aspirar",
    "assador",
    "assinar",
    "assoalho",
    "assunto",
    "astral",
    "atacado",
    "atadura",
    "atalho",
    "atarefar",
    "atear",
    "atender",
    "aterro",
    "ateu",
    "atingir",
    "atirador",
    "ativo",
    "atoleiro",
    "atracar",
    "atrevido",
    "atriz",
    "atual",
    "atum",
    "auditor",
    "aumentar",
    "aura",
    "aurora",
    "autismo",
    "autoria",
    "autuar",
    "avaliar",
    "avante",
    "avaria",
    "avental",
    "avesso",
    "aviador",
    "avisar",
    "avulso",
    "axila",
    "azarar",
    "azedo",
    "azeite",
    "azulejo",
    "babar",
    "babosa",
    "bacalhau",
    "bacharel",
    "bacia",
    "bagagem",
    "baiano",
    "bailar",
    "baioneta",
    "bairro",
    "baixista",
    "bajular",
    "baleia",
    "baliza",
    "balsa",
    "banal",
    "bandeira",
    "banho",
    "banir",
    "banquete",
    "barato",
    "barbado",
    "baronesa",
    "barraca",
    "barulho",
    "baseado",
    "bastante",
    "batata",
    "batedor",
    "batida",
    "batom",
    "batucar",
    "baunilha",
    "beber",
    "beijo",
    "beirada",
    "beisebol",
    "beldade",
    "beleza",
    "belga",
    "beliscar",
    "bendito",
    "bengala",
    "benzer",
    "berimbau",
    "berlinda",
    "berro",
    "besouro",
    "bexiga",
    "bezerro",
    "bico",
    "bicudo",
    "bienal",
    "bifocal",
    "bifurcar",
    "bigorna",
    "bilhete",
    "bimestre",
    "bimotor",
    "biologia",
    "biombo",
    "biosfera",
    "bipolar",
    "birrento",
    "biscoito",
    "bisneto",
    "bispo",
    "bissexto",
    "bitola",
    "bizarro",
    "blindado",
    "bloco",
    "bloquear",
    "boato",
    "bobagem",
    "bocado",
    "bocejo",
    "bochecha",
    "boicotar",
    "bolada",
    "boletim",
    "bolha",
    "bolo",
    "bombeiro",
    "bonde",
    "boneco",
    "bonita",
    "borbulha",
    "borda",
    "boreal",
    "borracha",
    "bovino",
    "boxeador",
    "branco",
    "brasa",
    "braveza",
    "breu",
    "briga",
    "brilho",
    "brincar",
    "broa",
    "brochura",
    "bronzear",
    "broto",
    "bruxo",
    "bucha",
    "budismo",
    "bufar",
    "bule",
    "buraco",
    "busca",
    "busto",
    "buzina",
    "cabana",
    "cabelo",
    "cabide",
    "cabo",
    "cabrito",
    "cacau",
    "cacetada",
    "cachorro",
    "cacique",
    "cadastro",
    "cadeado",
    "cafezal",
    "caiaque",
    "caipira",
    "caixote",
    "cajado",
    "caju",
    "calafrio",
    "calcular",
    "caldeira",
    "calibrar",
    "calmante",
    "calota",
    "camada",
    "cambista",
    "camisa",
    "camomila",
    "campanha",
    "camuflar",
    "canavial",
    "cancelar",
    "caneta",
    "canguru",
    "canhoto",
    "canivete",
    "canoa",
    "cansado",
    "cantar",
    "canudo",
    "capacho",
    "capela",
    "capinar",
    "capotar",
    "capricho",
    "captador",
    "capuz",
    "caracol",
    "carbono",
    "cardeal",
    "careca",
    "carimbar",
    "carneiro",
    "carpete",
    "carreira",
    "cartaz",
    "carvalho",
    "casaco",
    "casca",
    "casebre",
    "castelo",
    "casulo",
    "catarata",
    "cativar",
    "caule",
    "causador",
    "cautelar",
    "cavalo",
    "caverna",
    "cebola",
    "cedilha",
    "cegonha",
    "celebrar",
    "celular",
    "cenoura",
    "censo",
    "centeio",
    "cercar",
    "cerrado",
    "certeiro",
    "cerveja",
    "cetim",
    "cevada",
    "chacota",
    "chaleira",
    "chamado",
    "chapada",
    "charme",
    "chatice",
    "chave",
    "chefe",
    "chegada",
    "cheiro",
    "cheque",
    "chicote",
    "chifre",
    "chinelo",
    "chocalho",
    "chover",
    "chumbo",
    "chutar",
    "chuva",
    "cicatriz",
    "ciclone",
    "cidade",
    "cidreira",
    "ciente",
    "cigana",
    "cimento",
    "cinto",
    "cinza",
    "ciranda",
    "circuito",
    "cirurgia",
    "citar",
    "clareza",
    "clero",
    "clicar",
    "clone",
    "clube",
    "coado",
    "coagir",
    "cobaia",
    "cobertor",
    "cobrar",
    "cocada",
    "coelho",
    "coentro",
    "coeso",
    "cogumelo",
    "coibir",
    "coifa",
    "coiote",
    "colar",
    "coleira",
    "colher",
    "colidir",
    "colmeia",
    "colono",
    "coluna",
    "comando",
    "combinar",
    "comentar",
    "comitiva",
    "comover",
    "complexo",
    "comum",
    "concha",
    "condor",
    "conectar",
    "confuso",
    "congelar",
    "conhecer",
    "conjugar",
    "consumir",
    "contrato",
    "convite",
    "cooperar",
    "copeiro",
    "copiador",
    "copo",
    "coquetel",
    "coragem",
    "cordial",
    "corneta",
    "coronha",
    "corporal",
    "correio",
    "cortejo",
    "coruja",
    "corvo",
    "cosseno",
    "costela",
    "cotonete",
    "couro",
    "couve",
    "covil",
    "cozinha",
    "cratera",
    "cravo",
    "creche",
    "credor",
    "creme",
    "crer",
    "crespo",
    "criada",
    "criminal",
    "crioulo",
    "crise",
    "criticar",
    "crosta",
    "crua",
    "cruzeiro",
    "cubano",
    "cueca",
    "cuidado",
    "cujo",
    "culatra",
    "culminar",
    "culpar",
    "cultura",
    "cumprir",
    "cunhado",
    "cupido",
    "curativo",
    "curral",
    "cursar",
    "curto",
    "cuspir",
    "custear",
    "cutelo",
    "damasco",
    "datar",
    "debater",
    "debitar",
    "deboche",
    "debulhar",
    "decalque",
    "decimal",
    "declive",
    "decote",
    "decretar",
    "dedal",
    "dedicado",
    "deduzir",
    "defesa",
    "defumar",
    "degelo",
    "degrau",
    "degustar",
    "deitado",
    "deixar",
    "delator",
    "delegado",
    "delinear",
    "delonga",
    "demanda",
    "demitir",
    "demolido",
    "dentista",
    "depenado",
    "depilar",
    "depois",
    "depressa",
    "depurar",
    "deriva",
    "derramar",
    "desafio",
    "desbotar",
    "descanso",
    "desenho",
    "desfiado",
    "desgaste",
    "desigual",
    "deslize",
    "desmamar",
    "desova",
    "despesa",
    "destaque",
    "desviar",
    "detalhar",
    "detentor",
    "detonar",
    "detrito",
    "deusa",
    "dever",
    "devido",
    "devotado",
    "dezena",
    "diagrama",
    "dialeto",
    "didata",
    "difuso",
    "digitar",
    "dilatado",
    "diluente",
    "diminuir",
    "dinastia",
    "dinheiro",
    "diocese",
    "direto",
    "discreta",
    "disfarce",
    "disparo",
    "disquete",
    "dissipar",
    "distante",
    "ditador",
    "diurno",
    "diverso",
    "divisor",
    "divulgar",
    "dizer",
    "dobrador",
    "dolorido",
    "domador",
    "dominado",
    "donativo",
    "donzela",
    "dormente",
    "dorsal",
    "dosagem",
    "dourado",
    "doutor",
    "drenagem",
    "drible",
    "drogaria",
    "duelar",
    "duende",
    "dueto",
    "duplo",
    "duquesa",
    "durante",
    "duvidoso",
    "eclodir",
    "ecoar",
    "ecologia",
    "edificar",
    "edital",
    "educado",
    "efeito",
    "efetivar",
    "ejetar",
    "elaborar",
    "eleger",
    "eleitor",
    "elenco",
    "elevador",
    "eliminar",
    "elogiar",
    "embargo",
    "embolado",
    "embrulho",
    "embutido",
    "emenda",
    "emergir",
    "emissor",
    "empatia",
    "empenho",
    "empinado",
    "empolgar",
    "emprego",
    "empurrar",
    "emulador",
    "encaixe",
    "encenado",
    "enchente",
    "encontro",
    "endeusar",
    "endossar",
    "enfaixar",
    "enfeite",
    "enfim",
    "engajado",
    "engenho",
    "englobar",
    "engomado",
    "engraxar",
    "enguia",
    "enjoar",
    "enlatar",
    "enquanto",
    "enraizar",
    "enrolado",
    "enrugar",
    "ensaio",
    "enseada",
    "ensino",
    "ensopado",
    "entanto",
    "enteado",
    "entidade",
    "entortar",
    "entrada",
    "entulho",
    "envergar",
    "enviado",
    "envolver",
    "enxame",
    "enxerto",
    "enxofre",
    "enxuto",
    "epiderme",
    "equipar",
    "ereto",
    "erguido",
    "errata",
    "erva",
    "ervilha",
    "esbanjar",
    "esbelto",
    "escama",
    "escola",
    "escrita",
    "escuta",
    "esfinge",
    "esfolar",
    "esfregar",
    "esfumado",
    "esgrima",
    "esmalte",
    "espanto",
    "espelho",
    "espiga",
    "esponja",
    "espreita",
    "espumar",
    "esquerda",
    "estaca",
    "esteira",
    "esticar",
    "estofado",
    "estrela",
    "estudo",
    "esvaziar",
    "etanol",
    "etiqueta",
    "euforia",
    "europeu",
    "evacuar",
    "evaporar",
    "evasivo",
    "eventual",
    "evidente",
    "evoluir",
    "exagero",
    "exalar",
    "examinar",
    "exato",
    "exausto",
    "excesso",
    "excitar",
    "exclamar",
    "executar",
    "exemplo",
    "exibir",
    "exigente",
    "exonerar",
    "expandir",
    "expelir",
    "expirar",
    "explanar",
    "exposto",
    "expresso",
    "expulsar",
    "externo",
    "extinto",
    "extrato",
    "fabricar",
    "fabuloso",
    "faceta",
    "facial",
    "fada",
    "fadiga",
    "faixa",
    "falar",
    "falta",
    "familiar",
    "fandango",
    "fanfarra",
    "fantoche",
    "fardado",
    "farelo",
    "farinha",
    "farofa",
    "farpa",
    "fartura",
    "fatia",
    "fator",
    "favorita",
    "faxina",
    "fazenda",
    "fechado",
    "feijoada",
    "feirante",
    "felino",
    "feminino",
    "fenda",
    "feno",
    "fera",
    "feriado",
    "ferrugem",
    "ferver",
    "festejar",
    "fetal",
    "feudal",
    "fiapo",
    "fibrose",
    "ficar",
    "ficheiro",
    "figurado",
    "fileira",
    "filho",
    "filme",
    "filtrar",
    "firmeza",
    "fisgada",
    "fissura",
    "fita",
    "fivela",
    "fixador",
    "fixo",
    "flacidez",
    "flamingo",
    "flanela",
    "flechada",
    "flora",
    "flutuar",
    "fluxo",
    "focal",
    "focinho",
    "fofocar",
    "fogo",
    "foguete",
    "foice",
    "folgado",
    "folheto",
    "forjar",
    "formiga",
    "forno",
    "forte",
    "fosco",
    "fossa",
    "fragata",
    "fralda",
    "frango",
    "frasco",
    "fraterno",
    "freira",
    "frente",
    "fretar",
    "frieza",
    "friso",
    "fritura",
    "fronha",
    "frustrar",
    "fruteira",
    "fugir",
    "fulano",
    "fuligem",
    "fundar",
    "fungo",
    "funil",
    "furador",
    "furioso",
    "futebol",
    "gabarito",
    "gabinete",
    "gado",
    "gaiato",
    "gaiola",
    "gaivota",
    "galega",
    "galho",
    "galinha",
    "galocha",
    "ganhar",
    "garagem",
    "garfo",
    "gargalo",
    "garimpo",
    "garoupa",
    "garrafa",
    "gasoduto",
    "gasto",
    "gata",
    "gatilho",
    "gaveta",
    "gazela",
    "gelado",
    "geleia",
    "gelo",
    "gemada",
    "gemer",
    "gemido",
    "generoso",
    "gengiva",
    "genial",
    "genoma",
    "genro",
    "geologia",
    "gerador",
    "germinar",
    "gesso",
    "gestor",
    "ginasta",
    "gincana",
    "gingado",
    "girafa",
    "girino",
    "glacial",
    "glicose",
    "global",
    "glorioso",
    "goela",
    "goiaba",
    "golfe",
    "golpear",
    "gordura",
    "gorjeta",
    "gorro",
    "gostoso",
    "goteira",
    "governar",
    "gracejo",
    "gradual",
    "grafite",
    "gralha",
    "grampo",
    "granada",
    "gratuito",
    "graveto",
    "graxa",
    "grego",
    "grelhar",
    "greve",
    "grilo",
    "grisalho",
    "gritaria",
    "grosso",
    "grotesco",
    "grudado",
    "grunhido",
    "gruta",
    "guache",
    "guarani",
    "guaxinim",
    "guerrear",
    "guiar",
    "guincho",
    "guisado",
    "gula",
    "guloso",
    "guru",
    "habitar",
    "harmonia",
    "haste",
    "haver",
    "hectare",
    "herdar",
    "heresia",
    "hesitar",
    "hiato",
    "hibernar",
    "hidratar",
    "hiena",
    "hino",
    "hipismo",
    "hipnose",
    "hipoteca",
    "hoje",
    "holofote",
    "homem",
    "honesto",
    "honrado",
    "hormonal",
    "hospedar",
    "humorado",
    "iate",
    "ideia",
    "idoso",
    "ignorado",
    "igreja",
    "iguana",
    "ileso",
    "ilha",
    "iludido",
    "iluminar",
    "ilustrar",
    "imagem",
    "imediato",
    "imenso",
    "imersivo",
    "iminente",
    "imitador",
    "imortal",
    "impacto",
    "impedir",
    "implante",
    "impor",
    "imprensa",
    "impune",
    "imunizar",
    "inalador",
    "inapto",
    "inativo",
    "incenso",
    "inchar",
    "incidir",
    "incluir",
    "incolor",
    "indeciso",
    "indireto",
    "indutor",
    "ineficaz",
    "inerente",
    "infantil",
    "infestar",
    "infinito",
    "inflamar",
    "informal",
    "infrator",
    "ingerir",
    "inibido",
    "inicial",
    "inimigo",
    "injetar",
    "inocente",
    "inodoro",
    "inovador",
    "inox",
    "inquieto",
    "inscrito",
    "inseto",
    "insistir",
    "inspetor",
    "instalar",
    "insulto",
    "intacto",
    "integral",
    "intimar",
    "intocado",
    "intriga",
    "invasor",
    "inverno",
    "invicto",
    "invocar",
    "iogurte",
    "iraniano",
    "ironizar",
    "irreal",
    "irritado",
    "isca",
    "isento",
    "isolado",
    "isqueiro",
    "italiano",
    "janeiro",
    "jangada",
    "janta",
    "jararaca",
    "jardim",
    "jarro",
    "jasmim",
    "jato",
    "javali",
    "jazida",
    "jejum",
    "joaninha",
    "joelhada",
    "jogador",
    "joia",
    "jornal",
    "jorrar",
    "jovem",
    "juba",
    "judeu",
    "judoca",
    "juiz",
    "julgador",
    "julho",
    "jurado",
    "jurista",
    "juro",
    "justa",
    "labareda",
    "laboral",
    "lacre",
    "lactante",
    "ladrilho",
    "lagarta",
    "lagoa",
    "laje",
    "lamber",
    "lamentar",
    "laminar",
    "lampejo",
    "lanche",
    "lapidar",
    "lapso",
    "laranja",
    "lareira",
    "largura",
    "lasanha",
    "lastro",
    "lateral",
    "latido",
    "lavanda",
    "lavoura",
    "lavrador",
    "laxante",
    "lazer",
    "lealdade",
    "lebre",
    "legado",
    "legendar",
    "legista",
    "leigo",
    "leiloar",
    "leitura",
    "lembrete",
    "leme",
    "lenhador",
    "lentilha",
    "leoa",
    "lesma",
    "leste",
    "letivo",
    "letreiro",
    "levar",
    "leveza",
    "levitar",
    "liberal",
    "libido",
    "liderar",
    "ligar",
    "ligeiro",
    "limitar",
    "limoeiro",
    "limpador",
    "linda",
    "linear",
    "linhagem",
    "liquidez",
    "listagem",
    "lisura",
    "litoral",
    "livro",
    "lixa",
    "lixeira",
    "locador",
    "locutor",
    "lojista",
    "lombo",
    "lona",
    "longe",
    "lontra",
    "lorde",
    "lotado",
    "loteria",
    "loucura",
    "lousa",
    "louvar",
    "luar",
    "lucidez",
    "lucro",
    "luneta",
    "lustre",
    "lutador",
    "luva",
    "macaco",
    "macete",
    "machado",
    "macio",
    "madeira",
    "madrinha",
    "magnata",
    "magreza",
    "maior",
    "mais",
    "malandro",
    "malha",
    "malote",
    "maluco",
    "mamilo",
    "mamoeiro",
    "mamute",
    "manada",
    "mancha",
    "mandato",
    "manequim",
    "manhoso",
    "manivela",
    "manobrar",
    "mansa",
    "manter",
    "manusear",
    "mapeado",
    "maquinar",
    "marcador",
    "maresia",
    "marfim",
    "margem",
    "marinho",
    "marmita",
    "maroto",
    "marquise",
    "marreco",
    "martelo",
    "marujo",
    "mascote",
    "masmorra",
    "massagem",
    "mastigar",
    "matagal",
    "materno",
    "matinal",
    "matutar",
    "maxilar",
    "medalha",
    "medida",
    "medusa",
    "megafone",
    "meiga",
    "melancia",
    "melhor",
    "membro",
    "memorial",
    "menino",
    "menos",
    "mensagem",
    "mental",
    "merecer",
    "mergulho",
    "mesada",
    "mesclar",
    "mesmo",
    "mesquita",
    "mestre",
    "metade",
    "meteoro",
    "metragem",
    "mexer",
    "mexicano",
    "micro",
    "migalha",
    "migrar",
    "milagre",
    "milenar",
    "milhar",
    "mimado",
    "minerar",
    "minhoca",
    "ministro",
    "minoria",
    "miolo",
    "mirante",
    "mirtilo",
    "misturar",
    "mocidade",
    "moderno",
    "modular",
    "moeda",
    "moer",
    "moinho",
    "moita",
    "moldura",
    "moleza",
    "molho",
    "molinete",
    "molusco",
    "montanha",
    "moqueca",
    "morango",
    "morcego",
    "mordomo",
    "morena",
    "mosaico",
    "mosquete",
    "mostarda",
    "motel",
    "motim",
    "moto",
    "motriz",
    "muda",
    "muito",
    "mulata",
    "mulher",
    "multar",
    "mundial",
    "munido",
    "muralha",
    "murcho",
    "muscular",
    "museu",
    "musical",
    "nacional",
    "nadador",
    "naja",
    "namoro",
    "narina",
    "narrado",
    "nascer",
    "nativa",
    "natureza",
    "navalha",
    "navegar",
    "navio",
    "neblina",
    "nebuloso",
    "negativa",
    "negociar",
    "negrito",
    "nervoso",
    "neta",
    "neural",
    "nevasca",
    "nevoeiro",
    "ninar",
    "ninho",
    "nitidez",
    "nivelar",
    "nobreza",
    "noite",
    "noiva",
    "nomear",
    "nominal",
    "nordeste",
    "nortear",
    "notar",
    "noticiar",
    "noturno",
    "novelo",
    "novilho",
    "novo",
    "nublado",
    "nudez",
    "numeral",
    "nupcial",
    "nutrir",
    "nuvem",
    "obcecado",
    "obedecer",
    "objetivo",
    "obrigado",
    "obscuro",
    "obstetra",
    "obter",
    "obturar",
    "ocidente",
    "ocioso",
    "ocorrer",
    "oculista",
    "ocupado",
    "ofegante",
    "ofensiva",
    "oferenda",
    "oficina",
    "ofuscado",
    "ogiva",
    "olaria",
    "oleoso",
    "olhar",
    "oliveira",
    "ombro",
    "omelete",
    "omisso",
    "omitir",
    "ondulado",
    "oneroso",
    "ontem",
    "opcional",
    "operador",
    "oponente",
    "oportuno",
    "oposto",
    "orar",
    "orbitar",
    "ordem",
    "ordinal",
    "orfanato",
    "orgasmo",
    "orgulho",
    "oriental",
    "origem",
    "oriundo",
    "orla",
    "ortodoxo",
    "orvalho",
    "oscilar",
    "ossada",
    "osso",
    "ostentar",
    "otimismo",
    "ousadia",
    "outono",
    "outubro",
    "ouvido",
    "ovelha",
    "ovular",
    "oxidar",
    "oxigenar",
    "pacato",
    "paciente",
    "pacote",
    "pactuar",
    "padaria",
    "padrinho",
    "pagar",
    "pagode",
    "painel",
    "pairar",
    "paisagem",
    "palavra",
    "palestra",
    "palheta",
    "palito",
    "palmada",
    "palpitar",
    "pancada",
    "panela",
    "panfleto",
    "panqueca",
    "pantanal",
    "papagaio",
    "papelada",
    "papiro",
    "parafina",
    "parcial",
    "pardal",
    "parede",
    "partida",
    "pasmo",
    "passado",
    "pastel",
    "patamar",
    "patente",
    "patinar",
    "patrono",
    "paulada",
    "pausar",
    "peculiar",
    "pedalar",
    "pedestre",
    "pediatra",
    "pedra",
    "pegada",
    "peitoral",
    "peixe",
    "pele",
    "pelicano",
    "penca",
    "pendurar",
    "peneira",
    "penhasco",
    "pensador",
    "pente",
    "perceber",
    "perfeito",
    "pergunta",
    "perito",
    "permitir",
    "perna",
    "perplexo",
    "persiana",
    "pertence",
    "peruca",
    "pescado",
    "pesquisa",
    "pessoa",
    "petiscar",
    "piada",
    "picado",
    "piedade",
    "pigmento",
    "pilastra",
    "pilhado",
    "pilotar",
    "pimenta",
    "pincel",
    "pinguim",
    "pinha",
    "pinote",
    "pintar",
    "pioneiro",
    "pipoca",
    "piquete",
    "piranha",
    "pires",
    "pirueta",
    "piscar",
    "pistola",
    "pitanga",
    "pivete",
    "planta",
    "plaqueta",
    "platina",
    "plebeu",
    "plumagem",
    "pluvial",
    "pneu",
    "poda",
    "poeira",
    "poetisa",
    "polegada",
    "policiar",
    "poluente",
    "polvilho",
    "pomar",
    "pomba",
    "ponderar",
    "pontaria",
    "populoso",
    "porta",
    "possuir",
    "postal",
    "pote",
    "poupar",
    "pouso",
    "povoar",
    "praia",
    "prancha",
    "prato",
    "praxe",
    "prece",
    "predador",
    "prefeito",
    "premiar",
    "prensar",
    "preparar",
    "presilha",
    "pretexto",
    "prevenir",
    "prezar",
    "primata",
    "princesa",
    "prisma",
    "privado",
    "processo",
    "produto",
    "profeta",
    "proibido",
    "projeto",
    "prometer",
    "propagar",
    "prosa",
    "protetor",
    "provador",
    "publicar",
    "pudim",
    "pular",
    "pulmonar",
    "pulseira",
    "punhal",
    "punir",
    "pupilo",
    "pureza",
    "puxador",
    "quadra",
    "quantia",
    "quarto",
    "quase",
    "quebrar",
    "queda",
    "queijo",
    "quente",
    "querido",
    "quimono",
    "quina",
    "quiosque",
    "rabanada",
    "rabisco",
    "rachar",
    "racionar",
    "radial",
    "raiar",
    "rainha",
    "raio",
    "raiva",
    "rajada",
    "ralado",
    "ramal",
    "ranger",
    "ranhura",
    "rapadura",
    "rapel",
    "rapidez",
    "raposa",
    "raquete",
    "raridade",
    "rasante",
    "rascunho",
    "rasgar",
    "raspador",
    "rasteira",
    "rasurar",
    "ratazana",
    "ratoeira",
    "realeza",
    "reanimar",
    "reaver",
    "rebaixar",
    "rebelde",
    "rebolar",
    "recado",
    "recente",
    "recheio",
    "recibo",
    "recordar",
    "recrutar",
    "recuar",
    "rede",
    "redimir",
    "redonda",
    "reduzida",
    "reenvio",
    "refinar",
    "refletir",
    "refogar",
    "refresco",
    "refugiar",
    "regalia",
    "regime",
    "regra",
    "reinado",
    "reitor",
    "rejeitar",
    "relativo",
    "remador",
    "remendo",
    "remorso",
    "renovado",
    "reparo",
    "repelir",
    "repleto",
    "repolho",
    "represa",
    "repudiar",
    "requerer",
    "resenha",
    "resfriar",
    "resgatar",
    "residir",
    "resolver",
    "respeito",
    "ressaca",
    "restante",
    "resumir",
    "retalho",
    "reter",
    "retirar",
    "retomada",
    "retratar",
    "revelar",
    "revisor",
    "revolta",
    "riacho",
    "rica",
    "rigidez",
    "rigoroso",
    "rimar",
    "ringue",
    "risada",
    "risco",
    "risonho",
    "robalo",
    "rochedo",
    "rodada",
    "rodeio",
    "rodovia",
    "roedor",
    "roleta",
    "romano",
    "roncar",
    "rosado",
    "roseira",
    "rosto",
    "rota",
    "roteiro",
    "rotina",
    "rotular",
    "rouco",
    "roupa",
    "roxo",
    "rubro",
    "rugido",
    "rugoso",
    "ruivo",
    "rumo",
    "rupestre",
    "russo",
    "sabor",
    "saciar",
    "sacola",
    "sacudir",
    "sadio",
    "safira",
    "saga",
    "sagrada",
    "saibro",
    "salada",
    "saleiro",
    "salgado",
    "saliva",
    "salpicar",
    "salsicha",
    "saltar",
    "salvador",
    "sambar",
    "samurai",
    "sanar",
    "sanfona",
    "sangue",
    "sanidade",
    "sapato",
    "sarda",
    "sargento",
    "sarjeta",
    "saturar",
    "saudade",
    "saxofone",
    "sazonal",
    "secar",
    "secular",
    "seda",
    "sedento",
    "sediado",
    "sedoso",
    "sedutor",
    "segmento",
    "segredo",
    "segundo",
    "seiva",
    "seleto",
    "selvagem",
    "semanal",
    "semente",
    "senador",
    "senhor",
    "sensual",
    "sentado",
    "separado",
    "sereia",
    "seringa",
    "serra",
    "servo",
    "setembro",
    "setor",
    "sigilo",
    "silhueta",
    "silicone",
    "simetria",
    "simpatia",
    "simular",
    "sinal",
    "sincero",
    "singular",
    "sinopse",
    "sintonia",
    "sirene",
    "siri",
    "situado",
    "soberano",
    "sobra",
    "socorro",
    "sogro",
    "soja",
    "solda",
    "soletrar",
    "solteiro",
    "sombrio",
    "sonata",
    "sondar",
    "sonegar",
    "sonhador",
    "sono",
    "soprano",
    "soquete",
    "sorrir",
    "sorteio",
    "sossego",
    "sotaque",
    "soterrar",
    "sovado",
    "sozinho",
    "suavizar",
    "subida",
    "submerso",
    "subsolo",
    "subtrair",
    "sucata",
    "sucesso",
    "suco",
    "sudeste",
    "sufixo",
    "sugador",
    "sugerir",
    "sujeito",
    "sulfato",
    "sumir",
    "suor",
    "superior",
    "suplicar",
    "suposto",
    "suprimir",
    "surdina",
    "surfista",
    "surpresa",
    "surreal",
    "surtir",
    "suspiro",
    "sustento",
    "tabela",
    "tablete",
    "tabuada",
    "tacho",
    "tagarela",
    "talher",
    "talo",
    "talvez",
    "tamanho",
    "tamborim",
    "tampa",
    "tangente",
    "tanto",
    "tapar",
    "tapioca",
    "tardio",
    "tarefa",
    "tarja",
    "tarraxa",
    "tatuagem",
    "taurino",
    "taxativo",
    "taxista",
    "teatral",
    "tecer",
    "tecido",
    "teclado",
    "tedioso",
    "teia",
    "teimar",
    "telefone",
    "telhado",
    "tempero",
    "tenente",
    "tensor",
    "tentar",
    "termal",
    "terno",
    "terreno",
    "tese",
    "tesoura",
    "testado",
    "teto",
    "textura",
    "texugo",
    "tiara",
    "tigela",
    "tijolo",
    "timbrar",
    "timidez",
    "tingido",
    "tinteiro",
    "tiragem",
    "titular",
    "toalha",
    "tocha",
    "tolerar",
    "tolice",
    "tomada",
    "tomilho",
    "tonel",
    "tontura",
    "topete",
    "tora",
    "torcido",
    "torneio",
    "torque",
    "torrada",
    "torto",
    "tostar",
    "touca",
    "toupeira",
    "toxina",
    "trabalho",
    "tracejar",
    "tradutor",
    "trafegar",
    "trajeto",
    "trama",
    "trancar",
    "trapo",
    "traseiro",
    "tratador",
    "travar",
    "treino",
    "tremer",
    "trepidar",
    "trevo",
    "triagem",
    "tribo",
    "triciclo",
    "tridente",
    "trilogia",
    "trindade",
    "triplo",
    "triturar",
    "triunfal",
    "trocar",
    "trombeta",
    "trova",
    "trunfo",
    "truque",
    "tubular",
    "tucano",
    "tudo",
    "tulipa",
    "tupi",
    "turbo",
    "turma",
    "turquesa",
    "tutelar",
    "tutorial",
    "uivar",
    "umbigo",
    "unha",
    "unidade",
    "uniforme",
    "urologia",
    "urso",
    "urtiga",
    "urubu",
    "usado",
    "usina",
    "usufruir",
    "vacina",
    "vadiar",
    "vagaroso",
    "vaidoso",
    "vala",
    "valente",
    "validade",
    "valores",
    "vantagem",
    "vaqueiro",
    "varanda",
    "vareta",
    "varrer",
    "vascular",
    "vasilha",
    "vassoura",
    "vazar",
    "vazio",
    "veado",
    "vedar",
    "vegetar",
    "veicular",
    "veleiro",
    "velhice",
    "veludo",
    "vencedor",
    "vendaval",
    "venerar",
    "ventre",
    "verbal",
    "verdade",
    "vereador",
    "vergonha",
    "vermelho",
    "verniz",
    "versar",
    "vertente",
    "vespa",
    "vestido",
    "vetorial",
    "viaduto",
    "viagem",
    "viajar",
    "viatura",
    "vibrador",
    "videira",
    "vidraria",
    "viela",
    "viga",
    "vigente",
    "vigiar",
    "vigorar",
    "vilarejo",
    "vinco",
    "vinheta",
    "vinil",
    "violeta",
    "virada",
    "virtude",
    "visitar",
    "visto",
    "vitral",
    "viveiro",
    "vizinho",
    "voador",
    "voar",
    "vogal",
    "volante",
    "voleibol",
    "voltagem",
    "volumoso",
    "vontade",
    "vulto",
    "vuvuzela",
    "xadrez",
    "xarope",
    "xeque",
    "xeretar",
    "xerife",
    "xingar",
    "zangado",
    "zarpar",
    "zebu",
    "zelador",
    "zombar",
    "zoologia",
    "zumbido"
]

},{}],55:[function(require,module,exports){
module.exports=[
    "ábaco",
    "abdomen",
    "abeja",
    "abierto",
    "abogado",
    "abono",
    "aborto",
    "abrazo",
    "abrir",
    "abuelo",
    "abuso",
    "acabar",
    "academia",
    "acceso",
    "acción",
    "aceite",
    "acelga",
    "acento",
    "aceptar",
    "ácido",
    "aclarar",
    "acné",
    "acoger",
    "acoso",
    "activo",
    "acto",
    "actriz",
    "actuar",
    "acudir",
    "acuerdo",
    "acusar",
    "adicto",
    "admitir",
    "adoptar",
    "adorno",
    "aduana",
    "adulto",
    "aéreo",
    "afectar",
    "afición",
    "afinar",
    "afirmar",
    "ágil",
    "agitar",
    "agonía",
    "agosto",
    "agotar",
    "agregar",
    "agrio",
    "agua",
    "agudo",
    "águila",
    "aguja",
    "ahogo",
    "ahorro",
    "aire",
    "aislar",
    "ajedrez",
    "ajeno",
    "ajuste",
    "alacrán",
    "alambre",
    "alarma",
    "alba",
    "álbum",
    "alcalde",
    "aldea",
    "alegre",
    "alejar",
    "alerta",
    "aleta",
    "alfiler",
    "alga",
    "algodón",
    "aliado",
    "aliento",
    "alivio",
    "alma",
    "almeja",
    "almíbar",
    "altar",
    "alteza",
    "altivo",
    "alto",
    "altura",
    "alumno",
    "alzar",
    "amable",
    "amante",
    "amapola",
    "amargo",
    "amasar",
    "ámbar",
    "ámbito",
    "ameno",
    "amigo",
    "amistad",
    "amor",
    "amparo",
    "amplio",
    "ancho",
    "anciano",
    "ancla",
    "andar",
    "andén",
    "anemia",
    "ángulo",
    "anillo",
    "ánimo",
    "anís",
    "anotar",
    "antena",
    "antiguo",
    "antojo",
    "anual",
    "anular",
    "anuncio",
    "añadir",
    "añejo",
    "año",
    "apagar",
    "aparato",
    "apetito",
    "apio",
    "aplicar",
    "apodo",
    "aporte",
    "apoyo",
    "aprender",
    "aprobar",
    "apuesta",
    "apuro",
    "arado",
    "araña",
    "arar",
    "árbitro",
    "árbol",
    "arbusto",
    "archivo",
    "arco",
    "arder",
    "ardilla",
    "arduo",
    "área",
    "árido",
    "aries",
    "armonía",
    "arnés",
    "aroma",
    "arpa",
    "arpón",
    "arreglo",
    "arroz",
    "arruga",
    "arte",
    "artista",
    "asa",
    "asado",
    "asalto",
    "ascenso",
    "asegurar",
    "aseo",
    "asesor",
    "asiento",
    "asilo",
    "asistir",
    "asno",
    "asombro",
    "áspero",
    "astilla",
    "astro",
    "astuto",
    "asumir",
    "asunto",
    "atajo",
    "ataque",
    "atar",
    "atento",
    "ateo",
    "ático",
    "atleta",
    "átomo",
    "atraer",
    "atroz",
    "atún",
    "audaz",
    "audio",
    "auge",
    "aula",
    "aumento",
    "ausente",
    "autor",
    "aval",
    "avance",
    "avaro",
    "ave",
    "avellana",
    "avena",
    "avestruz",
    "avión",
    "aviso",
    "ayer",
    "ayuda",
    "ayuno",
    "azafrán",
    "azar",
    "azote",
    "azúcar",
    "azufre",
    "azul",
    "baba",
    "babor",
    "bache",
    "bahía",
    "baile",
    "bajar",
    "balanza",
    "balcón",
    "balde",
    "bambú",
    "banco",
    "banda",
    "baño",
    "barba",
    "barco",
    "barniz",
    "barro",
    "báscula",
    "bastón",
    "basura",
    "batalla",
    "batería",
    "batir",
    "batuta",
    "baúl",
    "bazar",
    "bebé",
    "bebida",
    "bello",
    "besar",
    "beso",
    "bestia",
    "bicho",
    "bien",
    "bingo",
    "blanco",
    "bloque",
    "blusa",
    "boa",
    "bobina",
    "bobo",
    "boca",
    "bocina",
    "boda",
    "bodega",
    "boina",
    "bola",
    "bolero",
    "bolsa",
    "bomba",
    "bondad",
    "bonito",
    "bono",
    "bonsái",
    "borde",
    "borrar",
    "bosque",
    "bote",
    "botín",
    "bóveda",
    "bozal",
    "bravo",
    "brazo",
    "brecha",
    "breve",
    "brillo",
    "brinco",
    "brisa",
    "broca",
    "broma",
    "bronce",
    "brote",
    "bruja",
    "brusco",
    "bruto",
    "buceo",
    "bucle",
    "bueno",
    "buey",
    "bufanda",
    "bufón",
    "búho",
    "buitre",
    "bulto",
    "burbuja",
    "burla",
    "burro",
    "buscar",
    "butaca",
    "buzón",
    "caballo",
    "cabeza",
    "cabina",
    "cabra",
    "cacao",
    "cadáver",
    "cadena",
    "caer",
    "café",
    "caída",
    "caimán",
    "caja",
    "cajón",
    "cal",
    "calamar",
    "calcio",
    "caldo",
    "calidad",
    "calle",
    "calma",
    "calor",
    "calvo",
    "cama",
    "cambio",
    "camello",
    "camino",
    "campo",
    "cáncer",
    "candil",
    "canela",
    "canguro",
    "canica",
    "canto",
    "caña",
    "cañón",
    "caoba",
    "caos",
    "capaz",
    "capitán",
    "capote",
    "captar",
    "capucha",
    "cara",
    "carbón",
    "cárcel",
    "careta",
    "carga",
    "cariño",
    "carne",
    "carpeta",
    "carro",
    "carta",
    "casa",
    "casco",
    "casero",
    "caspa",
    "castor",
    "catorce",
    "catre",
    "caudal",
    "causa",
    "cazo",
    "cebolla",
    "ceder",
    "cedro",
    "celda",
    "célebre",
    "celoso",
    "célula",
    "cemento",
    "ceniza",
    "centro",
    "cerca",
    "cerdo",
    "cereza",
    "cero",
    "cerrar",
    "certeza",
    "césped",
    "cetro",
    "chacal",
    "chaleco",
    "champú",
    "chancla",
    "chapa",
    "charla",
    "chico",
    "chiste",
    "chivo",
    "choque",
    "choza",
    "chuleta",
    "chupar",
    "ciclón",
    "ciego",
    "cielo",
    "cien",
    "cierto",
    "cifra",
    "cigarro",
    "cima",
    "cinco",
    "cine",
    "cinta",
    "ciprés",
    "circo",
    "ciruela",
    "cisne",
    "cita",
    "ciudad",
    "clamor",
    "clan",
    "claro",
    "clase",
    "clave",
    "cliente",
    "clima",
    "clínica",
    "cobre",
    "cocción",
    "cochino",
    "cocina",
    "coco",
    "código",
    "codo",
    "cofre",
    "coger",
    "cohete",
    "cojín",
    "cojo",
    "cola",
    "colcha",
    "colegio",
    "colgar",
    "colina",
    "collar",
    "colmo",
    "columna",
    "combate",
    "comer",
    "comida",
    "cómodo",
    "compra",
    "conde",
    "conejo",
    "conga",
    "conocer",
    "consejo",
    "contar",
    "copa",
    "copia",
    "corazón",
    "corbata",
    "corcho",
    "cordón",
    "corona",
    "correr",
    "coser",
    "cosmos",
    "costa",
    "cráneo",
    "cráter",
    "crear",
    "crecer",
    "creído",
    "crema",
    "cría",
    "crimen",
    "cripta",
    "crisis",
    "cromo",
    "crónica",
    "croqueta",
    "crudo",
    "cruz",
    "cuadro",
    "cuarto",
    "cuatro",
    "cubo",
    "cubrir",
    "cuchara",
    "cuello",
    "cuento",
    "cuerda",
    "cuesta",
    "cueva",
    "cuidar",
    "culebra",
    "culpa",
    "culto",
    "cumbre",
    "cumplir",
    "cuna",
    "cuneta",
    "cuota",
    "cupón",
    "cúpula",
    "curar",
    "curioso",
    "curso",
    "curva",
    "cutis",
    "dama",
    "danza",
    "dar",
    "dardo",
    "dátil",
    "deber",
    "débil",
    "década",
    "decir",
    "dedo",
    "defensa",
    "definir",
    "dejar",
    "delfín",
    "delgado",
    "delito",
    "demora",
    "denso",
    "dental",
    "deporte",
    "derecho",
    "derrota",
    "desayuno",
    "deseo",
    "desfile",
    "desnudo",
    "destino",
    "desvío",
    "detalle",
    "detener",
    "deuda",
    "día",
    "diablo",
    "diadema",
    "diamante",
    "diana",
    "diario",
    "dibujo",
    "dictar",
    "diente",
    "dieta",
    "diez",
    "difícil",
    "digno",
    "dilema",
    "diluir",
    "dinero",
    "directo",
    "dirigir",
    "disco",
    "diseño",
    "disfraz",
    "diva",
    "divino",
    "doble",
    "doce",
    "dolor",
    "domingo",
    "don",
    "donar",
    "dorado",
    "dormir",
    "dorso",
    "dos",
    "dosis",
    "dragón",
    "droga",
    "ducha",
    "duda",
    "duelo",
    "dueño",
    "dulce",
    "dúo",
    "duque",
    "durar",
    "dureza",
    "duro",
    "ébano",
    "ebrio",
    "echar",
    "eco",
    "ecuador",
    "edad",
    "edición",
    "edificio",
    "editor",
    "educar",
    "efecto",
    "eficaz",
    "eje",
    "ejemplo",
    "elefante",
    "elegir",
    "elemento",
    "elevar",
    "elipse",
    "élite",
    "elixir",
    "elogio",
    "eludir",
    "embudo",
    "emitir",
    "emoción",
    "empate",
    "empeño",
    "empleo",
    "empresa",
    "enano",
    "encargo",
    "enchufe",
    "encía",
    "enemigo",
    "enero",
    "enfado",
    "enfermo",
    "engaño",
    "enigma",
    "enlace",
    "enorme",
    "enredo",
    "ensayo",
    "enseñar",
    "entero",
    "entrar",
    "envase",
    "envío",
    "época",
    "equipo",
    "erizo",
    "escala",
    "escena",
    "escolar",
    "escribir",
    "escudo",
    "esencia",
    "esfera",
    "esfuerzo",
    "espada",
    "espejo",
    "espía",
    "esposa",
    "espuma",
    "esquí",
    "estar",
    "este",
    "estilo",
    "estufa",
    "etapa",
    "eterno",
    "ética",
    "etnia",
    "evadir",
    "evaluar",
    "evento",
    "evitar",
    "exacto",
    "examen",
    "exceso",
    "excusa",
    "exento",
    "exigir",
    "exilio",
    "existir",
    "éxito",
    "experto",
    "explicar",
    "exponer",
    "extremo",
    "fábrica",
    "fábula",
    "fachada",
    "fácil",
    "factor",
    "faena",
    "faja",
    "falda",
    "fallo",
    "falso",
    "faltar",
    "fama",
    "familia",
    "famoso",
    "faraón",
    "farmacia",
    "farol",
    "farsa",
    "fase",
    "fatiga",
    "fauna",
    "favor",
    "fax",
    "febrero",
    "fecha",
    "feliz",
    "feo",
    "feria",
    "feroz",
    "fértil",
    "fervor",
    "festín",
    "fiable",
    "fianza",
    "fiar",
    "fibra",
    "ficción",
    "ficha",
    "fideo",
    "fiebre",
    "fiel",
    "fiera",
    "fiesta",
    "figura",
    "fijar",
    "fijo",
    "fila",
    "filete",
    "filial",
    "filtro",
    "fin",
    "finca",
    "fingir",
    "finito",
    "firma",
    "flaco",
    "flauta",
    "flecha",
    "flor",
    "flota",
    "fluir",
    "flujo",
    "flúor",
    "fobia",
    "foca",
    "fogata",
    "fogón",
    "folio",
    "folleto",
    "fondo",
    "forma",
    "forro",
    "fortuna",
    "forzar",
    "fosa",
    "foto",
    "fracaso",
    "frágil",
    "franja",
    "frase",
    "fraude",
    "freír",
    "freno",
    "fresa",
    "frío",
    "frito",
    "fruta",
    "fuego",
    "fuente",
    "fuerza",
    "fuga",
    "fumar",
    "función",
    "funda",
    "furgón",
    "furia",
    "fusil",
    "fútbol",
    "futuro",
    "gacela",
    "gafas",
    "gaita",
    "gajo",
    "gala",
    "galería",
    "gallo",
    "gamba",
    "ganar",
    "gancho",
    "ganga",
    "ganso",
    "garaje",
    "garza",
    "gasolina",
    "gastar",
    "gato",
    "gavilán",
    "gemelo",
    "gemir",
    "gen",
    "género",
    "genio",
    "gente",
    "geranio",
    "gerente",
    "germen",
    "gesto",
    "gigante",
    "gimnasio",
    "girar",
    "giro",
    "glaciar",
    "globo",
    "gloria",
    "gol",
    "golfo",
    "goloso",
    "golpe",
    "goma",
    "gordo",
    "gorila",
    "gorra",
    "gota",
    "goteo",
    "gozar",
    "grada",
    "gráfico",
    "grano",
    "grasa",
    "gratis",
    "grave",
    "grieta",
    "grillo",
    "gripe",
    "gris",
    "grito",
    "grosor",
    "grúa",
    "grueso",
    "grumo",
    "grupo",
    "guante",
    "guapo",
    "guardia",
    "guerra",
    "guía",
    "guiño",
    "guion",
    "guiso",
    "guitarra",
    "gusano",
    "gustar",
    "haber",
    "hábil",
    "hablar",
    "hacer",
    "hacha",
    "hada",
    "hallar",
    "hamaca",
    "harina",
    "haz",
    "hazaña",
    "hebilla",
    "hebra",
    "hecho",
    "helado",
    "helio",
    "hembra",
    "herir",
    "hermano",
    "héroe",
    "hervir",
    "hielo",
    "hierro",
    "hígado",
    "higiene",
    "hijo",
    "himno",
    "historia",
    "hocico",
    "hogar",
    "hoguera",
    "hoja",
    "hombre",
    "hongo",
    "honor",
    "honra",
    "hora",
    "hormiga",
    "horno",
    "hostil",
    "hoyo",
    "hueco",
    "huelga",
    "huerta",
    "hueso",
    "huevo",
    "huida",
    "huir",
    "humano",
    "húmedo",
    "humilde",
    "humo",
    "hundir",
    "huracán",
    "hurto",
    "icono",
    "ideal",
    "idioma",
    "ídolo",
    "iglesia",
    "iglú",
    "igual",
    "ilegal",
    "ilusión",
    "imagen",
    "imán",
    "imitar",
    "impar",
    "imperio",
    "imponer",
    "impulso",
    "incapaz",
    "índice",
    "inerte",
    "infiel",
    "informe",
    "ingenio",
    "inicio",
    "inmenso",
    "inmune",
    "innato",
    "insecto",
    "instante",
    "interés",
    "íntimo",
    "intuir",
    "inútil",
    "invierno",
    "ira",
    "iris",
    "ironía",
    "isla",
    "islote",
    "jabalí",
    "jabón",
    "jamón",
    "jarabe",
    "jardín",
    "jarra",
    "jaula",
    "jazmín",
    "jefe",
    "jeringa",
    "jinete",
    "jornada",
    "joroba",
    "joven",
    "joya",
    "juerga",
    "jueves",
    "juez",
    "jugador",
    "jugo",
    "juguete",
    "juicio",
    "junco",
    "jungla",
    "junio",
    "juntar",
    "júpiter",
    "jurar",
    "justo",
    "juvenil",
    "juzgar",
    "kilo",
    "koala",
    "labio",
    "lacio",
    "lacra",
    "lado",
    "ladrón",
    "lagarto",
    "lágrima",
    "laguna",
    "laico",
    "lamer",
    "lámina",
    "lámpara",
    "lana",
    "lancha",
    "langosta",
    "lanza",
    "lápiz",
    "largo",
    "larva",
    "lástima",
    "lata",
    "látex",
    "latir",
    "laurel",
    "lavar",
    "lazo",
    "leal",
    "lección",
    "leche",
    "lector",
    "leer",
    "legión",
    "legumbre",
    "lejano",
    "lengua",
    "lento",
    "leña",
    "león",
    "leopardo",
    "lesión",
    "letal",
    "letra",
    "leve",
    "leyenda",
    "libertad",
    "libro",
    "licor",
    "líder",
    "lidiar",
    "lienzo",
    "liga",
    "ligero",
    "lima",
    "límite",
    "limón",
    "limpio",
    "lince",
    "lindo",
    "línea",
    "lingote",
    "lino",
    "linterna",
    "líquido",
    "liso",
    "lista",
    "litera",
    "litio",
    "litro",
    "llaga",
    "llama",
    "llanto",
    "llave",
    "llegar",
    "llenar",
    "llevar",
    "llorar",
    "llover",
    "lluvia",
    "lobo",
    "loción",
    "loco",
    "locura",
    "lógica",
    "logro",
    "lombriz",
    "lomo",
    "lonja",
    "lote",
    "lucha",
    "lucir",
    "lugar",
    "lujo",
    "luna",
    "lunes",
    "lupa",
    "lustro",
    "luto",
    "luz",
    "maceta",
    "macho",
    "madera",
    "madre",
    "maduro",
    "maestro",
    "mafia",
    "magia",
    "mago",
    "maíz",
    "maldad",
    "maleta",
    "malla",
    "malo",
    "mamá",
    "mambo",
    "mamut",
    "manco",
    "mando",
    "manejar",
    "manga",
    "maniquí",
    "manjar",
    "mano",
    "manso",
    "manta",
    "mañana",
    "mapa",
    "máquina",
    "mar",
    "marco",
    "marea",
    "marfil",
    "margen",
    "marido",
    "mármol",
    "marrón",
    "martes",
    "marzo",
    "masa",
    "máscara",
    "masivo",
    "matar",
    "materia",
    "matiz",
    "matriz",
    "máximo",
    "mayor",
    "mazorca",
    "mecha",
    "medalla",
    "medio",
    "médula",
    "mejilla",
    "mejor",
    "melena",
    "melón",
    "memoria",
    "menor",
    "mensaje",
    "mente",
    "menú",
    "mercado",
    "merengue",
    "mérito",
    "mes",
    "mesón",
    "meta",
    "meter",
    "método",
    "metro",
    "mezcla",
    "miedo",
    "miel",
    "miembro",
    "miga",
    "mil",
    "milagro",
    "militar",
    "millón",
    "mimo",
    "mina",
    "minero",
    "mínimo",
    "minuto",
    "miope",
    "mirar",
    "misa",
    "miseria",
    "misil",
    "mismo",
    "mitad",
    "mito",
    "mochila",
    "moción",
    "moda",
    "modelo",
    "moho",
    "mojar",
    "molde",
    "moler",
    "molino",
    "momento",
    "momia",
    "monarca",
    "moneda",
    "monja",
    "monto",
    "moño",
    "morada",
    "morder",
    "moreno",
    "morir",
    "morro",
    "morsa",
    "mortal",
    "mosca",
    "mostrar",
    "motivo",
    "mover",
    "móvil",
    "mozo",
    "mucho",
    "mudar",
    "mueble",
    "muela",
    "muerte",
    "muestra",
    "mugre",
    "mujer",
    "mula",
    "muleta",
    "multa",
    "mundo",
    "muñeca",
    "mural",
    "muro",
    "músculo",
    "museo",
    "musgo",
    "música",
    "muslo",
    "nácar",
    "nación",
    "nadar",
    "naipe",
    "naranja",
    "nariz",
    "narrar",
    "nasal",
    "natal",
    "nativo",
    "natural",
    "náusea",
    "naval",
    "nave",
    "navidad",
    "necio",
    "néctar",
    "negar",
    "negocio",
    "negro",
    "neón",
    "nervio",
    "neto",
    "neutro",
    "nevar",
    "nevera",
    "nicho",
    "nido",
    "niebla",
    "nieto",
    "niñez",
    "niño",
    "nítido",
    "nivel",
    "nobleza",
    "noche",
    "nómina",
    "noria",
    "norma",
    "norte",
    "nota",
    "noticia",
    "novato",
    "novela",
    "novio",
    "nube",
    "nuca",
    "núcleo",
    "nudillo",
    "nudo",
    "nuera",
    "nueve",
    "nuez",
    "nulo",
    "número",
    "nutria",
    "oasis",
    "obeso",
    "obispo",
    "objeto",
    "obra",
    "obrero",
    "observar",
    "obtener",
    "obvio",
    "oca",
    "ocaso",
    "océano",
    "ochenta",
    "ocho",
    "ocio",
    "ocre",
    "octavo",
    "octubre",
    "oculto",
    "ocupar",
    "ocurrir",
    "odiar",
    "odio",
    "odisea",
    "oeste",
    "ofensa",
    "oferta",
    "oficio",
    "ofrecer",
    "ogro",
    "oído",
    "oír",
    "ojo",
    "ola",
    "oleada",
    "olfato",
    "olivo",
    "olla",
    "olmo",
    "olor",
    "olvido",
    "ombligo",
    "onda",
    "onza",
    "opaco",
    "opción",
    "ópera",
    "opinar",
    "oponer",
    "optar",
    "óptica",
    "opuesto",
    "oración",
    "orador",
    "oral",
    "órbita",
    "orca",
    "orden",
    "oreja",
    "órgano",
    "orgía",
    "orgullo",
    "oriente",
    "origen",
    "orilla",
    "oro",
    "orquesta",
    "oruga",
    "osadía",
    "oscuro",
    "osezno",
    "oso",
    "ostra",
    "otoño",
    "otro",
    "oveja",
    "óvulo",
    "óxido",
    "oxígeno",
    "oyente",
    "ozono",
    "pacto",
    "padre",
    "paella",
    "página",
    "pago",
    "país",
    "pájaro",
    "palabra",
    "palco",
    "paleta",
    "pálido",
    "palma",
    "paloma",
    "palpar",
    "pan",
    "panal",
    "pánico",
    "pantera",
    "pañuelo",
    "papá",
    "papel",
    "papilla",
    "paquete",
    "parar",
    "parcela",
    "pared",
    "parir",
    "paro",
    "párpado",
    "parque",
    "párrafo",
    "parte",
    "pasar",
    "paseo",
    "pasión",
    "paso",
    "pasta",
    "pata",
    "patio",
    "patria",
    "pausa",
    "pauta",
    "pavo",
    "payaso",
    "peatón",
    "pecado",
    "pecera",
    "pecho",
    "pedal",
    "pedir",
    "pegar",
    "peine",
    "pelar",
    "peldaño",
    "pelea",
    "peligro",
    "pellejo",
    "pelo",
    "peluca",
    "pena",
    "pensar",
    "peñón",
    "peón",
    "peor",
    "pepino",
    "pequeño",
    "pera",
    "percha",
    "perder",
    "pereza",
    "perfil",
    "perico",
    "perla",
    "permiso",
    "perro",
    "persona",
    "pesa",
    "pesca",
    "pésimo",
    "pestaña",
    "pétalo",
    "petróleo",
    "pez",
    "pezuña",
    "picar",
    "pichón",
    "pie",
    "piedra",
    "pierna",
    "pieza",
    "pijama",
    "pilar",
    "piloto",
    "pimienta",
    "pino",
    "pintor",
    "pinza",
    "piña",
    "piojo",
    "pipa",
    "pirata",
    "pisar",
    "piscina",
    "piso",
    "pista",
    "pitón",
    "pizca",
    "placa",
    "plan",
    "plata",
    "playa",
    "plaza",
    "pleito",
    "pleno",
    "plomo",
    "pluma",
    "plural",
    "pobre",
    "poco",
    "poder",
    "podio",
    "poema",
    "poesía",
    "poeta",
    "polen",
    "policía",
    "pollo",
    "polvo",
    "pomada",
    "pomelo",
    "pomo",
    "pompa",
    "poner",
    "porción",
    "portal",
    "posada",
    "poseer",
    "posible",
    "poste",
    "potencia",
    "potro",
    "pozo",
    "prado",
    "precoz",
    "pregunta",
    "premio",
    "prensa",
    "preso",
    "previo",
    "primo",
    "príncipe",
    "prisión",
    "privar",
    "proa",
    "probar",
    "proceso",
    "producto",
    "proeza",
    "profesor",
    "programa",
    "prole",
    "promesa",
    "pronto",
    "propio",
    "próximo",
    "prueba",
    "público",
    "puchero",
    "pudor",
    "pueblo",
    "puerta",
    "puesto",
    "pulga",
    "pulir",
    "pulmón",
    "pulpo",
    "pulso",
    "puma",
    "punto",
    "puñal",
    "puño",
    "pupa",
    "pupila",
    "puré",
    "quedar",
    "queja",
    "quemar",
    "querer",
    "queso",
    "quieto",
    "química",
    "quince",
    "quitar",
    "rábano",
    "rabia",
    "rabo",
    "ración",
    "radical",
    "raíz",
    "rama",
    "rampa",
    "rancho",
    "rango",
    "rapaz",
    "rápido",
    "rapto",
    "rasgo",
    "raspa",
    "rato",
    "rayo",
    "raza",
    "razón",
    "reacción",
    "realidad",
    "rebaño",
    "rebote",
    "recaer",
    "receta",
    "rechazo",
    "recoger",
    "recreo",
    "recto",
    "recurso",
    "red",
    "redondo",
    "reducir",
    "reflejo",
    "reforma",
    "refrán",
    "refugio",
    "regalo",
    "regir",
    "regla",
    "regreso",
    "rehén",
    "reino",
    "reír",
    "reja",
    "relato",
    "relevo",
    "relieve",
    "relleno",
    "reloj",
    "remar",
    "remedio",
    "remo",
    "rencor",
    "rendir",
    "renta",
    "reparto",
    "repetir",
    "reposo",
    "reptil",
    "res",
    "rescate",
    "resina",
    "respeto",
    "resto",
    "resumen",
    "retiro",
    "retorno",
    "retrato",
    "reunir",
    "revés",
    "revista",
    "rey",
    "rezar",
    "rico",
    "riego",
    "rienda",
    "riesgo",
    "rifa",
    "rígido",
    "rigor",
    "rincón",
    "riñón",
    "río",
    "riqueza",
    "risa",
    "ritmo",
    "rito",
    "rizo",
    "roble",
    "roce",
    "rociar",
    "rodar",
    "rodeo",
    "rodilla",
    "roer",
    "rojizo",
    "rojo",
    "romero",
    "romper",
    "ron",
    "ronco",
    "ronda",
    "ropa",
    "ropero",
    "rosa",
    "rosca",
    "rostro",
    "rotar",
    "rubí",
    "rubor",
    "rudo",
    "rueda",
    "rugir",
    "ruido",
    "ruina",
    "ruleta",
    "rulo",
    "rumbo",
    "rumor",
    "ruptura",
    "ruta",
    "rutina",
    "sábado",
    "saber",
    "sabio",
    "sable",
    "sacar",
    "sagaz",
    "sagrado",
    "sala",
    "saldo",
    "salero",
    "salir",
    "salmón",
    "salón",
    "salsa",
    "salto",
    "salud",
    "salvar",
    "samba",
    "sanción",
    "sandía",
    "sanear",
    "sangre",
    "sanidad",
    "sano",
    "santo",
    "sapo",
    "saque",
    "sardina",
    "sartén",
    "sastre",
    "satán",
    "sauna",
    "saxofón",
    "sección",
    "seco",
    "secreto",
    "secta",
    "sed",
    "seguir",
    "seis",
    "sello",
    "selva",
    "semana",
    "semilla",
    "senda",
    "sensor",
    "señal",
    "señor",
    "separar",
    "sepia",
    "sequía",
    "ser",
    "serie",
    "sermón",
    "servir",
    "sesenta",
    "sesión",
    "seta",
    "setenta",
    "severo",
    "sexo",
    "sexto",
    "sidra",
    "siesta",
    "siete",
    "siglo",
    "signo",
    "sílaba",
    "silbar",
    "silencio",
    "silla",
    "símbolo",
    "simio",
    "sirena",
    "sistema",
    "sitio",
    "situar",
    "sobre",
    "socio",
    "sodio",
    "sol",
    "solapa",
    "soldado",
    "soledad",
    "sólido",
    "soltar",
    "solución",
    "sombra",
    "sondeo",
    "sonido",
    "sonoro",
    "sonrisa",
    "sopa",
    "soplar",
    "soporte",
    "sordo",
    "sorpresa",
    "sorteo",
    "sostén",
    "sótano",
    "suave",
    "subir",
    "suceso",
    "sudor",
    "suegra",
    "suelo",
    "sueño",
    "suerte",
    "sufrir",
    "sujeto",
    "sultán",
    "sumar",
    "superar",
    "suplir",
    "suponer",
    "supremo",
    "sur",
    "surco",
    "sureño",
    "surgir",
    "susto",
    "sutil",
    "tabaco",
    "tabique",
    "tabla",
    "tabú",
    "taco",
    "tacto",
    "tajo",
    "talar",
    "talco",
    "talento",
    "talla",
    "talón",
    "tamaño",
    "tambor",
    "tango",
    "tanque",
    "tapa",
    "tapete",
    "tapia",
    "tapón",
    "taquilla",
    "tarde",
    "tarea",
    "tarifa",
    "tarjeta",
    "tarot",
    "tarro",
    "tarta",
    "tatuaje",
    "tauro",
    "taza",
    "tazón",
    "teatro",
    "techo",
    "tecla",
    "técnica",
    "tejado",
    "tejer",
    "tejido",
    "tela",
    "teléfono",
    "tema",
    "temor",
    "templo",
    "tenaz",
    "tender",
    "tener",
    "tenis",
    "tenso",
    "teoría",
    "terapia",
    "terco",
    "término",
    "ternura",
    "terror",
    "tesis",
    "tesoro",
    "testigo",
    "tetera",
    "texto",
    "tez",
    "tibio",
    "tiburón",
    "tiempo",
    "tienda",
    "tierra",
    "tieso",
    "tigre",
    "tijera",
    "tilde",
    "timbre",
    "tímido",
    "timo",
    "tinta",
    "tío",
    "típico",
    "tipo",
    "tira",
    "tirón",
    "titán",
    "títere",
    "título",
    "tiza",
    "toalla",
    "tobillo",
    "tocar",
    "tocino",
    "todo",
    "toga",
    "toldo",
    "tomar",
    "tono",
    "tonto",
    "topar",
    "tope",
    "toque",
    "tórax",
    "torero",
    "tormenta",
    "torneo",
    "toro",
    "torpedo",
    "torre",
    "torso",
    "tortuga",
    "tos",
    "tosco",
    "toser",
    "tóxico",
    "trabajo",
    "tractor",
    "traer",
    "tráfico",
    "trago",
    "traje",
    "tramo",
    "trance",
    "trato",
    "trauma",
    "trazar",
    "trébol",
    "tregua",
    "treinta",
    "tren",
    "trepar",
    "tres",
    "tribu",
    "trigo",
    "tripa",
    "triste",
    "triunfo",
    "trofeo",
    "trompa",
    "tronco",
    "tropa",
    "trote",
    "trozo",
    "truco",
    "trueno",
    "trufa",
    "tubería",
    "tubo",
    "tuerto",
    "tumba",
    "tumor",
    "túnel",
    "túnica",
    "turbina",
    "turismo",
    "turno",
    "tutor",
    "ubicar",
    "úlcera",
    "umbral",
    "unidad",
    "unir",
    "universo",
    "uno",
    "untar",
    "uña",
    "urbano",
    "urbe",
    "urgente",
    "urna",
    "usar",
    "usuario",
    "útil",
    "utopía",
    "uva",
    "vaca",
    "vacío",
    "vacuna",
    "vagar",
    "vago",
    "vaina",
    "vajilla",
    "vale",
    "válido",
    "valle",
    "valor",
    "válvula",
    "vampiro",
    "vara",
    "variar",
    "varón",
    "vaso",
    "vecino",
    "vector",
    "vehículo",
    "veinte",
    "vejez",
    "vela",
    "velero",
    "veloz",
    "vena",
    "vencer",
    "venda",
    "veneno",
    "vengar",
    "venir",
    "venta",
    "venus",
    "ver",
    "verano",
    "verbo",
    "verde",
    "vereda",
    "verja",
    "verso",
    "verter",
    "vía",
    "viaje",
    "vibrar",
    "vicio",
    "víctima",
    "vida",
    "vídeo",
    "vidrio",
    "viejo",
    "viernes",
    "vigor",
    "vil",
    "villa",
    "vinagre",
    "vino",
    "viñedo",
    "violín",
    "viral",
    "virgo",
    "virtud",
    "visor",
    "víspera",
    "vista",
    "vitamina",
    "viudo",
    "vivaz",
    "vivero",
    "vivir",
    "vivo",
    "volcán",
    "volumen",
    "volver",
    "voraz",
    "votar",
    "voto",
    "voz",
    "vuelo",
    "vulgar",
    "yacer",
    "yate",
    "yegua",
    "yema",
    "yerno",
    "yeso",
    "yodo",
    "yoga",
    "yogur",
    "zafiro",
    "zanja",
    "zapato",
    "zarza",
    "zona",
    "zorro",
    "zumo",
    "zurdo"
]

},{}],56:[function(require,module,exports){
'use strict'
// base-x encoding / decoding
// Copyright (c) 2018 base-x contributors
// Copyright (c) 2014-2018 The Bitcoin Core developers (base58.cpp)
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
function base (ALPHABET) {
  if (ALPHABET.length >= 255) { throw new TypeError('Alphabet too long') }
  var BASE_MAP = new Uint8Array(256)
  for (var j = 0; j < BASE_MAP.length; j++) {
    BASE_MAP[j] = 255
  }
  for (var i = 0; i < ALPHABET.length; i++) {
    var x = ALPHABET.charAt(i)
    var xc = x.charCodeAt(0)
    if (BASE_MAP[xc] !== 255) { throw new TypeError(x + ' is ambiguous') }
    BASE_MAP[xc] = i
  }
  var BASE = ALPHABET.length
  var LEADER = ALPHABET.charAt(0)
  var FACTOR = Math.log(BASE) / Math.log(256) // log(BASE) / log(256), rounded up
  var iFACTOR = Math.log(256) / Math.log(BASE) // log(256) / log(BASE), rounded up
  function encode (source) {
    if (source instanceof Uint8Array) {
    } else if (ArrayBuffer.isView(source)) {
      source = new Uint8Array(source.buffer, source.byteOffset, source.byteLength)
    } else if (Array.isArray(source)) {
      source = Uint8Array.from(source)
    }
    if (!(source instanceof Uint8Array)) { throw new TypeError('Expected Uint8Array') }
    if (source.length === 0) { return '' }
        // Skip & count leading zeroes.
    var zeroes = 0
    var length = 0
    var pbegin = 0
    var pend = source.length
    while (pbegin !== pend && source[pbegin] === 0) {
      pbegin++
      zeroes++
    }
        // Allocate enough space in big-endian base58 representation.
    var size = ((pend - pbegin) * iFACTOR + 1) >>> 0
    var b58 = new Uint8Array(size)
        // Process the bytes.
    while (pbegin !== pend) {
      var carry = source[pbegin]
            // Apply "b58 = b58 * 256 + ch".
      var i = 0
      for (var it1 = size - 1; (carry !== 0 || i < length) && (it1 !== -1); it1--, i++) {
        carry += (256 * b58[it1]) >>> 0
        b58[it1] = (carry % BASE) >>> 0
        carry = (carry / BASE) >>> 0
      }
      if (carry !== 0) { throw new Error('Non-zero carry') }
      length = i
      pbegin++
    }
        // Skip leading zeroes in base58 result.
    var it2 = size - length
    while (it2 !== size && b58[it2] === 0) {
      it2++
    }
        // Translate the result into a string.
    var str = LEADER.repeat(zeroes)
    for (; it2 < size; ++it2) { str += ALPHABET.charAt(b58[it2]) }
    return str
  }
  function decodeUnsafe (source) {
    if (typeof source !== 'string') { throw new TypeError('Expected String') }
    if (source.length === 0) { return new Uint8Array() }
    var psz = 0
        // Skip and count leading '1's.
    var zeroes = 0
    var length = 0
    while (source[psz] === LEADER) {
      zeroes++
      psz++
    }
        // Allocate enough space in big-endian base256 representation.
    var size = (((source.length - psz) * FACTOR) + 1) >>> 0 // log(58) / log(256), rounded up.
    var b256 = new Uint8Array(size)
        // Process the characters.
    while (source[psz]) {
            // Decode character
      var carry = BASE_MAP[source.charCodeAt(psz)]
            // Invalid character
      if (carry === 255) { return }
      var i = 0
      for (var it3 = size - 1; (carry !== 0 || i < length) && (it3 !== -1); it3--, i++) {
        carry += (BASE * b256[it3]) >>> 0
        b256[it3] = (carry % 256) >>> 0
        carry = (carry / 256) >>> 0
      }
      if (carry !== 0) { throw new Error('Non-zero carry') }
      length = i
      psz++
    }
        // Skip leading zeroes in b256.
    var it4 = size - length
    while (it4 !== size && b256[it4] === 0) {
      it4++
    }
    var vch = new Uint8Array(zeroes + (size - it4))
    var j = zeroes
    while (it4 !== size) {
      vch[j++] = b256[it4++]
    }
    return vch
  }
  function decode (string) {
    var buffer = decodeUnsafe(string)
    if (buffer) { return buffer }
    throw new Error('Non-base' + BASE + ' character')
  }
  return {
    encode: encode,
    decodeUnsafe: decodeUnsafe,
    decode: decode
  }
}
module.exports = base

},{}],57:[function(require,module,exports){
const basex = require('base-x')
const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

module.exports = basex(ALPHABET)

},{"base-x":56}],58:[function(require,module,exports){
'use strict'

var base58 = require('bs58')

module.exports = function (checksumFn) {
  // Encode a buffer as a base58-check encoded string
  function encode (payload) {
    var payloadU8 = Uint8Array.from(payload)
    var checksum = checksumFn(payloadU8)
    var length = payloadU8.length + 4
    var both = new Uint8Array(length)
    both.set(payloadU8, 0)
    both.set(checksum.subarray(0, 4), payloadU8.length)
    return base58.encode(both, length)
  }

  function decodeRaw (buffer) {
    var payload = buffer.slice(0, -4)
    var checksum = buffer.slice(-4)
    var newChecksum = checksumFn(payload)

    if (checksum[0] ^ newChecksum[0] |
        checksum[1] ^ newChecksum[1] |
        checksum[2] ^ newChecksum[2] |
        checksum[3] ^ newChecksum[3]) return

    return payload
  }

  // Decode a base58-check encoded string to a buffer, no result if checksum is wrong
  function decodeUnsafe (string) {
    var buffer = base58.decodeUnsafe(string)
    if (!buffer) return

    return decodeRaw(buffer)
  }

  function decode (string) {
    var buffer = base58.decode(string)
    var payload = decodeRaw(buffer, checksumFn)
    if (!payload) throw new Error('Invalid checksum')
    return payload
  }

  return {
    encode: encode,
    decode: decode,
    decodeUnsafe: decodeUnsafe
  }
}

},{"bs58":57}],59:[function(require,module,exports){
'use strict'

var { sha256 } = require('@noble/hashes/sha256')
var bs58checkBase = require('./base')

// SHA256(SHA256(buffer))
function sha256x2 (buffer) {
  return sha256(sha256(buffer))
}

module.exports = bs58checkBase(sha256x2)

},{"./base":58,"@noble/hashes/sha256":10}],60:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.toOutputScript =
  exports.fromOutputScript =
  exports.toBech32 =
  exports.toBase58Check =
  exports.fromBech32 =
  exports.fromBase58Check =
    void 0;
const networks = require('./networks');
const payments = require('./payments');
const bscript = require('./script');
const types_1 = require('./types');
const bech32_1 = require('bech32');
const bs58check = require('bs58check');
const FUTURE_SEGWIT_MAX_SIZE = 40;
const FUTURE_SEGWIT_MIN_SIZE = 2;
const FUTURE_SEGWIT_MAX_VERSION = 16;
const FUTURE_SEGWIT_MIN_VERSION = 2;
const FUTURE_SEGWIT_VERSION_DIFF = 0x50;
const FUTURE_SEGWIT_VERSION_WARNING =
  'WARNING: Sending to a future segwit version address can lead to loss of funds. ' +
  'End users MUST be warned carefully in the GUI and asked if they wish to proceed ' +
  'with caution. Wallets should verify the segwit version from the output of fromBech32, ' +
  'then decide when it is safe to use which version of segwit.';
function _toFutureSegwitAddress(output, network) {
  const data = output.slice(2);
  if (
    data.length < FUTURE_SEGWIT_MIN_SIZE ||
    data.length > FUTURE_SEGWIT_MAX_SIZE
  )
    throw new TypeError('Invalid program length for segwit address');
  const version = output[0] - FUTURE_SEGWIT_VERSION_DIFF;
  if (
    version < FUTURE_SEGWIT_MIN_VERSION ||
    version > FUTURE_SEGWIT_MAX_VERSION
  )
    throw new TypeError('Invalid version for segwit address');
  if (output[1] !== data.length)
    throw new TypeError('Invalid script for segwit address');
  console.warn(FUTURE_SEGWIT_VERSION_WARNING);
  return toBech32(data, version, network.bech32);
}
function fromBase58Check(address) {
  const payload = Buffer.from(bs58check.decode(address));
  // TODO: 4.0.0, move to "toOutputScript"
  if (payload.length < 21) throw new TypeError(address + ' is too short');
  if (payload.length > 21) throw new TypeError(address + ' is too long');
  const version = payload.readUInt8(0);
  const hash = payload.slice(1);
  return { version, hash };
}
exports.fromBase58Check = fromBase58Check;
function fromBech32(address) {
  let result;
  let version;
  try {
    result = bech32_1.bech32.decode(address);
  } catch (e) {}
  if (result) {
    version = result.words[0];
    if (version !== 0) throw new TypeError(address + ' uses wrong encoding');
  } else {
    result = bech32_1.bech32m.decode(address);
    version = result.words[0];
    if (version === 0) throw new TypeError(address + ' uses wrong encoding');
  }
  const data = bech32_1.bech32.fromWords(result.words.slice(1));
  return {
    version,
    prefix: result.prefix,
    data: Buffer.from(data),
  };
}
exports.fromBech32 = fromBech32;
function toBase58Check(hash, version) {
  (0, types_1.typeforce)(
    (0, types_1.tuple)(types_1.Hash160bit, types_1.UInt8),
    arguments,
  );
  const payload = Buffer.allocUnsafe(21);
  payload.writeUInt8(version, 0);
  hash.copy(payload, 1);
  return bs58check.encode(payload);
}
exports.toBase58Check = toBase58Check;
function toBech32(data, version, prefix) {
  const words = bech32_1.bech32.toWords(data);
  words.unshift(version);
  return version === 0
    ? bech32_1.bech32.encode(prefix, words)
    : bech32_1.bech32m.encode(prefix, words);
}
exports.toBech32 = toBech32;
function fromOutputScript(output, network) {
  // TODO: Network
  network = network || networks.bitcoin;
  try {
    return payments.p2pkh({ output, network }).address;
  } catch (e) {}
  try {
    return payments.p2sh({ output, network }).address;
  } catch (e) {}
  try {
    return payments.p2wpkh({ output, network }).address;
  } catch (e) {}
  try {
    return payments.p2wsh({ output, network }).address;
  } catch (e) {}
  try {
    return payments.p2tr({ output, network }).address;
  } catch (e) {}
  try {
    return _toFutureSegwitAddress(output, network);
  } catch (e) {}
  throw new Error(bscript.toASM(output) + ' has no matching Address');
}
exports.fromOutputScript = fromOutputScript;
function toOutputScript(address, network) {
  network = network || networks.bitcoin;
  let decodeBase58;
  let decodeBech32;
  try {
    decodeBase58 = fromBase58Check(address);
  } catch (e) {}
  if (decodeBase58) {
    if (decodeBase58.version === network.pubKeyHash)
      return payments.p2pkh({ hash: decodeBase58.hash }).output;
    if (decodeBase58.version === network.scriptHash)
      return payments.p2sh({ hash: decodeBase58.hash }).output;
  } else {
    try {
      decodeBech32 = fromBech32(address);
    } catch (e) {}
    if (decodeBech32) {
      if (decodeBech32.prefix !== network.bech32)
        throw new Error(address + ' has an invalid prefix');
      if (decodeBech32.version === 0) {
        if (decodeBech32.data.length === 20)
          return payments.p2wpkh({ hash: decodeBech32.data }).output;
        if (decodeBech32.data.length === 32)
          return payments.p2wsh({ hash: decodeBech32.data }).output;
      } else if (decodeBech32.version === 1) {
        if (decodeBech32.data.length === 32)
          return payments.p2tr({ pubkey: decodeBech32.data }).output;
      } else if (
        decodeBech32.version >= FUTURE_SEGWIT_MIN_VERSION &&
        decodeBech32.version <= FUTURE_SEGWIT_MAX_VERSION &&
        decodeBech32.data.length >= FUTURE_SEGWIT_MIN_SIZE &&
        decodeBech32.data.length <= FUTURE_SEGWIT_MAX_SIZE
      ) {
        console.warn(FUTURE_SEGWIT_VERSION_WARNING);
        return bscript.compile([
          decodeBech32.version + FUTURE_SEGWIT_VERSION_DIFF,
          decodeBech32.data,
        ]);
      }
    }
  }
  throw new Error(address + ' has no matching Script');
}
exports.toOutputScript = toOutputScript;

}).call(this)}).call(this,require("buffer").Buffer)
},{"./networks":68,"./payments":72,"./script":85,"./types":89,"bech32":13,"bs58check":59,"buffer":97}],61:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
// Reference https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki
// Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S]
// NOTE: SIGHASH byte ignored AND restricted, truncate before use
Object.defineProperty(exports, '__esModule', { value: true });
exports.encode = exports.decode = exports.check = void 0;
function check(buffer) {
  if (buffer.length < 8) return false;
  if (buffer.length > 72) return false;
  if (buffer[0] !== 0x30) return false;
  if (buffer[1] !== buffer.length - 2) return false;
  if (buffer[2] !== 0x02) return false;
  const lenR = buffer[3];
  if (lenR === 0) return false;
  if (5 + lenR >= buffer.length) return false;
  if (buffer[4 + lenR] !== 0x02) return false;
  const lenS = buffer[5 + lenR];
  if (lenS === 0) return false;
  if (6 + lenR + lenS !== buffer.length) return false;
  if (buffer[4] & 0x80) return false;
  if (lenR > 1 && buffer[4] === 0x00 && !(buffer[5] & 0x80)) return false;
  if (buffer[lenR + 6] & 0x80) return false;
  if (lenS > 1 && buffer[lenR + 6] === 0x00 && !(buffer[lenR + 7] & 0x80))
    return false;
  return true;
}
exports.check = check;
function decode(buffer) {
  if (buffer.length < 8) throw new Error('DER sequence length is too short');
  if (buffer.length > 72) throw new Error('DER sequence length is too long');
  if (buffer[0] !== 0x30) throw new Error('Expected DER sequence');
  if (buffer[1] !== buffer.length - 2)
    throw new Error('DER sequence length is invalid');
  if (buffer[2] !== 0x02) throw new Error('Expected DER integer');
  const lenR = buffer[3];
  if (lenR === 0) throw new Error('R length is zero');
  if (5 + lenR >= buffer.length) throw new Error('R length is too long');
  if (buffer[4 + lenR] !== 0x02) throw new Error('Expected DER integer (2)');
  const lenS = buffer[5 + lenR];
  if (lenS === 0) throw new Error('S length is zero');
  if (6 + lenR + lenS !== buffer.length) throw new Error('S length is invalid');
  if (buffer[4] & 0x80) throw new Error('R value is negative');
  if (lenR > 1 && buffer[4] === 0x00 && !(buffer[5] & 0x80))
    throw new Error('R value excessively padded');
  if (buffer[lenR + 6] & 0x80) throw new Error('S value is negative');
  if (lenS > 1 && buffer[lenR + 6] === 0x00 && !(buffer[lenR + 7] & 0x80))
    throw new Error('S value excessively padded');
  // non-BIP66 - extract R, S values
  return {
    r: buffer.slice(4, 4 + lenR),
    s: buffer.slice(6 + lenR),
  };
}
exports.decode = decode;
/*
 * Expects r and s to be positive DER integers.
 *
 * The DER format uses the most significant bit as a sign bit (& 0x80).
 * If the significant bit is set AND the integer is positive, a 0x00 is prepended.
 *
 * Examples:
 *
 *      0 =>     0x00
 *      1 =>     0x01
 *     -1 =>     0xff
 *    127 =>     0x7f
 *   -127 =>     0x81
 *    128 =>   0x0080
 *   -128 =>     0x80
 *    255 =>   0x00ff
 *   -255 =>   0xff01
 *  16300 =>   0x3fac
 * -16300 =>   0xc054
 *  62300 => 0x00f35c
 * -62300 => 0xff0ca4
 */
function encode(r, s) {
  const lenR = r.length;
  const lenS = s.length;
  if (lenR === 0) throw new Error('R length is zero');
  if (lenS === 0) throw new Error('S length is zero');
  if (lenR > 33) throw new Error('R length is too long');
  if (lenS > 33) throw new Error('S length is too long');
  if (r[0] & 0x80) throw new Error('R value is negative');
  if (s[0] & 0x80) throw new Error('S value is negative');
  if (lenR > 1 && r[0] === 0x00 && !(r[1] & 0x80))
    throw new Error('R value excessively padded');
  if (lenS > 1 && s[0] === 0x00 && !(s[1] & 0x80))
    throw new Error('S value excessively padded');
  const signature = Buffer.allocUnsafe(6 + lenR + lenS);
  // 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S]
  signature[0] = 0x30;
  signature[1] = signature.length - 2;
  signature[2] = 0x02;
  signature[3] = r.length;
  r.copy(signature, 4);
  signature[4 + lenR] = 0x02;
  signature[5 + lenR] = s.length;
  s.copy(signature, 6 + lenR);
  return signature;
}
exports.encode = encode;

}).call(this)}).call(this,require("buffer").Buffer)
},{"buffer":97}],62:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.Block = void 0;
const bufferutils_1 = require('./bufferutils');
const bcrypto = require('./crypto');
const merkle_1 = require('./merkle');
const transaction_1 = require('./transaction');
const types = require('./types');
const { typeforce } = types;
const errorMerkleNoTxes = new TypeError(
  'Cannot compute merkle root for zero transactions',
);
const errorWitnessNotSegwit = new TypeError(
  'Cannot compute witness commit for non-segwit block',
);
class Block {
  constructor() {
    this.version = 1;
    this.prevHash = undefined;
    this.merkleRoot = undefined;
    this.timestamp = 0;
    this.witnessCommit = undefined;
    this.bits = 0;
    this.nonce = 0;
    this.transactions = undefined;
  }
  static fromBuffer(buffer) {
    if (buffer.length < 80) throw new Error('Buffer too small (< 80 bytes)');
    const bufferReader = new bufferutils_1.BufferReader(buffer);
    const block = new Block();
    block.version = bufferReader.readInt32();
    block.prevHash = bufferReader.readSlice(32);
    block.merkleRoot = bufferReader.readSlice(32);
    block.timestamp = bufferReader.readUInt32();
    block.bits = bufferReader.readUInt32();
    block.nonce = bufferReader.readUInt32();
    if (buffer.length === 80) return block;
    const readTransaction = () => {
      const tx = transaction_1.Transaction.fromBuffer(
        bufferReader.buffer.slice(bufferReader.offset),
        true,
      );
      bufferReader.offset += tx.byteLength();
      return tx;
    };
    const nTransactions = bufferReader.readVarInt();
    block.transactions = [];
    for (let i = 0; i < nTransactions; ++i) {
      const tx = readTransaction();
      block.transactions.push(tx);
    }
    const witnessCommit = block.getWitnessCommit();
    // This Block contains a witness commit
    if (witnessCommit) block.witnessCommit = witnessCommit;
    return block;
  }
  static fromHex(hex) {
    return Block.fromBuffer(Buffer.from(hex, 'hex'));
  }
  static calculateTarget(bits) {
    const exponent = ((bits & 0xff000000) >> 24) - 3;
    const mantissa = bits & 0x007fffff;
    const target = Buffer.alloc(32, 0);
    target.writeUIntBE(mantissa, 29 - exponent, 3);
    return target;
  }
  static calculateMerkleRoot(transactions, forWitness) {
    typeforce([{ getHash: types.Function }], transactions);
    if (transactions.length === 0) throw errorMerkleNoTxes;
    if (forWitness && !txesHaveWitnessCommit(transactions))
      throw errorWitnessNotSegwit;
    const hashes = transactions.map(transaction =>
      transaction.getHash(forWitness),
    );
    const rootHash = (0, merkle_1.fastMerkleRoot)(hashes, bcrypto.hash256);
    return forWitness
      ? bcrypto.hash256(
          Buffer.concat([rootHash, transactions[0].ins[0].witness[0]]),
        )
      : rootHash;
  }
  getWitnessCommit() {
    if (!txesHaveWitnessCommit(this.transactions)) return null;
    // The merkle root for the witness data is in an OP_RETURN output.
    // There is no rule for the index of the output, so use filter to find it.
    // The root is prepended with 0xaa21a9ed so check for 0x6a24aa21a9ed
    // If multiple commits are found, the output with highest index is assumed.
    const witnessCommits = this.transactions[0].outs
      .filter(out =>
        out.script.slice(0, 6).equals(Buffer.from('6a24aa21a9ed', 'hex')),
      )
      .map(out => out.script.slice(6, 38));
    if (witnessCommits.length === 0) return null;
    // Use the commit with the highest output (should only be one though)
    const result = witnessCommits[witnessCommits.length - 1];
    if (!(result instanceof Buffer && result.length === 32)) return null;
    return result;
  }
  hasWitnessCommit() {
    if (
      this.witnessCommit instanceof Buffer &&
      this.witnessCommit.length === 32
    )
      return true;
    if (this.getWitnessCommit() !== null) return true;
    return false;
  }
  hasWitness() {
    return anyTxHasWitness(this.transactions);
  }
  weight() {
    const base = this.byteLength(false, false);
    const total = this.byteLength(false, true);
    return base * 3 + total;
  }
  byteLength(headersOnly, allowWitness = true) {
    if (headersOnly || !this.transactions) return 80;
    return (
      80 +
      bufferutils_1.varuint.encodingLength(this.transactions.length) +
      this.transactions.reduce((a, x) => a + x.byteLength(allowWitness), 0)
    );
  }
  getHash() {
    return bcrypto.hash256(this.toBuffer(true));
  }
  getId() {
    return (0, bufferutils_1.reverseBuffer)(this.getHash()).toString('hex');
  }
  getUTCDate() {
    const date = new Date(0); // epoch
    date.setUTCSeconds(this.timestamp);
    return date;
  }
  // TODO: buffer, offset compatibility
  toBuffer(headersOnly) {
    const buffer = Buffer.allocUnsafe(this.byteLength(headersOnly));
    const bufferWriter = new bufferutils_1.BufferWriter(buffer);
    bufferWriter.writeInt32(this.version);
    bufferWriter.writeSlice(this.prevHash);
    bufferWriter.writeSlice(this.merkleRoot);
    bufferWriter.writeUInt32(this.timestamp);
    bufferWriter.writeUInt32(this.bits);
    bufferWriter.writeUInt32(this.nonce);
    if (headersOnly || !this.transactions) return buffer;
    bufferutils_1.varuint.encode(
      this.transactions.length,
      buffer,
      bufferWriter.offset,
    );
    bufferWriter.offset += bufferutils_1.varuint.encode.bytes;
    this.transactions.forEach(tx => {
      const txSize = tx.byteLength(); // TODO: extract from toBuffer?
      tx.toBuffer(buffer, bufferWriter.offset);
      bufferWriter.offset += txSize;
    });
    return buffer;
  }
  toHex(headersOnly) {
    return this.toBuffer(headersOnly).toString('hex');
  }
  checkTxRoots() {
    // If the Block has segwit transactions but no witness commit,
    // there's no way it can be valid, so fail the check.
    const hasWitnessCommit = this.hasWitnessCommit();
    if (!hasWitnessCommit && this.hasWitness()) return false;
    return (
      this.__checkMerkleRoot() &&
      (hasWitnessCommit ? this.__checkWitnessCommit() : true)
    );
  }
  checkProofOfWork() {
    const hash = (0, bufferutils_1.reverseBuffer)(this.getHash());
    const target = Block.calculateTarget(this.bits);
    return hash.compare(target) <= 0;
  }
  __checkMerkleRoot() {
    if (!this.transactions) throw errorMerkleNoTxes;
    const actualMerkleRoot = Block.calculateMerkleRoot(this.transactions);
    return this.merkleRoot.compare(actualMerkleRoot) === 0;
  }
  __checkWitnessCommit() {
    if (!this.transactions) throw errorMerkleNoTxes;
    if (!this.hasWitnessCommit()) throw errorWitnessNotSegwit;
    const actualWitnessCommit = Block.calculateMerkleRoot(
      this.transactions,
      true,
    );
    return this.witnessCommit.compare(actualWitnessCommit) === 0;
  }
}
exports.Block = Block;
function txesHaveWitnessCommit(transactions) {
  return (
    transactions instanceof Array &&
    transactions[0] &&
    transactions[0].ins &&
    transactions[0].ins instanceof Array &&
    transactions[0].ins[0] &&
    transactions[0].ins[0].witness &&
    transactions[0].ins[0].witness instanceof Array &&
    transactions[0].ins[0].witness.length > 0
  );
}
function anyTxHasWitness(transactions) {
  return (
    transactions instanceof Array &&
    transactions.some(
      tx =>
        typeof tx === 'object' &&
        tx.ins instanceof Array &&
        tx.ins.some(
          input =>
            typeof input === 'object' &&
            input.witness instanceof Array &&
            input.witness.length > 0,
        ),
    )
  );
}

}).call(this)}).call(this,require("buffer").Buffer)
},{"./bufferutils":63,"./crypto":64,"./merkle":67,"./transaction":88,"./types":89,"buffer":97}],63:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.BufferReader =
  exports.BufferWriter =
  exports.cloneBuffer =
  exports.reverseBuffer =
  exports.writeUInt64LE =
  exports.readUInt64LE =
  exports.varuint =
    void 0;
const types = require('./types');
const { typeforce } = types;
const varuint = require('varuint-bitcoin');
exports.varuint = varuint;
// https://github.com/feross/buffer/blob/master/index.js#L1127
function verifuint(value, max) {
  if (typeof value !== 'number')
    throw new Error('cannot write a non-number as a number');
  if (value < 0)
    throw new Error('specified a negative value for writing an unsigned value');
  if (value > max) throw new Error('RangeError: value out of range');
  if (Math.floor(value) !== value)
    throw new Error('value has a fractional component');
}
function readUInt64LE(buffer, offset) {
  const a = buffer.readUInt32LE(offset);
  let b = buffer.readUInt32LE(offset + 4);
  b *= 0x100000000;
  verifuint(b + a, 0x001fffffffffffff);
  return b + a;
}
exports.readUInt64LE = readUInt64LE;
function writeUInt64LE(buffer, value, offset) {
  verifuint(value, 0x001fffffffffffff);
  buffer.writeInt32LE(value & -1, offset);
  buffer.writeUInt32LE(Math.floor(value / 0x100000000), offset + 4);
  return offset + 8;
}
exports.writeUInt64LE = writeUInt64LE;
function reverseBuffer(buffer) {
  if (buffer.length < 1) return buffer;
  let j = buffer.length - 1;
  let tmp = 0;
  for (let i = 0; i < buffer.length / 2; i++) {
    tmp = buffer[i];
    buffer[i] = buffer[j];
    buffer[j] = tmp;
    j--;
  }
  return buffer;
}
exports.reverseBuffer = reverseBuffer;
function cloneBuffer(buffer) {
  const clone = Buffer.allocUnsafe(buffer.length);
  buffer.copy(clone);
  return clone;
}
exports.cloneBuffer = cloneBuffer;
/**
 * Helper class for serialization of bitcoin data types into a pre-allocated buffer.
 */
class BufferWriter {
  static withCapacity(size) {
    return new BufferWriter(Buffer.alloc(size));
  }
  constructor(buffer, offset = 0) {
    this.buffer = buffer;
    this.offset = offset;
    typeforce(types.tuple(types.Buffer, types.UInt32), [buffer, offset]);
  }
  writeUInt8(i) {
    this.offset = this.buffer.writeUInt8(i, this.offset);
  }
  writeInt32(i) {
    this.offset = this.buffer.writeInt32LE(i, this.offset);
  }
  writeUInt32(i) {
    this.offset = this.buffer.writeUInt32LE(i, this.offset);
  }
  writeUInt64(i) {
    this.offset = writeUInt64LE(this.buffer, i, this.offset);
  }
  writeVarInt(i) {
    varuint.encode(i, this.buffer, this.offset);
    this.offset += varuint.encode.bytes;
  }
  writeSlice(slice) {
    if (this.buffer.length < this.offset + slice.length) {
      throw new Error('Cannot write slice out of bounds');
    }
    this.offset += slice.copy(this.buffer, this.offset);
  }
  writeVarSlice(slice) {
    this.writeVarInt(slice.length);
    this.writeSlice(slice);
  }
  writeVector(vector) {
    this.writeVarInt(vector.length);
    vector.forEach(buf => this.writeVarSlice(buf));
  }
  end() {
    if (this.buffer.length === this.offset) {
      return this.buffer;
    }
    throw new Error(`buffer size ${this.buffer.length}, offset ${this.offset}`);
  }
}
exports.BufferWriter = BufferWriter;
/**
 * Helper class for reading of bitcoin data types from a buffer.
 */
class BufferReader {
  constructor(buffer, offset = 0) {
    this.buffer = buffer;
    this.offset = offset;
    typeforce(types.tuple(types.Buffer, types.UInt32), [buffer, offset]);
  }
  readUInt8() {
    const result = this.buffer.readUInt8(this.offset);
    this.offset++;
    return result;
  }
  readInt32() {
    const result = this.buffer.readInt32LE(this.offset);
    this.offset += 4;
    return result;
  }
  readUInt32() {
    const result = this.buffer.readUInt32LE(this.offset);
    this.offset += 4;
    return result;
  }
  readUInt64() {
    const result = readUInt64LE(this.buffer, this.offset);
    this.offset += 8;
    return result;
  }
  readVarInt() {
    const vi = varuint.decode(this.buffer, this.offset);
    this.offset += varuint.decode.bytes;
    return vi;
  }
  readSlice(n) {
    if (this.buffer.length < this.offset + n) {
      throw new Error('Cannot read slice out of bounds');
    }
    const result = this.buffer.slice(this.offset, this.offset + n);
    this.offset += n;
    return result;
  }
  readVarSlice() {
    return this.readSlice(this.readVarInt());
  }
  readVector() {
    const count = this.readVarInt();
    const vector = [];
    for (let i = 0; i < count; i++) vector.push(this.readVarSlice());
    return vector;
  }
}
exports.BufferReader = BufferReader;

}).call(this)}).call(this,require("buffer").Buffer)
},{"./types":89,"buffer":97,"varuint-bitcoin":95}],64:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.taggedHash =
  exports.TAGGED_HASH_PREFIXES =
  exports.TAGS =
  exports.hash256 =
  exports.hash160 =
  exports.sha256 =
  exports.sha1 =
  exports.ripemd160 =
    void 0;
const ripemd160_1 = require('@noble/hashes/ripemd160');
const sha1_1 = require('@noble/hashes/sha1');
const sha256_1 = require('@noble/hashes/sha256');
function ripemd160(buffer) {
  return Buffer.from((0, ripemd160_1.ripemd160)(Uint8Array.from(buffer)));
}
exports.ripemd160 = ripemd160;
function sha1(buffer) {
  return Buffer.from((0, sha1_1.sha1)(Uint8Array.from(buffer)));
}
exports.sha1 = sha1;
function sha256(buffer) {
  return Buffer.from((0, sha256_1.sha256)(Uint8Array.from(buffer)));
}
exports.sha256 = sha256;
function hash160(buffer) {
  return Buffer.from(
    (0, ripemd160_1.ripemd160)((0, sha256_1.sha256)(Uint8Array.from(buffer))),
  );
}
exports.hash160 = hash160;
function hash256(buffer) {
  return Buffer.from(
    (0, sha256_1.sha256)((0, sha256_1.sha256)(Uint8Array.from(buffer))),
  );
}
exports.hash256 = hash256;
exports.TAGS = [
  'BIP0340/challenge',
  'BIP0340/aux',
  'BIP0340/nonce',
  'TapLeaf',
  'TapBranch',
  'TapSighash',
  'TapTweak',
  'KeyAgg list',
  'KeyAgg coefficient',
];
/** An object mapping tags to their tagged hash prefix of [SHA256(tag) | SHA256(tag)] */
exports.TAGGED_HASH_PREFIXES = {
  'BIP0340/challenge': Buffer.from([
    123, 181, 45, 122, 159, 239, 88, 50, 62, 177, 191, 122, 64, 125, 179, 130,
    210, 243, 242, 216, 27, 177, 34, 79, 73, 254, 81, 143, 109, 72, 211, 124,
    123, 181, 45, 122, 159, 239, 88, 50, 62, 177, 191, 122, 64, 125, 179, 130,
    210, 243, 242, 216, 27, 177, 34, 79, 73, 254, 81, 143, 109, 72, 211, 124,
  ]),
  'BIP0340/aux': Buffer.from([
    241, 239, 78, 94, 192, 99, 202, 218, 109, 148, 202, 250, 157, 152, 126, 160,
    105, 38, 88, 57, 236, 193, 31, 151, 45, 119, 165, 46, 216, 193, 204, 144,
    241, 239, 78, 94, 192, 99, 202, 218, 109, 148, 202, 250, 157, 152, 126, 160,
    105, 38, 88, 57, 236, 193, 31, 151, 45, 119, 165, 46, 216, 193, 204, 144,
  ]),
  'BIP0340/nonce': Buffer.from([
    7, 73, 119, 52, 167, 155, 203, 53, 91, 155, 140, 125, 3, 79, 18, 28, 244,
    52, 215, 62, 247, 45, 218, 25, 135, 0, 97, 251, 82, 191, 235, 47, 7, 73,
    119, 52, 167, 155, 203, 53, 91, 155, 140, 125, 3, 79, 18, 28, 244, 52, 215,
    62, 247, 45, 218, 25, 135, 0, 97, 251, 82, 191, 235, 47,
  ]),
  TapLeaf: Buffer.from([
    174, 234, 143, 220, 66, 8, 152, 49, 5, 115, 75, 88, 8, 29, 30, 38, 56, 211,
    95, 28, 181, 64, 8, 212, 211, 87, 202, 3, 190, 120, 233, 238, 174, 234, 143,
    220, 66, 8, 152, 49, 5, 115, 75, 88, 8, 29, 30, 38, 56, 211, 95, 28, 181,
    64, 8, 212, 211, 87, 202, 3, 190, 120, 233, 238,
  ]),
  TapBranch: Buffer.from([
    25, 65, 161, 242, 229, 110, 185, 95, 162, 169, 241, 148, 190, 92, 1, 247,
    33, 111, 51, 237, 130, 176, 145, 70, 52, 144, 208, 91, 245, 22, 160, 21, 25,
    65, 161, 242, 229, 110, 185, 95, 162, 169, 241, 148, 190, 92, 1, 247, 33,
    111, 51, 237, 130, 176, 145, 70, 52, 144, 208, 91, 245, 22, 160, 21,
  ]),
  TapSighash: Buffer.from([
    244, 10, 72, 223, 75, 42, 112, 200, 180, 146, 75, 242, 101, 70, 97, 237, 61,
    149, 253, 102, 163, 19, 235, 135, 35, 117, 151, 198, 40, 228, 160, 49, 244,
    10, 72, 223, 75, 42, 112, 200, 180, 146, 75, 242, 101, 70, 97, 237, 61, 149,
    253, 102, 163, 19, 235, 135, 35, 117, 151, 198, 40, 228, 160, 49,
  ]),
  TapTweak: Buffer.from([
    232, 15, 225, 99, 156, 156, 160, 80, 227, 175, 27, 57, 193, 67, 198, 62, 66,
    156, 188, 235, 21, 217, 64, 251, 181, 197, 161, 244, 175, 87, 197, 233, 232,
    15, 225, 99, 156, 156, 160, 80, 227, 175, 27, 57, 193, 67, 198, 62, 66, 156,
    188, 235, 21, 217, 64, 251, 181, 197, 161, 244, 175, 87, 197, 233,
  ]),
  'KeyAgg list': Buffer.from([
    72, 28, 151, 28, 60, 11, 70, 215, 240, 178, 117, 174, 89, 141, 78, 44, 126,
    215, 49, 156, 89, 74, 92, 110, 199, 158, 160, 212, 153, 2, 148, 240, 72, 28,
    151, 28, 60, 11, 70, 215, 240, 178, 117, 174, 89, 141, 78, 44, 126, 215, 49,
    156, 89, 74, 92, 110, 199, 158, 160, 212, 153, 2, 148, 240,
  ]),
  'KeyAgg coefficient': Buffer.from([
    191, 201, 4, 3, 77, 28, 136, 232, 200, 14, 34, 229, 61, 36, 86, 109, 100,
    130, 78, 214, 66, 114, 129, 192, 145, 0, 249, 77, 205, 82, 201, 129, 191,
    201, 4, 3, 77, 28, 136, 232, 200, 14, 34, 229, 61, 36, 86, 109, 100, 130,
    78, 214, 66, 114, 129, 192, 145, 0, 249, 77, 205, 82, 201, 129,
  ]),
};
function taggedHash(prefix, data) {
  return sha256(Buffer.concat([exports.TAGGED_HASH_PREFIXES[prefix], data]));
}
exports.taggedHash = taggedHash;

}).call(this)}).call(this,require("buffer").Buffer)
},{"@noble/hashes/ripemd160":8,"@noble/hashes/sha1":9,"@noble/hashes/sha256":10,"buffer":97}],65:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.getEccLib = exports.initEccLib = void 0;
const _ECCLIB_CACHE = {};
function initEccLib(eccLib) {
  if (!eccLib) {
    // allow clearing the library
    _ECCLIB_CACHE.eccLib = eccLib;
  } else if (eccLib !== _ECCLIB_CACHE.eccLib) {
    // new instance, verify it
    verifyEcc(eccLib);
    _ECCLIB_CACHE.eccLib = eccLib;
  }
}
exports.initEccLib = initEccLib;
function getEccLib() {
  if (!_ECCLIB_CACHE.eccLib)
    throw new Error(
      'No ECC Library provided. You must call initEccLib() with a valid TinySecp256k1Interface instance',
    );
  return _ECCLIB_CACHE.eccLib;
}
exports.getEccLib = getEccLib;
const h = hex => Buffer.from(hex, 'hex');
function verifyEcc(ecc) {
  assert(typeof ecc.isXOnlyPoint === 'function');
  assert(
    ecc.isXOnlyPoint(
      h('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'),
    ),
  );
  assert(
    ecc.isXOnlyPoint(
      h('fffffffffffffffffffffffffffffffffffffffffffffffffffffffeeffffc2e'),
    ),
  );
  assert(
    ecc.isXOnlyPoint(
      h('f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9'),
    ),
  );
  assert(
    ecc.isXOnlyPoint(
      h('0000000000000000000000000000000000000000000000000000000000000001'),
    ),
  );
  assert(
    !ecc.isXOnlyPoint(
      h('0000000000000000000000000000000000000000000000000000000000000000'),
    ),
  );
  assert(
    !ecc.isXOnlyPoint(
      h('fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f'),
    ),
  );
  assert(typeof ecc.xOnlyPointAddTweak === 'function');
  tweakAddVectors.forEach(t => {
    const r = ecc.xOnlyPointAddTweak(h(t.pubkey), h(t.tweak));
    if (t.result === null) {
      assert(r === null);
    } else {
      assert(r !== null);
      assert(r.parity === t.parity);
      assert(Buffer.from(r.xOnlyPubkey).equals(h(t.result)));
    }
  });
}
function assert(bool) {
  if (!bool) throw new Error('ecc library invalid');
}
const tweakAddVectors = [
  {
    pubkey: '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
    tweak: 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140',
    parity: -1,
    result: null,
  },
  {
    pubkey: '1617d38ed8d8657da4d4761e8057bc396ea9e4b9d29776d4be096016dbd2509b',
    tweak: 'a8397a935f0dfceba6ba9618f6451ef4d80637abf4e6af2669fbc9de6a8fd2ac',
    parity: 1,
    result: 'e478f99dab91052ab39a33ea35fd5e6e4933f4d28023cd597c9a1f6760346adf',
  },
  {
    pubkey: '2c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991',
    tweak: '823c3cd2142744b075a87eade7e1b8678ba308d566226a0056ca2b7a76f86b47',
    parity: 0,
    result: '9534f8dc8c6deda2dc007655981c78b49c5d96c778fbf363462a11ec9dfd948c',
  },
];

}).call(this)}).call(this,require("buffer").Buffer)
},{"buffer":97}],66:[function(require,module,exports){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.initEccLib =
  exports.Transaction =
  exports.opcodes =
  exports.Psbt =
  exports.Block =
  exports.script =
  exports.payments =
  exports.networks =
  exports.crypto =
  exports.address =
    void 0;
const address = require('./address');
exports.address = address;
const crypto = require('./crypto');
exports.crypto = crypto;
const networks = require('./networks');
exports.networks = networks;
const payments = require('./payments');
exports.payments = payments;
const script = require('./script');
exports.script = script;
var block_1 = require('./block');
Object.defineProperty(exports, 'Block', {
  enumerable: true,
  get: function () {
    return block_1.Block;
  },
});
var psbt_1 = require('./psbt');
Object.defineProperty(exports, 'Psbt', {
  enumerable: true,
  get: function () {
    return psbt_1.Psbt;
  },
});
var ops_1 = require('./ops');
Object.defineProperty(exports, 'opcodes', {
  enumerable: true,
  get: function () {
    return ops_1.OPS;
  },
});
var transaction_1 = require('./transaction');
Object.defineProperty(exports, 'Transaction', {
  enumerable: true,
  get: function () {
    return transaction_1.Transaction;
  },
});
var ecc_lib_1 = require('./ecc_lib');
Object.defineProperty(exports, 'initEccLib', {
  enumerable: true,
  get: function () {
    return ecc_lib_1.initEccLib;
  },
});

},{"./address":60,"./block":62,"./crypto":64,"./ecc_lib":65,"./networks":68,"./ops":69,"./payments":72,"./psbt":81,"./script":85,"./transaction":88}],67:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.fastMerkleRoot = void 0;
function fastMerkleRoot(values, digestFn) {
  if (!Array.isArray(values)) throw TypeError('Expected values Array');
  if (typeof digestFn !== 'function')
    throw TypeError('Expected digest Function');
  let length = values.length;
  const results = values.concat();
  while (length > 1) {
    let j = 0;
    for (let i = 0; i < length; i += 2, ++j) {
      const left = results[i];
      const right = i + 1 === length ? left : results[i + 1];
      const data = Buffer.concat([left, right]);
      results[j] = digestFn(data);
    }
    length = j;
  }
  return results[0];
}
exports.fastMerkleRoot = fastMerkleRoot;

}).call(this)}).call(this,require("buffer").Buffer)
},{"buffer":97}],68:[function(require,module,exports){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.testnet = exports.regtest = exports.bitcoin = void 0;
exports.bitcoin = {
  messagePrefix: '\x18Bitcoin Signed Message:\n',
  bech32: 'bc',
  bip32: {
    public: 0x0488b21e,
    private: 0x0488ade4,
  },
  pubKeyHash: 0x00,
  scriptHash: 0x05,
  wif: 0x80,
};
exports.regtest = {
  messagePrefix: '\x18Bitcoin Signed Message:\n',
  bech32: 'bcrt',
  bip32: {
    public: 0x043587cf,
    private: 0x04358394,
  },
  pubKeyHash: 0x6f,
  scriptHash: 0xc4,
  wif: 0xef,
};
exports.testnet = {
  messagePrefix: '\x18Bitcoin Signed Message:\n',
  bech32: 'tb',
  bip32: {
    public: 0x043587cf,
    private: 0x04358394,
  },
  pubKeyHash: 0x6f,
  scriptHash: 0xc4,
  wif: 0xef,
};

},{}],69:[function(require,module,exports){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.REVERSE_OPS = exports.OPS = void 0;
const OPS = {
  OP_FALSE: 0,
  OP_0: 0,
  OP_PUSHDATA1: 76,
  OP_PUSHDATA2: 77,
  OP_PUSHDATA4: 78,
  OP_1NEGATE: 79,
  OP_RESERVED: 80,
  OP_TRUE: 81,
  OP_1: 81,
  OP_2: 82,
  OP_3: 83,
  OP_4: 84,
  OP_5: 85,
  OP_6: 86,
  OP_7: 87,
  OP_8: 88,
  OP_9: 89,
  OP_10: 90,
  OP_11: 91,
  OP_12: 92,
  OP_13: 93,
  OP_14: 94,
  OP_15: 95,
  OP_16: 96,
  OP_NOP: 97,
  OP_VER: 98,
  OP_IF: 99,
  OP_NOTIF: 100,
  OP_VERIF: 101,
  OP_VERNOTIF: 102,
  OP_ELSE: 103,
  OP_ENDIF: 104,
  OP_VERIFY: 105,
  OP_RETURN: 106,
  OP_TOALTSTACK: 107,
  OP_FROMALTSTACK: 108,
  OP_2DROP: 109,
  OP_2DUP: 110,
  OP_3DUP: 111,
  OP_2OVER: 112,
  OP_2ROT: 113,
  OP_2SWAP: 114,
  OP_IFDUP: 115,
  OP_DEPTH: 116,
  OP_DROP: 117,
  OP_DUP: 118,
  OP_NIP: 119,
  OP_OVER: 120,
  OP_PICK: 121,
  OP_ROLL: 122,
  OP_ROT: 123,
  OP_SWAP: 124,
  OP_TUCK: 125,
  OP_CAT: 126,
  OP_SUBSTR: 127,
  OP_LEFT: 128,
  OP_RIGHT: 129,
  OP_SIZE: 130,
  OP_INVERT: 131,
  OP_AND: 132,
  OP_OR: 133,
  OP_XOR: 134,
  OP_EQUAL: 135,
  OP_EQUALVERIFY: 136,
  OP_RESERVED1: 137,
  OP_RESERVED2: 138,
  OP_1ADD: 139,
  OP_1SUB: 140,
  OP_2MUL: 141,
  OP_2DIV: 142,
  OP_NEGATE: 143,
  OP_ABS: 144,
  OP_NOT: 145,
  OP_0NOTEQUAL: 146,
  OP_ADD: 147,
  OP_SUB: 148,
  OP_MUL: 149,
  OP_DIV: 150,
  OP_MOD: 151,
  OP_LSHIFT: 152,
  OP_RSHIFT: 153,
  OP_BOOLAND: 154,
  OP_BOOLOR: 155,
  OP_NUMEQUAL: 156,
  OP_NUMEQUALVERIFY: 157,
  OP_NUMNOTEQUAL: 158,
  OP_LESSTHAN: 159,
  OP_GREATERTHAN: 160,
  OP_LESSTHANOREQUAL: 161,
  OP_GREATERTHANOREQUAL: 162,
  OP_MIN: 163,
  OP_MAX: 164,
  OP_WITHIN: 165,
  OP_RIPEMD160: 166,
  OP_SHA1: 167,
  OP_SHA256: 168,
  OP_HASH160: 169,
  OP_HASH256: 170,
  OP_CODESEPARATOR: 171,
  OP_CHECKSIG: 172,
  OP_CHECKSIGVERIFY: 173,
  OP_CHECKMULTISIG: 174,
  OP_CHECKMULTISIGVERIFY: 175,
  OP_NOP1: 176,
  OP_NOP2: 177,
  OP_CHECKLOCKTIMEVERIFY: 177,
  OP_NOP3: 178,
  OP_CHECKSEQUENCEVERIFY: 178,
  OP_NOP4: 179,
  OP_NOP5: 180,
  OP_NOP6: 181,
  OP_NOP7: 182,
  OP_NOP8: 183,
  OP_NOP9: 184,
  OP_NOP10: 185,
  OP_CHECKSIGADD: 186,
  OP_PUBKEYHASH: 253,
  OP_PUBKEY: 254,
  OP_INVALIDOPCODE: 255,
};
exports.OPS = OPS;
const REVERSE_OPS = {};
exports.REVERSE_OPS = REVERSE_OPS;
for (const op of Object.keys(OPS)) {
  const code = OPS[op];
  REVERSE_OPS[code] = op;
}

},{}],70:[function(require,module,exports){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.tweakKey =
  exports.tapTweakHash =
  exports.tapleafHash =
  exports.findScriptPath =
  exports.toHashTree =
  exports.rootHashFromPath =
  exports.MAX_TAPTREE_DEPTH =
  exports.LEAF_VERSION_TAPSCRIPT =
    void 0;
const buffer_1 = require('buffer');
const ecc_lib_1 = require('../ecc_lib');
const bcrypto = require('../crypto');
const bufferutils_1 = require('../bufferutils');
const types_1 = require('../types');
exports.LEAF_VERSION_TAPSCRIPT = 0xc0;
exports.MAX_TAPTREE_DEPTH = 128;
const isHashBranch = ht => 'left' in ht && 'right' in ht;
function rootHashFromPath(controlBlock, leafHash) {
  if (controlBlock.length < 33)
    throw new TypeError(
      `The control-block length is too small. Got ${controlBlock.length}, expected min 33.`,
    );
  const m = (controlBlock.length - 33) / 32;
  let kj = leafHash;
  for (let j = 0; j < m; j++) {
    const ej = controlBlock.slice(33 + 32 * j, 65 + 32 * j);
    if (kj.compare(ej) < 0) {
      kj = tapBranchHash(kj, ej);
    } else {
      kj = tapBranchHash(ej, kj);
    }
  }
  return kj;
}
exports.rootHashFromPath = rootHashFromPath;
/**
 * Build a hash tree of merkle nodes from the scripts binary tree.
 * @param scriptTree - the tree of scripts to pairwise hash.
 */
function toHashTree(scriptTree) {
  if ((0, types_1.isTapleaf)(scriptTree))
    return { hash: tapleafHash(scriptTree) };
  const hashes = [toHashTree(scriptTree[0]), toHashTree(scriptTree[1])];
  hashes.sort((a, b) => a.hash.compare(b.hash));
  const [left, right] = hashes;
  return {
    hash: tapBranchHash(left.hash, right.hash),
    left,
    right,
  };
}
exports.toHashTree = toHashTree;
/**
 * Given a HashTree, finds the path from a particular hash to the root.
 * @param node - the root of the tree
 * @param hash - the hash to search for
 * @returns - array of sibling hashes, from leaf (inclusive) to root
 * (exclusive) needed to prove inclusion of the specified hash. undefined if no
 * path is found
 */
function findScriptPath(node, hash) {
  if (isHashBranch(node)) {
    const leftPath = findScriptPath(node.left, hash);
    if (leftPath !== undefined) return [...leftPath, node.right.hash];
    const rightPath = findScriptPath(node.right, hash);
    if (rightPath !== undefined) return [...rightPath, node.left.hash];
  } else if (node.hash.equals(hash)) {
    return [];
  }
  return undefined;
}
exports.findScriptPath = findScriptPath;
function tapleafHash(leaf) {
  const version = leaf.version || exports.LEAF_VERSION_TAPSCRIPT;
  return bcrypto.taggedHash(
    'TapLeaf',
    buffer_1.Buffer.concat([
      buffer_1.Buffer.from([version]),
      serializeScript(leaf.output),
    ]),
  );
}
exports.tapleafHash = tapleafHash;
function tapTweakHash(pubKey, h) {
  return bcrypto.taggedHash(
    'TapTweak',
    buffer_1.Buffer.concat(h ? [pubKey, h] : [pubKey]),
  );
}
exports.tapTweakHash = tapTweakHash;
function tweakKey(pubKey, h) {
  if (!buffer_1.Buffer.isBuffer(pubKey)) return null;
  if (pubKey.length !== 32) return null;
  if (h && h.length !== 32) return null;
  const tweakHash = tapTweakHash(pubKey, h);
  const res = (0, ecc_lib_1.getEccLib)().xOnlyPointAddTweak(pubKey, tweakHash);
  if (!res || res.xOnlyPubkey === null) return null;
  return {
    parity: res.parity,
    x: buffer_1.Buffer.from(res.xOnlyPubkey),
  };
}
exports.tweakKey = tweakKey;
function tapBranchHash(a, b) {
  return bcrypto.taggedHash('TapBranch', buffer_1.Buffer.concat([a, b]));
}
function serializeScript(s) {
  const varintLen = bufferutils_1.varuint.encodingLength(s.length);
  const buffer = buffer_1.Buffer.allocUnsafe(varintLen); // better
  bufferutils_1.varuint.encode(s.length, buffer);
  return buffer_1.Buffer.concat([buffer, s]);
}

},{"../bufferutils":63,"../crypto":64,"../ecc_lib":65,"../types":89,"buffer":97}],71:[function(require,module,exports){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.p2data = void 0;
const networks_1 = require('../networks');
const bscript = require('../script');
const types_1 = require('../types');
const lazy = require('./lazy');
const OPS = bscript.OPS;
function stacksEqual(a, b) {
  if (a.length !== b.length) return false;
  return a.every((x, i) => {
    return x.equals(b[i]);
  });
}
// output: OP_RETURN ...
function p2data(a, opts) {
  if (!a.data && !a.output) throw new TypeError('Not enough data');
  opts = Object.assign({ validate: true }, opts || {});
  (0, types_1.typeforce)(
    {
      network: types_1.typeforce.maybe(types_1.typeforce.Object),
      output: types_1.typeforce.maybe(types_1.typeforce.Buffer),
      data: types_1.typeforce.maybe(
        types_1.typeforce.arrayOf(types_1.typeforce.Buffer),
      ),
    },
    a,
  );
  const network = a.network || networks_1.bitcoin;
  const o = { name: 'embed', network };
  lazy.prop(o, 'output', () => {
    if (!a.data) return;
    return bscript.compile([OPS.OP_RETURN].concat(a.data));
  });
  lazy.prop(o, 'data', () => {
    if (!a.output) return;
    return bscript.decompile(a.output).slice(1);
  });
  // extended validation
  if (opts.validate) {
    if (a.output) {
      const chunks = bscript.decompile(a.output);
      if (chunks[0] !== OPS.OP_RETURN) throw new TypeError('Output is invalid');
      if (!chunks.slice(1).every(types_1.typeforce.Buffer))
        throw new TypeError('Output is invalid');
      if (a.data && !stacksEqual(a.data, o.data))
        throw new TypeError('Data mismatch');
    }
  }
  return Object.assign(o, a);
}
exports.p2data = p2data;

},{"../networks":68,"../script":85,"../types":89,"./lazy":73}],72:[function(require,module,exports){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.p2tr =
  exports.p2wsh =
  exports.p2wpkh =
  exports.p2sh =
  exports.p2pkh =
  exports.p2pk =
  exports.p2ms =
  exports.embed =
    void 0;
const embed_1 = require('./embed');
Object.defineProperty(exports, 'embed', {
  enumerable: true,
  get: function () {
    return embed_1.p2data;
  },
});
const p2ms_1 = require('./p2ms');
Object.defineProperty(exports, 'p2ms', {
  enumerable: true,
  get: function () {
    return p2ms_1.p2ms;
  },
});
const p2pk_1 = require('./p2pk');
Object.defineProperty(exports, 'p2pk', {
  enumerable: true,
  get: function () {
    return p2pk_1.p2pk;
  },
});
const p2pkh_1 = require('./p2pkh');
Object.defineProperty(exports, 'p2pkh', {
  enumerable: true,
  get: function () {
    return p2pkh_1.p2pkh;
  },
});
const p2sh_1 = require('./p2sh');
Object.defineProperty(exports, 'p2sh', {
  enumerable: true,
  get: function () {
    return p2sh_1.p2sh;
  },
});
const p2wpkh_1 = require('./p2wpkh');
Object.defineProperty(exports, 'p2wpkh', {
  enumerable: true,
  get: function () {
    return p2wpkh_1.p2wpkh;
  },
});
const p2wsh_1 = require('./p2wsh');
Object.defineProperty(exports, 'p2wsh', {
  enumerable: true,
  get: function () {
    return p2wsh_1.p2wsh;
  },
});
const p2tr_1 = require('./p2tr');
Object.defineProperty(exports, 'p2tr', {
  enumerable: true,
  get: function () {
    return p2tr_1.p2tr;
  },
});
// TODO
// witness commitment

},{"./embed":71,"./p2ms":74,"./p2pk":75,"./p2pkh":76,"./p2sh":77,"./p2tr":78,"./p2wpkh":79,"./p2wsh":80}],73:[function(require,module,exports){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.value = exports.prop = void 0;
function prop(object, name, f) {
  Object.defineProperty(object, name, {
    configurable: true,
    enumerable: true,
    get() {
      const _value = f.call(this);
      this[name] = _value;
      return _value;
    },
    set(_value) {
      Object.defineProperty(this, name, {
        configurable: true,
        enumerable: true,
        value: _value,
        writable: true,
      });
    },
  });
}
exports.prop = prop;
function value(f) {
  let _value;
  return () => {
    if (_value !== undefined) return _value;
    _value = f();
    return _value;
  };
}
exports.value = value;

},{}],74:[function(require,module,exports){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.p2ms = void 0;
const networks_1 = require('../networks');
const bscript = require('../script');
const types_1 = require('../types');
const lazy = require('./lazy');
const OPS = bscript.OPS;
const OP_INT_BASE = OPS.OP_RESERVED; // OP_1 - 1
function stacksEqual(a, b) {
  if (a.length !== b.length) return false;
  return a.every((x, i) => {
    return x.equals(b[i]);
  });
}
// input: OP_0 [signatures ...]
// output: m [pubKeys ...] n OP_CHECKMULTISIG
function p2ms(a, opts) {
  if (
    !a.input &&
    !a.output &&
    !(a.pubkeys && a.m !== undefined) &&
    !a.signatures
  )
    throw new TypeError('Not enough data');
  opts = Object.assign({ validate: true }, opts || {});
  function isAcceptableSignature(x) {
    return (
      bscript.isCanonicalScriptSignature(x) ||
      (opts.allowIncomplete && x === OPS.OP_0) !== undefined
    );
  }
  (0, types_1.typeforce)(
    {
      network: types_1.typeforce.maybe(types_1.typeforce.Object),
      m: types_1.typeforce.maybe(types_1.typeforce.Number),
      n: types_1.typeforce.maybe(types_1.typeforce.Number),
      output: types_1.typeforce.maybe(types_1.typeforce.Buffer),
      pubkeys: types_1.typeforce.maybe(
        types_1.typeforce.arrayOf(types_1.isPoint),
      ),
      signatures: types_1.typeforce.maybe(
        types_1.typeforce.arrayOf(isAcceptableSignature),
      ),
      input: types_1.typeforce.maybe(types_1.typeforce.Buffer),
    },
    a,
  );
  const network = a.network || networks_1.bitcoin;
  const o = { network };
  let chunks = [];
  let decoded = false;
  function decode(output) {
    if (decoded) return;
    decoded = true;
    chunks = bscript.decompile(output);
    o.m = chunks[0] - OP_INT_BASE;
    o.n = chunks[chunks.length - 2] - OP_INT_BASE;
    o.pubkeys = chunks.slice(1, -2);
  }
  lazy.prop(o, 'output', () => {
    if (!a.m) return;
    if (!o.n) return;
    if (!a.pubkeys) return;
    return bscript.compile(
      [].concat(
        OP_INT_BASE + a.m,
        a.pubkeys,
        OP_INT_BASE + o.n,
        OPS.OP_CHECKMULTISIG,
      ),
    );
  });
  lazy.prop(o, 'm', () => {
    if (!o.output) return;
    decode(o.output);
    return o.m;
  });
  lazy.prop(o, 'n', () => {
    if (!o.pubkeys) return;
    return o.pubkeys.length;
  });
  lazy.prop(o, 'pubkeys', () => {
    if (!a.output) return;
    decode(a.output);
    return o.pubkeys;
  });
  lazy.prop(o, 'signatures', () => {
    if (!a.input) return;
    return bscript.decompile(a.input).slice(1);
  });
  lazy.prop(o, 'input', () => {
    if (!a.signatures) return;
    return bscript.compile([OPS.OP_0].concat(a.signatures));
  });
  lazy.prop(o, 'witness', () => {
    if (!o.input) return;
    return [];
  });
  lazy.prop(o, 'name', () => {
    if (!o.m || !o.n) return;
    return `p2ms(${o.m} of ${o.n})`;
  });
  // extended validation
  if (opts.validate) {
    if (a.output) {
      decode(a.output);
      if (!types_1.typeforce.Number(chunks[0]))
        throw new TypeError('Output is invalid');
      if (!types_1.typeforce.Number(chunks[chunks.length - 2]))
        throw new TypeError('Output is invalid');
      if (chunks[chunks.length - 1] !== OPS.OP_CHECKMULTISIG)
        throw new TypeError('Output is invalid');
      if (o.m <= 0 || o.n > 16 || o.m > o.n || o.n !== chunks.length - 3)
        throw new TypeError('Output is invalid');
      if (!o.pubkeys.every(x => (0, types_1.isPoint)(x)))
        throw new TypeError('Output is invalid');
      if (a.m !== undefined && a.m !== o.m) throw new TypeError('m mismatch');
      if (a.n !== undefined && a.n !== o.n) throw new TypeError('n mismatch');
      if (a.pubkeys && !stacksEqual(a.pubkeys, o.pubkeys))
        throw new TypeError('Pubkeys mismatch');
    }
    if (a.pubkeys) {
      if (a.n !== undefined && a.n !== a.pubkeys.length)
        throw new TypeError('Pubkey count mismatch');
      o.n = a.pubkeys.length;
      if (o.n < o.m) throw new TypeError('Pubkey count cannot be less than m');
    }
    if (a.signatures) {
      if (a.signatures.length < o.m)
        throw new TypeError('Not enough signatures provided');
      if (a.signatures.length > o.m)
        throw new TypeError('Too many signatures provided');
    }
    if (a.input) {
      if (a.input[0] !== OPS.OP_0) throw new TypeError('Input is invalid');
      if (
        o.signatures.length === 0 ||
        !o.signatures.every(isAcceptableSignature)
      )
        throw new TypeError('Input has invalid signature(s)');
      if (a.signatures && !stacksEqual(a.signatures, o.signatures))
        throw new TypeError('Signature mismatch');
      if (a.m !== undefined && a.m !== a.signatures.length)
        throw new TypeError('Signature count mismatch');
    }
  }
  return Object.assign(o, a);
}
exports.p2ms = p2ms;

},{"../networks":68,"../script":85,"../types":89,"./lazy":73}],75:[function(require,module,exports){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.p2pk = void 0;
const networks_1 = require('../networks');
const bscript = require('../script');
const types_1 = require('../types');
const lazy = require('./lazy');
const OPS = bscript.OPS;
// input: {signature}
// output: {pubKey} OP_CHECKSIG
function p2pk(a, opts) {
  if (!a.input && !a.output && !a.pubkey && !a.input && !a.signature)
    throw new TypeError('Not enough data');
  opts = Object.assign({ validate: true }, opts || {});
  (0, types_1.typeforce)(
    {
      network: types_1.typeforce.maybe(types_1.typeforce.Object),
      output: types_1.typeforce.maybe(types_1.typeforce.Buffer),
      pubkey: types_1.typeforce.maybe(types_1.isPoint),
      signature: types_1.typeforce.maybe(bscript.isCanonicalScriptSignature),
      input: types_1.typeforce.maybe(types_1.typeforce.Buffer),
    },
    a,
  );
  const _chunks = lazy.value(() => {
    return bscript.decompile(a.input);
  });
  const network = a.network || networks_1.bitcoin;
  const o = { name: 'p2pk', network };
  lazy.prop(o, 'output', () => {
    if (!a.pubkey) return;
    return bscript.compile([a.pubkey, OPS.OP_CHECKSIG]);
  });
  lazy.prop(o, 'pubkey', () => {
    if (!a.output) return;
    return a.output.slice(1, -1);
  });
  lazy.prop(o, 'signature', () => {
    if (!a.input) return;
    return _chunks()[0];
  });
  lazy.prop(o, 'input', () => {
    if (!a.signature) return;
    return bscript.compile([a.signature]);
  });
  lazy.prop(o, 'witness', () => {
    if (!o.input) return;
    return [];
  });
  // extended validation
  if (opts.validate) {
    if (a.output) {
      if (a.output[a.output.length - 1] !== OPS.OP_CHECKSIG)
        throw new TypeError('Output is invalid');
      if (!(0, types_1.isPoint)(o.pubkey))
        throw new TypeError('Output pubkey is invalid');
      if (a.pubkey && !a.pubkey.equals(o.pubkey))
        throw new TypeError('Pubkey mismatch');
    }
    if (a.signature) {
      if (a.input && !a.input.equals(o.input))
        throw new TypeError('Signature mismatch');
    }
    if (a.input) {
      if (_chunks().length !== 1) throw new TypeError('Input is invalid');
      if (!bscript.isCanonicalScriptSignature(o.signature))
        throw new TypeError('Input has invalid signature');
    }
  }
  return Object.assign(o, a);
}
exports.p2pk = p2pk;

},{"../networks":68,"../script":85,"../types":89,"./lazy":73}],76:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.p2pkh = void 0;
const bcrypto = require('../crypto');
const networks_1 = require('../networks');
const bscript = require('../script');
const types_1 = require('../types');
const lazy = require('./lazy');
const bs58check = require('bs58check');
const OPS = bscript.OPS;
// input: {signature} {pubkey}
// output: OP_DUP OP_HASH160 {hash160(pubkey)} OP_EQUALVERIFY OP_CHECKSIG
function p2pkh(a, opts) {
  if (!a.address && !a.hash && !a.output && !a.pubkey && !a.input)
    throw new TypeError('Not enough data');
  opts = Object.assign({ validate: true }, opts || {});
  (0, types_1.typeforce)(
    {
      network: types_1.typeforce.maybe(types_1.typeforce.Object),
      address: types_1.typeforce.maybe(types_1.typeforce.String),
      hash: types_1.typeforce.maybe(types_1.typeforce.BufferN(20)),
      output: types_1.typeforce.maybe(types_1.typeforce.BufferN(25)),
      pubkey: types_1.typeforce.maybe(types_1.isPoint),
      signature: types_1.typeforce.maybe(bscript.isCanonicalScriptSignature),
      input: types_1.typeforce.maybe(types_1.typeforce.Buffer),
    },
    a,
  );
  const _address = lazy.value(() => {
    const payload = Buffer.from(bs58check.decode(a.address));
    const version = payload.readUInt8(0);
    const hash = payload.slice(1);
    return { version, hash };
  });
  const _chunks = lazy.value(() => {
    return bscript.decompile(a.input);
  });
  const network = a.network || networks_1.bitcoin;
  const o = { name: 'p2pkh', network };
  lazy.prop(o, 'address', () => {
    if (!o.hash) return;
    const payload = Buffer.allocUnsafe(21);
    payload.writeUInt8(network.pubKeyHash, 0);
    o.hash.copy(payload, 1);
    return bs58check.encode(payload);
  });
  lazy.prop(o, 'hash', () => {
    if (a.output) return a.output.slice(3, 23);
    if (a.address) return _address().hash;
    if (a.pubkey || o.pubkey) return bcrypto.hash160(a.pubkey || o.pubkey);
  });
  lazy.prop(o, 'output', () => {
    if (!o.hash) return;
    return bscript.compile([
      OPS.OP_DUP,
      OPS.OP_HASH160,
      o.hash,
      OPS.OP_EQUALVERIFY,
      OPS.OP_CHECKSIG,
    ]);
  });
  lazy.prop(o, 'pubkey', () => {
    if (!a.input) return;
    return _chunks()[1];
  });
  lazy.prop(o, 'signature', () => {
    if (!a.input) return;
    return _chunks()[0];
  });
  lazy.prop(o, 'input', () => {
    if (!a.pubkey) return;
    if (!a.signature) return;
    return bscript.compile([a.signature, a.pubkey]);
  });
  lazy.prop(o, 'witness', () => {
    if (!o.input) return;
    return [];
  });
  // extended validation
  if (opts.validate) {
    let hash = Buffer.from([]);
    if (a.address) {
      if (_address().version !== network.pubKeyHash)
        throw new TypeError('Invalid version or Network mismatch');
      if (_address().hash.length !== 20) throw new TypeError('Invalid address');
      hash = _address().hash;
    }
    if (a.hash) {
      if (hash.length > 0 && !hash.equals(a.hash))
        throw new TypeError('Hash mismatch');
      else hash = a.hash;
    }
    if (a.output) {
      if (
        a.output.length !== 25 ||
        a.output[0] !== OPS.OP_DUP ||
        a.output[1] !== OPS.OP_HASH160 ||
        a.output[2] !== 0x14 ||
        a.output[23] !== OPS.OP_EQUALVERIFY ||
        a.output[24] !== OPS.OP_CHECKSIG
      )
        throw new TypeError('Output is invalid');
      const hash2 = a.output.slice(3, 23);
      if (hash.length > 0 && !hash.equals(hash2))
        throw new TypeError('Hash mismatch');
      else hash = hash2;
    }
    if (a.pubkey) {
      const pkh = bcrypto.hash160(a.pubkey);
      if (hash.length > 0 && !hash.equals(pkh))
        throw new TypeError('Hash mismatch');
      else hash = pkh;
    }
    if (a.input) {
      const chunks = _chunks();
      if (chunks.length !== 2) throw new TypeError('Input is invalid');
      if (!bscript.isCanonicalScriptSignature(chunks[0]))
        throw new TypeError('Input has invalid signature');
      if (!(0, types_1.isPoint)(chunks[1]))
        throw new TypeError('Input has invalid pubkey');
      if (a.signature && !a.signature.equals(chunks[0]))
        throw new TypeError('Signature mismatch');
      if (a.pubkey && !a.pubkey.equals(chunks[1]))
        throw new TypeError('Pubkey mismatch');
      const pkh = bcrypto.hash160(chunks[1]);
      if (hash.length > 0 && !hash.equals(pkh))
        throw new TypeError('Hash mismatch');
    }
  }
  return Object.assign(o, a);
}
exports.p2pkh = p2pkh;

}).call(this)}).call(this,require("buffer").Buffer)
},{"../crypto":64,"../networks":68,"../script":85,"../types":89,"./lazy":73,"bs58check":59,"buffer":97}],77:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.p2sh = void 0;
const bcrypto = require('../crypto');
const networks_1 = require('../networks');
const bscript = require('../script');
const types_1 = require('../types');
const lazy = require('./lazy');
const bs58check = require('bs58check');
const OPS = bscript.OPS;
function stacksEqual(a, b) {
  if (a.length !== b.length) return false;
  return a.every((x, i) => {
    return x.equals(b[i]);
  });
}
// input: [redeemScriptSig ...] {redeemScript}
// witness: <?>
// output: OP_HASH160 {hash160(redeemScript)} OP_EQUAL
function p2sh(a, opts) {
  if (!a.address && !a.hash && !a.output && !a.redeem && !a.input)
    throw new TypeError('Not enough data');
  opts = Object.assign({ validate: true }, opts || {});
  (0, types_1.typeforce)(
    {
      network: types_1.typeforce.maybe(types_1.typeforce.Object),
      address: types_1.typeforce.maybe(types_1.typeforce.String),
      hash: types_1.typeforce.maybe(types_1.typeforce.BufferN(20)),
      output: types_1.typeforce.maybe(types_1.typeforce.BufferN(23)),
      redeem: types_1.typeforce.maybe({
        network: types_1.typeforce.maybe(types_1.typeforce.Object),
        output: types_1.typeforce.maybe(types_1.typeforce.Buffer),
        input: types_1.typeforce.maybe(types_1.typeforce.Buffer),
        witness: types_1.typeforce.maybe(
          types_1.typeforce.arrayOf(types_1.typeforce.Buffer),
        ),
      }),
      input: types_1.typeforce.maybe(types_1.typeforce.Buffer),
      witness: types_1.typeforce.maybe(
        types_1.typeforce.arrayOf(types_1.typeforce.Buffer),
      ),
    },
    a,
  );
  let network = a.network;
  if (!network) {
    network = (a.redeem && a.redeem.network) || networks_1.bitcoin;
  }
  const o = { network };
  const _address = lazy.value(() => {
    const payload = Buffer.from(bs58check.decode(a.address));
    const version = payload.readUInt8(0);
    const hash = payload.slice(1);
    return { version, hash };
  });
  const _chunks = lazy.value(() => {
    return bscript.decompile(a.input);
  });
  const _redeem = lazy.value(() => {
    const chunks = _chunks();
    const lastChunk = chunks[chunks.length - 1];
    return {
      network,
      output: lastChunk === OPS.OP_FALSE ? Buffer.from([]) : lastChunk,
      input: bscript.compile(chunks.slice(0, -1)),
      witness: a.witness || [],
    };
  });
  // output dependents
  lazy.prop(o, 'address', () => {
    if (!o.hash) return;
    const payload = Buffer.allocUnsafe(21);
    payload.writeUInt8(o.network.scriptHash, 0);
    o.hash.copy(payload, 1);
    return bs58check.encode(payload);
  });
  lazy.prop(o, 'hash', () => {
    // in order of least effort
    if (a.output) return a.output.slice(2, 22);
    if (a.address) return _address().hash;
    if (o.redeem && o.redeem.output) return bcrypto.hash160(o.redeem.output);
  });
  lazy.prop(o, 'output', () => {
    if (!o.hash) return;
    return bscript.compile([OPS.OP_HASH160, o.hash, OPS.OP_EQUAL]);
  });
  // input dependents
  lazy.prop(o, 'redeem', () => {
    if (!a.input) return;
    return _redeem();
  });
  lazy.prop(o, 'input', () => {
    if (!a.redeem || !a.redeem.input || !a.redeem.output) return;
    return bscript.compile(
      [].concat(bscript.decompile(a.redeem.input), a.redeem.output),
    );
  });
  lazy.prop(o, 'witness', () => {
    if (o.redeem && o.redeem.witness) return o.redeem.witness;
    if (o.input) return [];
  });
  lazy.prop(o, 'name', () => {
    const nameParts = ['p2sh'];
    if (o.redeem !== undefined && o.redeem.name !== undefined)
      nameParts.push(o.redeem.name);
    return nameParts.join('-');
  });
  if (opts.validate) {
    let hash = Buffer.from([]);
    if (a.address) {
      if (_address().version !== network.scriptHash)
        throw new TypeError('Invalid version or Network mismatch');
      if (_address().hash.length !== 20) throw new TypeError('Invalid address');
      hash = _address().hash;
    }
    if (a.hash) {
      if (hash.length > 0 && !hash.equals(a.hash))
        throw new TypeError('Hash mismatch');
      else hash = a.hash;
    }
    if (a.output) {
      if (
        a.output.length !== 23 ||
        a.output[0] !== OPS.OP_HASH160 ||
        a.output[1] !== 0x14 ||
        a.output[22] !== OPS.OP_EQUAL
      )
        throw new TypeError('Output is invalid');
      const hash2 = a.output.slice(2, 22);
      if (hash.length > 0 && !hash.equals(hash2))
        throw new TypeError('Hash mismatch');
      else hash = hash2;
    }
    // inlined to prevent 'no-inner-declarations' failing
    const checkRedeem = redeem => {
      // is the redeem output empty/invalid?
      if (redeem.output) {
        const decompile = bscript.decompile(redeem.output);
        if (!decompile || decompile.length < 1)
          throw new TypeError('Redeem.output too short');
        if (redeem.output.byteLength > 520)
          throw new TypeError(
            'Redeem.output unspendable if larger than 520 bytes',
          );
        if (bscript.countNonPushOnlyOPs(decompile) > 201)
          throw new TypeError(
            'Redeem.output unspendable with more than 201 non-push ops',
          );
        // match hash against other sources
        const hash2 = bcrypto.hash160(redeem.output);
        if (hash.length > 0 && !hash.equals(hash2))
          throw new TypeError('Hash mismatch');
        else hash = hash2;
      }
      if (redeem.input) {
        const hasInput = redeem.input.length > 0;
        const hasWitness = redeem.witness && redeem.witness.length > 0;
        if (!hasInput && !hasWitness) throw new TypeError('Empty input');
        if (hasInput && hasWitness)
          throw new TypeError('Input and witness provided');
        if (hasInput) {
          const richunks = bscript.decompile(redeem.input);
          if (!bscript.isPushOnly(richunks))
            throw new TypeError('Non push-only scriptSig');
        }
      }
    };
    if (a.input) {
      const chunks = _chunks();
      if (!chunks || chunks.length < 1) throw new TypeError('Input too short');
      if (!Buffer.isBuffer(_redeem().output))
        throw new TypeError('Input is invalid');
      checkRedeem(_redeem());
    }
    if (a.redeem) {
      if (a.redeem.network && a.redeem.network !== network)
        throw new TypeError('Network mismatch');
      if (a.input) {
        const redeem = _redeem();
        if (a.redeem.output && !a.redeem.output.equals(redeem.output))
          throw new TypeError('Redeem.output mismatch');
        if (a.redeem.input && !a.redeem.input.equals(redeem.input))
          throw new TypeError('Redeem.input mismatch');
      }
      checkRedeem(a.redeem);
    }
    if (a.witness) {
      if (
        a.redeem &&
        a.redeem.witness &&
        !stacksEqual(a.redeem.witness, a.witness)
      )
        throw new TypeError('Witness and redeem.witness mismatch');
    }
  }
  return Object.assign(o, a);
}
exports.p2sh = p2sh;

}).call(this)}).call(this,require("buffer").Buffer)
},{"../crypto":64,"../networks":68,"../script":85,"../types":89,"./lazy":73,"bs58check":59,"buffer":97}],78:[function(require,module,exports){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.p2tr = void 0;
const buffer_1 = require('buffer');
const networks_1 = require('../networks');
const bscript = require('../script');
const types_1 = require('../types');
const ecc_lib_1 = require('../ecc_lib');
const bip341_1 = require('./bip341');
const lazy = require('./lazy');
const bech32_1 = require('bech32');
const OPS = bscript.OPS;
const TAPROOT_WITNESS_VERSION = 0x01;
const ANNEX_PREFIX = 0x50;
function p2tr(a, opts) {
  if (
    !a.address &&
    !a.output &&
    !a.pubkey &&
    !a.internalPubkey &&
    !(a.witness && a.witness.length > 1)
  )
    throw new TypeError('Not enough data');
  opts = Object.assign({ validate: true }, opts || {});
  (0, types_1.typeforce)(
    {
      address: types_1.typeforce.maybe(types_1.typeforce.String),
      input: types_1.typeforce.maybe(types_1.typeforce.BufferN(0)),
      network: types_1.typeforce.maybe(types_1.typeforce.Object),
      output: types_1.typeforce.maybe(types_1.typeforce.BufferN(34)),
      internalPubkey: types_1.typeforce.maybe(types_1.typeforce.BufferN(32)),
      hash: types_1.typeforce.maybe(types_1.typeforce.BufferN(32)),
      pubkey: types_1.typeforce.maybe(types_1.typeforce.BufferN(32)),
      signature: types_1.typeforce.maybe(
        types_1.typeforce.anyOf(
          types_1.typeforce.BufferN(64),
          types_1.typeforce.BufferN(65),
        ),
      ),
      witness: types_1.typeforce.maybe(
        types_1.typeforce.arrayOf(types_1.typeforce.Buffer),
      ),
      scriptTree: types_1.typeforce.maybe(types_1.isTaptree),
      redeem: types_1.typeforce.maybe({
        output: types_1.typeforce.maybe(types_1.typeforce.Buffer),
        redeemVersion: types_1.typeforce.maybe(types_1.typeforce.Number),
        witness: types_1.typeforce.maybe(
          types_1.typeforce.arrayOf(types_1.typeforce.Buffer),
        ),
      }),
      redeemVersion: types_1.typeforce.maybe(types_1.typeforce.Number),
    },
    a,
  );
  const _address = lazy.value(() => {
    const result = bech32_1.bech32m.decode(a.address);
    const version = result.words.shift();
    const data = bech32_1.bech32m.fromWords(result.words);
    return {
      version,
      prefix: result.prefix,
      data: buffer_1.Buffer.from(data),
    };
  });
  // remove annex if present, ignored by taproot
  const _witness = lazy.value(() => {
    if (!a.witness || !a.witness.length) return;
    if (
      a.witness.length >= 2 &&
      a.witness[a.witness.length - 1][0] === ANNEX_PREFIX
    ) {
      return a.witness.slice(0, -1);
    }
    return a.witness.slice();
  });
  const _hashTree = lazy.value(() => {
    if (a.scriptTree) return (0, bip341_1.toHashTree)(a.scriptTree);
    if (a.hash) return { hash: a.hash };
    return;
  });
  const network = a.network || networks_1.bitcoin;
  const o = { name: 'p2tr', network };
  lazy.prop(o, 'address', () => {
    if (!o.pubkey) return;
    const words = bech32_1.bech32m.toWords(o.pubkey);
    words.unshift(TAPROOT_WITNESS_VERSION);
    return bech32_1.bech32m.encode(network.bech32, words);
  });
  lazy.prop(o, 'hash', () => {
    const hashTree = _hashTree();
    if (hashTree) return hashTree.hash;
    const w = _witness();
    if (w && w.length > 1) {
      const controlBlock = w[w.length - 1];
      const leafVersion = controlBlock[0] & types_1.TAPLEAF_VERSION_MASK;
      const script = w[w.length - 2];
      const leafHash = (0, bip341_1.tapleafHash)({
        output: script,
        version: leafVersion,
      });
      return (0, bip341_1.rootHashFromPath)(controlBlock, leafHash);
    }
    return null;
  });
  lazy.prop(o, 'output', () => {
    if (!o.pubkey) return;
    return bscript.compile([OPS.OP_1, o.pubkey]);
  });
  lazy.prop(o, 'redeemVersion', () => {
    if (a.redeemVersion) return a.redeemVersion;
    if (
      a.redeem &&
      a.redeem.redeemVersion !== undefined &&
      a.redeem.redeemVersion !== null
    ) {
      return a.redeem.redeemVersion;
    }
    return bip341_1.LEAF_VERSION_TAPSCRIPT;
  });
  lazy.prop(o, 'redeem', () => {
    const witness = _witness(); // witness without annex
    if (!witness || witness.length < 2) return;
    return {
      output: witness[witness.length - 2],
      witness: witness.slice(0, -2),
      redeemVersion:
        witness[witness.length - 1][0] & types_1.TAPLEAF_VERSION_MASK,
    };
  });
  lazy.prop(o, 'pubkey', () => {
    if (a.pubkey) return a.pubkey;
    if (a.output) return a.output.slice(2);
    if (a.address) return _address().data;
    if (o.internalPubkey) {
      const tweakedKey = (0, bip341_1.tweakKey)(o.internalPubkey, o.hash);
      if (tweakedKey) return tweakedKey.x;
    }
  });
  lazy.prop(o, 'internalPubkey', () => {
    if (a.internalPubkey) return a.internalPubkey;
    const witness = _witness();
    if (witness && witness.length > 1)
      return witness[witness.length - 1].slice(1, 33);
  });
  lazy.prop(o, 'signature', () => {
    if (a.signature) return a.signature;
    const witness = _witness(); // witness without annex
    if (!witness || witness.length !== 1) return;
    return witness[0];
  });
  lazy.prop(o, 'witness', () => {
    if (a.witness) return a.witness;
    const hashTree = _hashTree();
    if (hashTree && a.redeem && a.redeem.output && a.internalPubkey) {
      const leafHash = (0, bip341_1.tapleafHash)({
        output: a.redeem.output,
        version: o.redeemVersion,
      });
      const path = (0, bip341_1.findScriptPath)(hashTree, leafHash);
      if (!path) return;
      const outputKey = (0, bip341_1.tweakKey)(a.internalPubkey, hashTree.hash);
      if (!outputKey) return;
      const controlBock = buffer_1.Buffer.concat(
        [
          buffer_1.Buffer.from([o.redeemVersion | outputKey.parity]),
          a.internalPubkey,
        ].concat(path),
      );
      return [a.redeem.output, controlBock];
    }
    if (a.signature) return [a.signature];
  });
  // extended validation
  if (opts.validate) {
    let pubkey = buffer_1.Buffer.from([]);
    if (a.address) {
      if (network && network.bech32 !== _address().prefix)
        throw new TypeError('Invalid prefix or Network mismatch');
      if (_address().version !== TAPROOT_WITNESS_VERSION)
        throw new TypeError('Invalid address version');
      if (_address().data.length !== 32)
        throw new TypeError('Invalid address data');
      pubkey = _address().data;
    }
    if (a.pubkey) {
      if (pubkey.length > 0 && !pubkey.equals(a.pubkey))
        throw new TypeError('Pubkey mismatch');
      else pubkey = a.pubkey;
    }
    if (a.output) {
      if (
        a.output.length !== 34 ||
        a.output[0] !== OPS.OP_1 ||
        a.output[1] !== 0x20
      )
        throw new TypeError('Output is invalid');
      if (pubkey.length > 0 && !pubkey.equals(a.output.slice(2)))
        throw new TypeError('Pubkey mismatch');
      else pubkey = a.output.slice(2);
    }
    if (a.internalPubkey) {
      const tweakedKey = (0, bip341_1.tweakKey)(a.internalPubkey, o.hash);
      if (pubkey.length > 0 && !pubkey.equals(tweakedKey.x))
        throw new TypeError('Pubkey mismatch');
      else pubkey = tweakedKey.x;
    }
    if (pubkey && pubkey.length) {
      if (!(0, ecc_lib_1.getEccLib)().isXOnlyPoint(pubkey))
        throw new TypeError('Invalid pubkey for p2tr');
    }
    const hashTree = _hashTree();
    if (a.hash && hashTree) {
      if (!a.hash.equals(hashTree.hash)) throw new TypeError('Hash mismatch');
    }
    if (a.redeem && a.redeem.output && hashTree) {
      const leafHash = (0, bip341_1.tapleafHash)({
        output: a.redeem.output,
        version: o.redeemVersion,
      });
      if (!(0, bip341_1.findScriptPath)(hashTree, leafHash))
        throw new TypeError('Redeem script not in tree');
    }
    const witness = _witness();
    // compare the provided redeem data with the one computed from witness
    if (a.redeem && o.redeem) {
      if (a.redeem.redeemVersion) {
        if (a.redeem.redeemVersion !== o.redeem.redeemVersion)
          throw new TypeError('Redeem.redeemVersion and witness mismatch');
      }
      if (a.redeem.output) {
        if (bscript.decompile(a.redeem.output).length === 0)
          throw new TypeError('Redeem.output is invalid');
        // output redeem is constructed from the witness
        if (o.redeem.output && !a.redeem.output.equals(o.redeem.output))
          throw new TypeError('Redeem.output and witness mismatch');
      }
      if (a.redeem.witness) {
        if (
          o.redeem.witness &&
          !stacksEqual(a.redeem.witness, o.redeem.witness)
        )
          throw new TypeError('Redeem.witness and witness mismatch');
      }
    }
    if (witness && witness.length) {
      if (witness.length === 1) {
        // key spending
        if (a.signature && !a.signature.equals(witness[0]))
          throw new TypeError('Signature mismatch');
      } else {
        // script path spending
        const controlBlock = witness[witness.length - 1];
        if (controlBlock.length < 33)
          throw new TypeError(
            `The control-block length is too small. Got ${controlBlock.length}, expected min 33.`,
          );
        if ((controlBlock.length - 33) % 32 !== 0)
          throw new TypeError(
            `The control-block length of ${controlBlock.length} is incorrect!`,
          );
        const m = (controlBlock.length - 33) / 32;
        if (m > 128)
          throw new TypeError(
            `The script path is too long. Got ${m}, expected max 128.`,
          );
        const internalPubkey = controlBlock.slice(1, 33);
        if (a.internalPubkey && !a.internalPubkey.equals(internalPubkey))
          throw new TypeError('Internal pubkey mismatch');
        if (!(0, ecc_lib_1.getEccLib)().isXOnlyPoint(internalPubkey))
          throw new TypeError('Invalid internalPubkey for p2tr witness');
        const leafVersion = controlBlock[0] & types_1.TAPLEAF_VERSION_MASK;
        const script = witness[witness.length - 2];
        const leafHash = (0, bip341_1.tapleafHash)({
          output: script,
          version: leafVersion,
        });
        const hash = (0, bip341_1.rootHashFromPath)(controlBlock, leafHash);
        const outputKey = (0, bip341_1.tweakKey)(internalPubkey, hash);
        if (!outputKey)
          // todo: needs test data
          throw new TypeError('Invalid outputKey for p2tr witness');
        if (pubkey.length && !pubkey.equals(outputKey.x))
          throw new TypeError('Pubkey mismatch for p2tr witness');
        if (outputKey.parity !== (controlBlock[0] & 1))
          throw new Error('Incorrect parity');
      }
    }
  }
  return Object.assign(o, a);
}
exports.p2tr = p2tr;
function stacksEqual(a, b) {
  if (a.length !== b.length) return false;
  return a.every((x, i) => {
    return x.equals(b[i]);
  });
}

},{"../ecc_lib":65,"../networks":68,"../script":85,"../types":89,"./bip341":70,"./lazy":73,"bech32":13,"buffer":97}],79:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.p2wpkh = void 0;
const bcrypto = require('../crypto');
const networks_1 = require('../networks');
const bscript = require('../script');
const types_1 = require('../types');
const lazy = require('./lazy');
const bech32_1 = require('bech32');
const OPS = bscript.OPS;
const EMPTY_BUFFER = Buffer.alloc(0);
// witness: {signature} {pubKey}
// input: <>
// output: OP_0 {pubKeyHash}
function p2wpkh(a, opts) {
  if (!a.address && !a.hash && !a.output && !a.pubkey && !a.witness)
    throw new TypeError('Not enough data');
  opts = Object.assign({ validate: true }, opts || {});
  (0, types_1.typeforce)(
    {
      address: types_1.typeforce.maybe(types_1.typeforce.String),
      hash: types_1.typeforce.maybe(types_1.typeforce.BufferN(20)),
      input: types_1.typeforce.maybe(types_1.typeforce.BufferN(0)),
      network: types_1.typeforce.maybe(types_1.typeforce.Object),
      output: types_1.typeforce.maybe(types_1.typeforce.BufferN(22)),
      pubkey: types_1.typeforce.maybe(types_1.isPoint),
      signature: types_1.typeforce.maybe(bscript.isCanonicalScriptSignature),
      witness: types_1.typeforce.maybe(
        types_1.typeforce.arrayOf(types_1.typeforce.Buffer),
      ),
    },
    a,
  );
  const _address = lazy.value(() => {
    const result = bech32_1.bech32.decode(a.address);
    const version = result.words.shift();
    const data = bech32_1.bech32.fromWords(result.words);
    return {
      version,
      prefix: result.prefix,
      data: Buffer.from(data),
    };
  });
  const network = a.network || networks_1.bitcoin;
  const o = { name: 'p2wpkh', network };
  lazy.prop(o, 'address', () => {
    if (!o.hash) return;
    const words = bech32_1.bech32.toWords(o.hash);
    words.unshift(0x00);
    return bech32_1.bech32.encode(network.bech32, words);
  });
  lazy.prop(o, 'hash', () => {
    if (a.output) return a.output.slice(2, 22);
    if (a.address) return _address().data;
    if (a.pubkey || o.pubkey) return bcrypto.hash160(a.pubkey || o.pubkey);
  });
  lazy.prop(o, 'output', () => {
    if (!o.hash) return;
    return bscript.compile([OPS.OP_0, o.hash]);
  });
  lazy.prop(o, 'pubkey', () => {
    if (a.pubkey) return a.pubkey;
    if (!a.witness) return;
    return a.witness[1];
  });
  lazy.prop(o, 'signature', () => {
    if (!a.witness) return;
    return a.witness[0];
  });
  lazy.prop(o, 'input', () => {
    if (!o.witness) return;
    return EMPTY_BUFFER;
  });
  lazy.prop(o, 'witness', () => {
    if (!a.pubkey) return;
    if (!a.signature) return;
    return [a.signature, a.pubkey];
  });
  // extended validation
  if (opts.validate) {
    let hash = Buffer.from([]);
    if (a.address) {
      if (network && network.bech32 !== _address().prefix)
        throw new TypeError('Invalid prefix or Network mismatch');
      if (_address().version !== 0x00)
        throw new TypeError('Invalid address version');
      if (_address().data.length !== 20)
        throw new TypeError('Invalid address data');
      hash = _address().data;
    }
    if (a.hash) {
      if (hash.length > 0 && !hash.equals(a.hash))
        throw new TypeError('Hash mismatch');
      else hash = a.hash;
    }
    if (a.output) {
      if (
        a.output.length !== 22 ||
        a.output[0] !== OPS.OP_0 ||
        a.output[1] !== 0x14
      )
        throw new TypeError('Output is invalid');
      if (hash.length > 0 && !hash.equals(a.output.slice(2)))
        throw new TypeError('Hash mismatch');
      else hash = a.output.slice(2);
    }
    if (a.pubkey) {
      const pkh = bcrypto.hash160(a.pubkey);
      if (hash.length > 0 && !hash.equals(pkh))
        throw new TypeError('Hash mismatch');
      else hash = pkh;
      if (!(0, types_1.isPoint)(a.pubkey) || a.pubkey.length !== 33)
        throw new TypeError('Invalid pubkey for p2wpkh');
    }
    if (a.witness) {
      if (a.witness.length !== 2) throw new TypeError('Witness is invalid');
      if (!bscript.isCanonicalScriptSignature(a.witness[0]))
        throw new TypeError('Witness has invalid signature');
      if (!(0, types_1.isPoint)(a.witness[1]) || a.witness[1].length !== 33)
        throw new TypeError('Witness has invalid pubkey');
      if (a.signature && !a.signature.equals(a.witness[0]))
        throw new TypeError('Signature mismatch');
      if (a.pubkey && !a.pubkey.equals(a.witness[1]))
        throw new TypeError('Pubkey mismatch');
      const pkh = bcrypto.hash160(a.witness[1]);
      if (hash.length > 0 && !hash.equals(pkh))
        throw new TypeError('Hash mismatch');
    }
  }
  return Object.assign(o, a);
}
exports.p2wpkh = p2wpkh;

}).call(this)}).call(this,require("buffer").Buffer)
},{"../crypto":64,"../networks":68,"../script":85,"../types":89,"./lazy":73,"bech32":13,"buffer":97}],80:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.p2wsh = void 0;
const bcrypto = require('../crypto');
const networks_1 = require('../networks');
const bscript = require('../script');
const types_1 = require('../types');
const lazy = require('./lazy');
const bech32_1 = require('bech32');
const OPS = bscript.OPS;
const EMPTY_BUFFER = Buffer.alloc(0);
function stacksEqual(a, b) {
  if (a.length !== b.length) return false;
  return a.every((x, i) => {
    return x.equals(b[i]);
  });
}
function chunkHasUncompressedPubkey(chunk) {
  if (
    Buffer.isBuffer(chunk) &&
    chunk.length === 65 &&
    chunk[0] === 0x04 &&
    (0, types_1.isPoint)(chunk)
  ) {
    return true;
  } else {
    return false;
  }
}
// input: <>
// witness: [redeemScriptSig ...] {redeemScript}
// output: OP_0 {sha256(redeemScript)}
function p2wsh(a, opts) {
  if (!a.address && !a.hash && !a.output && !a.redeem && !a.witness)
    throw new TypeError('Not enough data');
  opts = Object.assign({ validate: true }, opts || {});
  (0, types_1.typeforce)(
    {
      network: types_1.typeforce.maybe(types_1.typeforce.Object),
      address: types_1.typeforce.maybe(types_1.typeforce.String),
      hash: types_1.typeforce.maybe(types_1.typeforce.BufferN(32)),
      output: types_1.typeforce.maybe(types_1.typeforce.BufferN(34)),
      redeem: types_1.typeforce.maybe({
        input: types_1.typeforce.maybe(types_1.typeforce.Buffer),
        network: types_1.typeforce.maybe(types_1.typeforce.Object),
        output: types_1.typeforce.maybe(types_1.typeforce.Buffer),
        witness: types_1.typeforce.maybe(
          types_1.typeforce.arrayOf(types_1.typeforce.Buffer),
        ),
      }),
      input: types_1.typeforce.maybe(types_1.typeforce.BufferN(0)),
      witness: types_1.typeforce.maybe(
        types_1.typeforce.arrayOf(types_1.typeforce.Buffer),
      ),
    },
    a,
  );
  const _address = lazy.value(() => {
    const result = bech32_1.bech32.decode(a.address);
    const version = result.words.shift();
    const data = bech32_1.bech32.fromWords(result.words);
    return {
      version,
      prefix: result.prefix,
      data: Buffer.from(data),
    };
  });
  const _rchunks = lazy.value(() => {
    return bscript.decompile(a.redeem.input);
  });
  let network = a.network;
  if (!network) {
    network = (a.redeem && a.redeem.network) || networks_1.bitcoin;
  }
  const o = { network };
  lazy.prop(o, 'address', () => {
    if (!o.hash) return;
    const words = bech32_1.bech32.toWords(o.hash);
    words.unshift(0x00);
    return bech32_1.bech32.encode(network.bech32, words);
  });
  lazy.prop(o, 'hash', () => {
    if (a.output) return a.output.slice(2);
    if (a.address) return _address().data;
    if (o.redeem && o.redeem.output) return bcrypto.sha256(o.redeem.output);
  });
  lazy.prop(o, 'output', () => {
    if (!o.hash) return;
    return bscript.compile([OPS.OP_0, o.hash]);
  });
  lazy.prop(o, 'redeem', () => {
    if (!a.witness) return;
    return {
      output: a.witness[a.witness.length - 1],
      input: EMPTY_BUFFER,
      witness: a.witness.slice(0, -1),
    };
  });
  lazy.prop(o, 'input', () => {
    if (!o.witness) return;
    return EMPTY_BUFFER;
  });
  lazy.prop(o, 'witness', () => {
    // transform redeem input to witness stack?
    if (
      a.redeem &&
      a.redeem.input &&
      a.redeem.input.length > 0 &&
      a.redeem.output &&
      a.redeem.output.length > 0
    ) {
      const stack = bscript.toStack(_rchunks());
      // assign, and blank the existing input
      o.redeem = Object.assign({ witness: stack }, a.redeem);
      o.redeem.input = EMPTY_BUFFER;
      return [].concat(stack, a.redeem.output);
    }
    if (!a.redeem) return;
    if (!a.redeem.output) return;
    if (!a.redeem.witness) return;
    return [].concat(a.redeem.witness, a.redeem.output);
  });
  lazy.prop(o, 'name', () => {
    const nameParts = ['p2wsh'];
    if (o.redeem !== undefined && o.redeem.name !== undefined)
      nameParts.push(o.redeem.name);
    return nameParts.join('-');
  });
  // extended validation
  if (opts.validate) {
    let hash = Buffer.from([]);
    if (a.address) {
      if (_address().prefix !== network.bech32)
        throw new TypeError('Invalid prefix or Network mismatch');
      if (_address().version !== 0x00)
        throw new TypeError('Invalid address version');
      if (_address().data.length !== 32)
        throw new TypeError('Invalid address data');
      hash = _address().data;
    }
    if (a.hash) {
      if (hash.length > 0 && !hash.equals(a.hash))
        throw new TypeError('Hash mismatch');
      else hash = a.hash;
    }
    if (a.output) {
      if (
        a.output.length !== 34 ||
        a.output[0] !== OPS.OP_0 ||
        a.output[1] !== 0x20
      )
        throw new TypeError('Output is invalid');
      const hash2 = a.output.slice(2);
      if (hash.length > 0 && !hash.equals(hash2))
        throw new TypeError('Hash mismatch');
      else hash = hash2;
    }
    if (a.redeem) {
      if (a.redeem.network && a.redeem.network !== network)
        throw new TypeError('Network mismatch');
      // is there two redeem sources?
      if (
        a.redeem.input &&
        a.redeem.input.length > 0 &&
        a.redeem.witness &&
        a.redeem.witness.length > 0
      )
        throw new TypeError('Ambiguous witness source');
      // is the redeem output non-empty/valid?
      if (a.redeem.output) {
        const decompile = bscript.decompile(a.redeem.output);
        if (!decompile || decompile.length < 1)
          throw new TypeError('Redeem.output is invalid');
        if (a.redeem.output.byteLength > 3600)
          throw new TypeError(
            'Redeem.output unspendable if larger than 3600 bytes',
          );
        if (bscript.countNonPushOnlyOPs(decompile) > 201)
          throw new TypeError(
            'Redeem.output unspendable with more than 201 non-push ops',
          );
        // match hash against other sources
        const hash2 = bcrypto.sha256(a.redeem.output);
        if (hash.length > 0 && !hash.equals(hash2))
          throw new TypeError('Hash mismatch');
        else hash = hash2;
      }
      if (a.redeem.input && !bscript.isPushOnly(_rchunks()))
        throw new TypeError('Non push-only scriptSig');
      if (
        a.witness &&
        a.redeem.witness &&
        !stacksEqual(a.witness, a.redeem.witness)
      )
        throw new TypeError('Witness and redeem.witness mismatch');
      if (
        (a.redeem.input && _rchunks().some(chunkHasUncompressedPubkey)) ||
        (a.redeem.output &&
          (bscript.decompile(a.redeem.output) || []).some(
            chunkHasUncompressedPubkey,
          ))
      ) {
        throw new TypeError(
          'redeem.input or redeem.output contains uncompressed pubkey',
        );
      }
    }
    if (a.witness && a.witness.length > 0) {
      const wScript = a.witness[a.witness.length - 1];
      if (a.redeem && a.redeem.output && !a.redeem.output.equals(wScript))
        throw new TypeError('Witness and redeem.output mismatch');
      if (
        a.witness.some(chunkHasUncompressedPubkey) ||
        (bscript.decompile(wScript) || []).some(chunkHasUncompressedPubkey)
      )
        throw new TypeError('Witness contains uncompressed pubkey');
    }
  }
  return Object.assign(o, a);
}
exports.p2wsh = p2wsh;

}).call(this)}).call(this,require("buffer").Buffer)
},{"../crypto":64,"../networks":68,"../script":85,"../types":89,"./lazy":73,"bech32":13,"buffer":97}],81:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.Psbt = void 0;
const bip174_1 = require('bip174');
const varuint = require('bip174/src/lib/converter/varint');
const utils_1 = require('bip174/src/lib/utils');
const address_1 = require('./address');
const bufferutils_1 = require('./bufferutils');
const networks_1 = require('./networks');
const payments = require('./payments');
const bip341_1 = require('./payments/bip341');
const bscript = require('./script');
const transaction_1 = require('./transaction');
const bip371_1 = require('./psbt/bip371');
const psbtutils_1 = require('./psbt/psbtutils');
/**
 * These are the default arguments for a Psbt instance.
 */
const DEFAULT_OPTS = {
  /**
   * A bitcoinjs Network object. This is only used if you pass an `address`
   * parameter to addOutput. Otherwise it is not needed and can be left default.
   */
  network: networks_1.bitcoin,
  /**
   * When extractTransaction is called, the fee rate is checked.
   * THIS IS NOT TO BE RELIED ON.
   * It is only here as a last ditch effort to prevent sending a 500 BTC fee etc.
   */
  maximumFeeRate: 5000, // satoshi per byte
};
/**
 * Psbt class can parse and generate a PSBT binary based off of the BIP174.
 * There are 6 roles that this class fulfills. (Explained in BIP174)
 *
 * Creator: This can be done with `new Psbt()`
 * Updater: This can be done with `psbt.addInput(input)`, `psbt.addInputs(inputs)`,
 *   `psbt.addOutput(output)`, `psbt.addOutputs(outputs)` when you are looking to
 *   add new inputs and outputs to the PSBT, and `psbt.updateGlobal(itemObject)`,
 *   `psbt.updateInput(itemObject)`, `psbt.updateOutput(itemObject)`
 *   addInput requires hash: Buffer | string; and index: number; as attributes
 *   and can also include any attributes that are used in updateInput method.
 *   addOutput requires script: Buffer; and value: number; and likewise can include
 *   data for updateOutput.
 *   For a list of what attributes should be what types. Check the bip174 library.
 *   Also, check the integration tests for some examples of usage.
 * Signer: There are a few methods. signAllInputs and signAllInputsAsync, which will search all input
 *   information for your pubkey or pubkeyhash, and only sign inputs where it finds
 *   your info. Or you can explicitly sign a specific input with signInput and
 *   signInputAsync. For the async methods you can create a SignerAsync object
 *   and use something like a hardware wallet to sign with. (You must implement this)
 * Combiner: psbts can be combined easily with `psbt.combine(psbt2, psbt3, psbt4 ...)`
 *   the psbt calling combine will always have precedence when a conflict occurs.
 *   Combine checks if the internal bitcoin transaction is the same, so be sure that
 *   all sequences, version, locktime, etc. are the same before combining.
 * Input Finalizer: This role is fairly important. Not only does it need to construct
 *   the input scriptSigs and witnesses, but it SHOULD verify the signatures etc.
 *   Before running `psbt.finalizeAllInputs()` please run `psbt.validateSignaturesOfAllInputs()`
 *   Running any finalize method will delete any data in the input(s) that are no longer
 *   needed due to the finalized scripts containing the information.
 * Transaction Extractor: This role will perform some checks before returning a
 *   Transaction object. Such as fee rate not being larger than maximumFeeRate etc.
 */
class Psbt {
  static fromBase64(data, opts = {}) {
    const buffer = Buffer.from(data, 'base64');
    return this.fromBuffer(buffer, opts);
  }
  static fromHex(data, opts = {}) {
    const buffer = Buffer.from(data, 'hex');
    return this.fromBuffer(buffer, opts);
  }
  static fromBuffer(buffer, opts = {}) {
    const psbtBase = bip174_1.Psbt.fromBuffer(buffer, transactionFromBuffer);
    const psbt = new Psbt(opts, psbtBase);
    checkTxForDupeIns(psbt.__CACHE.__TX, psbt.__CACHE);
    return psbt;
  }
  constructor(opts = {}, data = new bip174_1.Psbt(new PsbtTransaction())) {
    this.data = data;
    // set defaults
    this.opts = Object.assign({}, DEFAULT_OPTS, opts);
    this.__CACHE = {
      __NON_WITNESS_UTXO_TX_CACHE: [],
      __NON_WITNESS_UTXO_BUF_CACHE: [],
      __TX_IN_CACHE: {},
      __TX: this.data.globalMap.unsignedTx.tx,
      // Psbt's predecesor (TransactionBuilder - now removed) behavior
      // was to not confirm input values  before signing.
      // Even though we highly encourage people to get
      // the full parent transaction to verify values, the ability to
      // sign non-segwit inputs without the full transaction was often
      // requested. So the only way to activate is to use @ts-ignore.
      // We will disable exporting the Psbt when unsafe sign is active.
      // because it is not BIP174 compliant.
      __UNSAFE_SIGN_NONSEGWIT: false,
    };
    if (this.data.inputs.length === 0) this.setVersion(2);
    // Make data hidden when enumerating
    const dpew = (obj, attr, enumerable, writable) =>
      Object.defineProperty(obj, attr, {
        enumerable,
        writable,
      });
    dpew(this, '__CACHE', false, true);
    dpew(this, 'opts', false, true);
  }
  get inputCount() {
    return this.data.inputs.length;
  }
  get version() {
    return this.__CACHE.__TX.version;
  }
  set version(version) {
    this.setVersion(version);
  }
  get locktime() {
    return this.__CACHE.__TX.locktime;
  }
  set locktime(locktime) {
    this.setLocktime(locktime);
  }
  get txInputs() {
    return this.__CACHE.__TX.ins.map(input => ({
      hash: (0, bufferutils_1.cloneBuffer)(input.hash),
      index: input.index,
      sequence: input.sequence,
    }));
  }
  get txOutputs() {
    return this.__CACHE.__TX.outs.map(output => {
      let address;
      try {
        address = (0, address_1.fromOutputScript)(
          output.script,
          this.opts.network,
        );
      } catch (_) {}
      return {
        script: (0, bufferutils_1.cloneBuffer)(output.script),
        value: output.value,
        address,
      };
    });
  }
  combine(...those) {
    this.data.combine(...those.map(o => o.data));
    return this;
  }
  clone() {
    // TODO: more efficient cloning
    const res = Psbt.fromBuffer(this.data.toBuffer());
    res.opts = JSON.parse(JSON.stringify(this.opts));
    return res;
  }
  setMaximumFeeRate(satoshiPerByte) {
    check32Bit(satoshiPerByte); // 42.9 BTC per byte IS excessive... so throw
    this.opts.maximumFeeRate = satoshiPerByte;
  }
  setVersion(version) {
    check32Bit(version);
    checkInputsForPartialSig(this.data.inputs, 'setVersion');
    const c = this.__CACHE;
    c.__TX.version = version;
    c.__EXTRACTED_TX = undefined;
    return this;
  }
  setLocktime(locktime) {
    check32Bit(locktime);
    checkInputsForPartialSig(this.data.inputs, 'setLocktime');
    const c = this.__CACHE;
    c.__TX.locktime = locktime;
    c.__EXTRACTED_TX = undefined;
    return this;
  }
  setInputSequence(inputIndex, sequence) {
    check32Bit(sequence);
    checkInputsForPartialSig(this.data.inputs, 'setInputSequence');
    const c = this.__CACHE;
    if (c.__TX.ins.length <= inputIndex) {
      throw new Error('Input index too high');
    }
    c.__TX.ins[inputIndex].sequence = sequence;
    c.__EXTRACTED_TX = undefined;
    return this;
  }
  addInputs(inputDatas) {
    inputDatas.forEach(inputData => this.addInput(inputData));
    return this;
  }
  addInput(inputData) {
    if (
      arguments.length > 1 ||
      !inputData ||
      inputData.hash === undefined ||
      inputData.index === undefined
    ) {
      throw new Error(
        `Invalid arguments for Psbt.addInput. ` +
          `Requires single object with at least [hash] and [index]`,
      );
    }
    (0, bip371_1.checkTaprootInputFields)(inputData, inputData, 'addInput');
    checkInputsForPartialSig(this.data.inputs, 'addInput');
    if (inputData.witnessScript) checkInvalidP2WSH(inputData.witnessScript);
    const c = this.__CACHE;
    this.data.addInput(inputData);
    const txIn = c.__TX.ins[c.__TX.ins.length - 1];
    checkTxInputCache(c, txIn);
    const inputIndex = this.data.inputs.length - 1;
    const input = this.data.inputs[inputIndex];
    if (input.nonWitnessUtxo) {
      addNonWitnessTxCache(this.__CACHE, input, inputIndex);
    }
    c.__FEE = undefined;
    c.__FEE_RATE = undefined;
    c.__EXTRACTED_TX = undefined;
    return this;
  }
  addOutputs(outputDatas) {
    outputDatas.forEach(outputData => this.addOutput(outputData));
    return this;
  }
  addOutput(outputData) {
    if (
      arguments.length > 1 ||
      !outputData ||
      outputData.value === undefined ||
      (outputData.address === undefined && outputData.script === undefined)
    ) {
      throw new Error(
        `Invalid arguments for Psbt.addOutput. ` +
          `Requires single object with at least [script or address] and [value]`,
      );
    }
    checkInputsForPartialSig(this.data.inputs, 'addOutput');
    const { address } = outputData;
    if (typeof address === 'string') {
      const { network } = this.opts;
      const script = (0, address_1.toOutputScript)(address, network);
      outputData = Object.assign(outputData, { script });
    }
    (0, bip371_1.checkTaprootOutputFields)(outputData, outputData, 'addOutput');
    const c = this.__CACHE;
    this.data.addOutput(outputData);
    c.__FEE = undefined;
    c.__FEE_RATE = undefined;
    c.__EXTRACTED_TX = undefined;
    return this;
  }
  extractTransaction(disableFeeCheck) {
    if (!this.data.inputs.every(isFinalized)) throw new Error('Not finalized');
    const c = this.__CACHE;
    if (!disableFeeCheck) {
      checkFees(this, c, this.opts);
    }
    if (c.__EXTRACTED_TX) return c.__EXTRACTED_TX;
    const tx = c.__TX.clone();
    inputFinalizeGetAmts(this.data.inputs, tx, c, true);
    return tx;
  }
  getFeeRate() {
    return getTxCacheValue(
      '__FEE_RATE',
      'fee rate',
      this.data.inputs,
      this.__CACHE,
    );
  }
  getFee() {
    return getTxCacheValue('__FEE', 'fee', this.data.inputs, this.__CACHE);
  }
  finalizeAllInputs() {
    (0, utils_1.checkForInput)(this.data.inputs, 0); // making sure we have at least one
    range(this.data.inputs.length).forEach(idx => this.finalizeInput(idx));
    return this;
  }
  finalizeInput(inputIndex, finalScriptsFunc) {
    const input = (0, utils_1.checkForInput)(this.data.inputs, inputIndex);
    if ((0, bip371_1.isTaprootInput)(input))
      return this._finalizeTaprootInput(
        inputIndex,
        input,
        undefined,
        finalScriptsFunc,
      );
    return this._finalizeInput(inputIndex, input, finalScriptsFunc);
  }
  finalizeTaprootInput(
    inputIndex,
    tapLeafHashToFinalize,
    finalScriptsFunc = bip371_1.tapScriptFinalizer,
  ) {
    const input = (0, utils_1.checkForInput)(this.data.inputs, inputIndex);
    if ((0, bip371_1.isTaprootInput)(input))
      return this._finalizeTaprootInput(
        inputIndex,
        input,
        tapLeafHashToFinalize,
        finalScriptsFunc,
      );
    throw new Error(`Cannot finalize input #${inputIndex}. Not Taproot.`);
  }
  _finalizeInput(inputIndex, input, finalScriptsFunc = getFinalScripts) {
    const { script, isP2SH, isP2WSH, isSegwit } = getScriptFromInput(
      inputIndex,
      input,
      this.__CACHE,
    );
    if (!script) throw new Error(`No script found for input #${inputIndex}`);
    checkPartialSigSighashes(input);
    const { finalScriptSig, finalScriptWitness } = finalScriptsFunc(
      inputIndex,
      input,
      script,
      isSegwit,
      isP2SH,
      isP2WSH,
    );
    if (finalScriptSig) this.data.updateInput(inputIndex, { finalScriptSig });
    if (finalScriptWitness)
      this.data.updateInput(inputIndex, { finalScriptWitness });
    if (!finalScriptSig && !finalScriptWitness)
      throw new Error(`Unknown error finalizing input #${inputIndex}`);
    this.data.clearFinalizedInput(inputIndex);
    return this;
  }
  _finalizeTaprootInput(
    inputIndex,
    input,
    tapLeafHashToFinalize,
    finalScriptsFunc = bip371_1.tapScriptFinalizer,
  ) {
    if (!input.witnessUtxo)
      throw new Error(
        `Cannot finalize input #${inputIndex}. Missing withness utxo.`,
      );
    // Check key spend first. Increased privacy and reduced block space.
    if (input.tapKeySig) {
      const payment = payments.p2tr({
        output: input.witnessUtxo.script,
        signature: input.tapKeySig,
      });
      const finalScriptWitness = (0, psbtutils_1.witnessStackToScriptWitness)(
        payment.witness,
      );
      this.data.updateInput(inputIndex, { finalScriptWitness });
    } else {
      const { finalScriptWitness } = finalScriptsFunc(
        inputIndex,
        input,
        tapLeafHashToFinalize,
      );
      this.data.updateInput(inputIndex, { finalScriptWitness });
    }
    this.data.clearFinalizedInput(inputIndex);
    return this;
  }
  getInputType(inputIndex) {
    const input = (0, utils_1.checkForInput)(this.data.inputs, inputIndex);
    const script = getScriptFromUtxo(inputIndex, input, this.__CACHE);
    const result = getMeaningfulScript(
      script,
      inputIndex,
      'input',
      input.redeemScript || redeemFromFinalScriptSig(input.finalScriptSig),
      input.witnessScript ||
        redeemFromFinalWitnessScript(input.finalScriptWitness),
    );
    const type = result.type === 'raw' ? '' : result.type + '-';
    const mainType = classifyScript(result.meaningfulScript);
    return type + mainType;
  }
  inputHasPubkey(inputIndex, pubkey) {
    const input = (0, utils_1.checkForInput)(this.data.inputs, inputIndex);
    return pubkeyInInput(pubkey, input, inputIndex, this.__CACHE);
  }
  inputHasHDKey(inputIndex, root) {
    const input = (0, utils_1.checkForInput)(this.data.inputs, inputIndex);
    const derivationIsMine = bip32DerivationIsMine(root);
    return (
      !!input.bip32Derivation && input.bip32Derivation.some(derivationIsMine)
    );
  }
  outputHasPubkey(outputIndex, pubkey) {
    const output = (0, utils_1.checkForOutput)(this.data.outputs, outputIndex);
    return pubkeyInOutput(pubkey, output, outputIndex, this.__CACHE);
  }
  outputHasHDKey(outputIndex, root) {
    const output = (0, utils_1.checkForOutput)(this.data.outputs, outputIndex);
    const derivationIsMine = bip32DerivationIsMine(root);
    return (
      !!output.bip32Derivation && output.bip32Derivation.some(derivationIsMine)
    );
  }
  validateSignaturesOfAllInputs(validator) {
    (0, utils_1.checkForInput)(this.data.inputs, 0); // making sure we have at least one
    const results = range(this.data.inputs.length).map(idx =>
      this.validateSignaturesOfInput(idx, validator),
    );
    return results.reduce((final, res) => res === true && final, true);
  }
  validateSignaturesOfInput(inputIndex, validator, pubkey) {
    const input = this.data.inputs[inputIndex];
    if ((0, bip371_1.isTaprootInput)(input))
      return this.validateSignaturesOfTaprootInput(
        inputIndex,
        validator,
        pubkey,
      );
    return this._validateSignaturesOfInput(inputIndex, validator, pubkey);
  }
  _validateSignaturesOfInput(inputIndex, validator, pubkey) {
    const input = this.data.inputs[inputIndex];
    const partialSig = (input || {}).partialSig;
    if (!input || !partialSig || partialSig.length < 1)
      throw new Error('No signatures to validate');
    if (typeof validator !== 'function')
      throw new Error('Need validator function to validate signatures');
    const mySigs = pubkey
      ? partialSig.filter(sig => sig.pubkey.equals(pubkey))
      : partialSig;
    if (mySigs.length < 1) throw new Error('No signatures for this pubkey');
    const results = [];
    let hashCache;
    let scriptCache;
    let sighashCache;
    for (const pSig of mySigs) {
      const sig = bscript.signature.decode(pSig.signature);
      const { hash, script } =
        sighashCache !== sig.hashType
          ? getHashForSig(
              inputIndex,
              Object.assign({}, input, { sighashType: sig.hashType }),
              this.__CACHE,
              true,
            )
          : { hash: hashCache, script: scriptCache };
      sighashCache = sig.hashType;
      hashCache = hash;
      scriptCache = script;
      checkScriptForPubkey(pSig.pubkey, script, 'verify');
      results.push(validator(pSig.pubkey, hash, sig.signature));
    }
    return results.every(res => res === true);
  }
  validateSignaturesOfTaprootInput(inputIndex, validator, pubkey) {
    const input = this.data.inputs[inputIndex];
    const tapKeySig = (input || {}).tapKeySig;
    const tapScriptSig = (input || {}).tapScriptSig;
    if (!input && !tapKeySig && !(tapScriptSig && !tapScriptSig.length))
      throw new Error('No signatures to validate');
    if (typeof validator !== 'function')
      throw new Error('Need validator function to validate signatures');
    pubkey = pubkey && (0, bip371_1.toXOnly)(pubkey);
    const allHashses = pubkey
      ? getTaprootHashesForSig(
          inputIndex,
          input,
          this.data.inputs,
          pubkey,
          this.__CACHE,
        )
      : getAllTaprootHashesForSig(
          inputIndex,
          input,
          this.data.inputs,
          this.__CACHE,
        );
    if (!allHashses.length) throw new Error('No signatures for this pubkey');
    const tapKeyHash = allHashses.find(h => !h.leafHash);
    let validationResultCount = 0;
    if (tapKeySig && tapKeyHash) {
      const isValidTapkeySig = validator(
        tapKeyHash.pubkey,
        tapKeyHash.hash,
        trimTaprootSig(tapKeySig),
      );
      if (!isValidTapkeySig) return false;
      validationResultCount++;
    }
    if (tapScriptSig) {
      for (const tapSig of tapScriptSig) {
        const tapSigHash = allHashses.find(h => tapSig.pubkey.equals(h.pubkey));
        if (tapSigHash) {
          const isValidTapScriptSig = validator(
            tapSig.pubkey,
            tapSigHash.hash,
            trimTaprootSig(tapSig.signature),
          );
          if (!isValidTapScriptSig) return false;
          validationResultCount++;
        }
      }
    }
    return validationResultCount > 0;
  }
  signAllInputsHD(
    hdKeyPair,
    sighashTypes = [transaction_1.Transaction.SIGHASH_ALL],
  ) {
    if (!hdKeyPair || !hdKeyPair.publicKey || !hdKeyPair.fingerprint) {
      throw new Error('Need HDSigner to sign input');
    }
    const results = [];
    for (const i of range(this.data.inputs.length)) {
      try {
        this.signInputHD(i, hdKeyPair, sighashTypes);
        results.push(true);
      } catch (err) {
        results.push(false);
      }
    }
    if (results.every(v => v === false)) {
      throw new Error('No inputs were signed');
    }
    return this;
  }
  signAllInputsHDAsync(
    hdKeyPair,
    sighashTypes = [transaction_1.Transaction.SIGHASH_ALL],
  ) {
    return new Promise((resolve, reject) => {
      if (!hdKeyPair || !hdKeyPair.publicKey || !hdKeyPair.fingerprint) {
        return reject(new Error('Need HDSigner to sign input'));
      }
      const results = [];
      const promises = [];
      for (const i of range(this.data.inputs.length)) {
        promises.push(
          this.signInputHDAsync(i, hdKeyPair, sighashTypes).then(
            () => {
              results.push(true);
            },
            () => {
              results.push(false);
            },
          ),
        );
      }
      return Promise.all(promises).then(() => {
        if (results.every(v => v === false)) {
          return reject(new Error('No inputs were signed'));
        }
        resolve();
      });
    });
  }
  signInputHD(
    inputIndex,
    hdKeyPair,
    sighashTypes = [transaction_1.Transaction.SIGHASH_ALL],
  ) {
    if (!hdKeyPair || !hdKeyPair.publicKey || !hdKeyPair.fingerprint) {
      throw new Error('Need HDSigner to sign input');
    }
    const signers = getSignersFromHD(inputIndex, this.data.inputs, hdKeyPair);
    signers.forEach(signer => this.signInput(inputIndex, signer, sighashTypes));
    return this;
  }
  signInputHDAsync(
    inputIndex,
    hdKeyPair,
    sighashTypes = [transaction_1.Transaction.SIGHASH_ALL],
  ) {
    return new Promise((resolve, reject) => {
      if (!hdKeyPair || !hdKeyPair.publicKey || !hdKeyPair.fingerprint) {
        return reject(new Error('Need HDSigner to sign input'));
      }
      const signers = getSignersFromHD(inputIndex, this.data.inputs, hdKeyPair);
      const promises = signers.map(signer =>
        this.signInputAsync(inputIndex, signer, sighashTypes),
      );
      return Promise.all(promises)
        .then(() => {
          resolve();
        })
        .catch(reject);
    });
  }
  signAllInputs(keyPair, sighashTypes) {
    if (!keyPair || !keyPair.publicKey)
      throw new Error('Need Signer to sign input');
    // TODO: Add a pubkey/pubkeyhash cache to each input
    // as input information is added, then eventually
    // optimize this method.
    const results = [];
    for (const i of range(this.data.inputs.length)) {
      try {
        this.signInput(i, keyPair, sighashTypes);
        results.push(true);
      } catch (err) {
        results.push(false);
      }
    }
    if (results.every(v => v === false)) {
      throw new Error('No inputs were signed');
    }
    return this;
  }
  signAllInputsAsync(keyPair, sighashTypes) {
    return new Promise((resolve, reject) => {
      if (!keyPair || !keyPair.publicKey)
        return reject(new Error('Need Signer to sign input'));
      // TODO: Add a pubkey/pubkeyhash cache to each input
      // as input information is added, then eventually
      // optimize this method.
      const results = [];
      const promises = [];
      for (const [i] of this.data.inputs.entries()) {
        promises.push(
          this.signInputAsync(i, keyPair, sighashTypes).then(
            () => {
              results.push(true);
            },
            () => {
              results.push(false);
            },
          ),
        );
      }
      return Promise.all(promises).then(() => {
        if (results.every(v => v === false)) {
          return reject(new Error('No inputs were signed'));
        }
        resolve();
      });
    });
  }
  signInput(inputIndex, keyPair, sighashTypes) {
    if (!keyPair || !keyPair.publicKey)
      throw new Error('Need Signer to sign input');
    const input = (0, utils_1.checkForInput)(this.data.inputs, inputIndex);
    if ((0, bip371_1.isTaprootInput)(input)) {
      return this._signTaprootInput(
        inputIndex,
        input,
        keyPair,
        undefined,
        sighashTypes,
      );
    }
    return this._signInput(inputIndex, keyPair, sighashTypes);
  }
  signTaprootInput(inputIndex, keyPair, tapLeafHashToSign, sighashTypes) {
    if (!keyPair || !keyPair.publicKey)
      throw new Error('Need Signer to sign input');
    const input = (0, utils_1.checkForInput)(this.data.inputs, inputIndex);
    if ((0, bip371_1.isTaprootInput)(input))
      return this._signTaprootInput(
        inputIndex,
        input,
        keyPair,
        tapLeafHashToSign,
        sighashTypes,
      );
    throw new Error(`Input #${inputIndex} is not of type Taproot.`);
  }
  _signInput(
    inputIndex,
    keyPair,
    sighashTypes = [transaction_1.Transaction.SIGHASH_ALL],
  ) {
    const { hash, sighashType } = getHashAndSighashType(
      this.data.inputs,
      inputIndex,
      keyPair.publicKey,
      this.__CACHE,
      sighashTypes,
    );
    const partialSig = [
      {
        pubkey: keyPair.publicKey,
        signature: bscript.signature.encode(keyPair.sign(hash), sighashType),
      },
    ];
    this.data.updateInput(inputIndex, { partialSig });
    return this;
  }
  _signTaprootInput(
    inputIndex,
    input,
    keyPair,
    tapLeafHashToSign,
    allowedSighashTypes = [transaction_1.Transaction.SIGHASH_DEFAULT],
  ) {
    const hashesForSig = this.checkTaprootHashesForSig(
      inputIndex,
      input,
      keyPair,
      tapLeafHashToSign,
      allowedSighashTypes,
    );
    const tapKeySig = hashesForSig
      .filter(h => !h.leafHash)
      .map(h =>
        (0, bip371_1.serializeTaprootSignature)(
          keyPair.signSchnorr(h.hash),
          input.sighashType,
        ),
      )[0];
    const tapScriptSig = hashesForSig
      .filter(h => !!h.leafHash)
      .map(h => ({
        pubkey: (0, bip371_1.toXOnly)(keyPair.publicKey),
        signature: (0, bip371_1.serializeTaprootSignature)(
          keyPair.signSchnorr(h.hash),
          input.sighashType,
        ),
        leafHash: h.leafHash,
      }));
    if (tapKeySig) {
      this.data.updateInput(inputIndex, { tapKeySig });
    }
    if (tapScriptSig.length) {
      this.data.updateInput(inputIndex, { tapScriptSig });
    }
    return this;
  }
  signInputAsync(inputIndex, keyPair, sighashTypes) {
    return Promise.resolve().then(() => {
      if (!keyPair || !keyPair.publicKey)
        throw new Error('Need Signer to sign input');
      const input = (0, utils_1.checkForInput)(this.data.inputs, inputIndex);
      if ((0, bip371_1.isTaprootInput)(input))
        return this._signTaprootInputAsync(
          inputIndex,
          input,
          keyPair,
          undefined,
          sighashTypes,
        );
      return this._signInputAsync(inputIndex, keyPair, sighashTypes);
    });
  }
  signTaprootInputAsync(inputIndex, keyPair, tapLeafHash, sighashTypes) {
    return Promise.resolve().then(() => {
      if (!keyPair || !keyPair.publicKey)
        throw new Error('Need Signer to sign input');
      const input = (0, utils_1.checkForInput)(this.data.inputs, inputIndex);
      if ((0, bip371_1.isTaprootInput)(input))
        return this._signTaprootInputAsync(
          inputIndex,
          input,
          keyPair,
          tapLeafHash,
          sighashTypes,
        );
      throw new Error(`Input #${inputIndex} is not of type Taproot.`);
    });
  }
  _signInputAsync(
    inputIndex,
    keyPair,
    sighashTypes = [transaction_1.Transaction.SIGHASH_ALL],
  ) {
    const { hash, sighashType } = getHashAndSighashType(
      this.data.inputs,
      inputIndex,
      keyPair.publicKey,
      this.__CACHE,
      sighashTypes,
    );
    return Promise.resolve(keyPair.sign(hash)).then(signature => {
      const partialSig = [
        {
          pubkey: keyPair.publicKey,
          signature: bscript.signature.encode(signature, sighashType),
        },
      ];
      this.data.updateInput(inputIndex, { partialSig });
    });
  }
  async _signTaprootInputAsync(
    inputIndex,
    input,
    keyPair,
    tapLeafHash,
    sighashTypes = [transaction_1.Transaction.SIGHASH_DEFAULT],
  ) {
    const hashesForSig = this.checkTaprootHashesForSig(
      inputIndex,
      input,
      keyPair,
      tapLeafHash,
      sighashTypes,
    );
    const signaturePromises = [];
    const tapKeyHash = hashesForSig.filter(h => !h.leafHash)[0];
    if (tapKeyHash) {
      const tapKeySigPromise = Promise.resolve(
        keyPair.signSchnorr(tapKeyHash.hash),
      ).then(sig => {
        return {
          tapKeySig: (0, bip371_1.serializeTaprootSignature)(
            sig,
            input.sighashType,
          ),
        };
      });
      signaturePromises.push(tapKeySigPromise);
    }
    const tapScriptHashes = hashesForSig.filter(h => !!h.leafHash);
    if (tapScriptHashes.length) {
      const tapScriptSigPromises = tapScriptHashes.map(tsh => {
        return Promise.resolve(keyPair.signSchnorr(tsh.hash)).then(
          signature => {
            const tapScriptSig = [
              {
                pubkey: (0, bip371_1.toXOnly)(keyPair.publicKey),
                signature: (0, bip371_1.serializeTaprootSignature)(
                  signature,
                  input.sighashType,
                ),
                leafHash: tsh.leafHash,
              },
            ];
            return { tapScriptSig };
          },
        );
      });
      signaturePromises.push(...tapScriptSigPromises);
    }
    return Promise.all(signaturePromises).then(results => {
      results.forEach(v => this.data.updateInput(inputIndex, v));
    });
  }
  checkTaprootHashesForSig(
    inputIndex,
    input,
    keyPair,
    tapLeafHashToSign,
    allowedSighashTypes,
  ) {
    if (typeof keyPair.signSchnorr !== 'function')
      throw new Error(
        `Need Schnorr Signer to sign taproot input #${inputIndex}.`,
      );
    const hashesForSig = getTaprootHashesForSig(
      inputIndex,
      input,
      this.data.inputs,
      keyPair.publicKey,
      this.__CACHE,
      tapLeafHashToSign,
      allowedSighashTypes,
    );
    if (!hashesForSig || !hashesForSig.length)
      throw new Error(
        `Can not sign for input #${inputIndex} with the key ${keyPair.publicKey.toString(
          'hex',
        )}`,
      );
    return hashesForSig;
  }
  toBuffer() {
    checkCache(this.__CACHE);
    return this.data.toBuffer();
  }
  toHex() {
    checkCache(this.__CACHE);
    return this.data.toHex();
  }
  toBase64() {
    checkCache(this.__CACHE);
    return this.data.toBase64();
  }
  updateGlobal(updateData) {
    this.data.updateGlobal(updateData);
    return this;
  }
  updateInput(inputIndex, updateData) {
    if (updateData.witnessScript) checkInvalidP2WSH(updateData.witnessScript);
    (0, bip371_1.checkTaprootInputFields)(
      this.data.inputs[inputIndex],
      updateData,
      'updateInput',
    );
    this.data.updateInput(inputIndex, updateData);
    if (updateData.nonWitnessUtxo) {
      addNonWitnessTxCache(
        this.__CACHE,
        this.data.inputs[inputIndex],
        inputIndex,
      );
    }
    return this;
  }
  updateOutput(outputIndex, updateData) {
    const outputData = this.data.outputs[outputIndex];
    (0, bip371_1.checkTaprootOutputFields)(
      outputData,
      updateData,
      'updateOutput',
    );
    this.data.updateOutput(outputIndex, updateData);
    return this;
  }
  addUnknownKeyValToGlobal(keyVal) {
    this.data.addUnknownKeyValToGlobal(keyVal);
    return this;
  }
  addUnknownKeyValToInput(inputIndex, keyVal) {
    this.data.addUnknownKeyValToInput(inputIndex, keyVal);
    return this;
  }
  addUnknownKeyValToOutput(outputIndex, keyVal) {
    this.data.addUnknownKeyValToOutput(outputIndex, keyVal);
    return this;
  }
  clearFinalizedInput(inputIndex) {
    this.data.clearFinalizedInput(inputIndex);
    return this;
  }
}
exports.Psbt = Psbt;
/**
 * This function is needed to pass to the bip174 base class's fromBuffer.
 * It takes the "transaction buffer" portion of the psbt buffer and returns a
 * Transaction (From the bip174 library) interface.
 */
const transactionFromBuffer = buffer => new PsbtTransaction(buffer);
/**
 * This class implements the Transaction interface from bip174 library.
 * It contains a bitcoinjs-lib Transaction object.
 */
class PsbtTransaction {
  constructor(buffer = Buffer.from([2, 0, 0, 0, 0, 0, 0, 0, 0, 0])) {
    this.tx = transaction_1.Transaction.fromBuffer(buffer);
    checkTxEmpty(this.tx);
    Object.defineProperty(this, 'tx', {
      enumerable: false,
      writable: true,
    });
  }
  getInputOutputCounts() {
    return {
      inputCount: this.tx.ins.length,
      outputCount: this.tx.outs.length,
    };
  }
  addInput(input) {
    if (
      input.hash === undefined ||
      input.index === undefined ||
      (!Buffer.isBuffer(input.hash) && typeof input.hash !== 'string') ||
      typeof input.index !== 'number'
    ) {
      throw new Error('Error adding input.');
    }
    const hash =
      typeof input.hash === 'string'
        ? (0, bufferutils_1.reverseBuffer)(Buffer.from(input.hash, 'hex'))
        : input.hash;
    this.tx.addInput(hash, input.index, input.sequence);
  }
  addOutput(output) {
    if (
      output.script === undefined ||
      output.value === undefined ||
      !Buffer.isBuffer(output.script) ||
      typeof output.value !== 'number'
    ) {
      throw new Error('Error adding output.');
    }
    this.tx.addOutput(output.script, output.value);
  }
  toBuffer() {
    return this.tx.toBuffer();
  }
}
function canFinalize(input, script, scriptType) {
  switch (scriptType) {
    case 'pubkey':
    case 'pubkeyhash':
    case 'witnesspubkeyhash':
      return hasSigs(1, input.partialSig);
    case 'multisig':
      const p2ms = payments.p2ms({ output: script });
      return hasSigs(p2ms.m, input.partialSig, p2ms.pubkeys);
    default:
      return false;
  }
}
function checkCache(cache) {
  if (cache.__UNSAFE_SIGN_NONSEGWIT !== false) {
    throw new Error('Not BIP174 compliant, can not export');
  }
}
function hasSigs(neededSigs, partialSig, pubkeys) {
  if (!partialSig) return false;
  let sigs;
  if (pubkeys) {
    sigs = pubkeys
      .map(pkey => {
        const pubkey = compressPubkey(pkey);
        return partialSig.find(pSig => pSig.pubkey.equals(pubkey));
      })
      .filter(v => !!v);
  } else {
    sigs = partialSig;
  }
  if (sigs.length > neededSigs) throw new Error('Too many signatures');
  return sigs.length === neededSigs;
}
function isFinalized(input) {
  return !!input.finalScriptSig || !!input.finalScriptWitness;
}
function bip32DerivationIsMine(root) {
  return d => {
    if (!d.masterFingerprint.equals(root.fingerprint)) return false;
    if (!root.derivePath(d.path).publicKey.equals(d.pubkey)) return false;
    return true;
  };
}
function check32Bit(num) {
  if (
    typeof num !== 'number' ||
    num !== Math.floor(num) ||
    num > 0xffffffff ||
    num < 0
  ) {
    throw new Error('Invalid 32 bit integer');
  }
}
function checkFees(psbt, cache, opts) {
  const feeRate = cache.__FEE_RATE || psbt.getFeeRate();
  const vsize = cache.__EXTRACTED_TX.virtualSize();
  const satoshis = feeRate * vsize;
  if (feeRate >= opts.maximumFeeRate) {
    throw new Error(
      `Warning: You are paying around ${(satoshis / 1e8).toFixed(8)} in ` +
        `fees, which is ${feeRate} satoshi per byte for a transaction ` +
        `with a VSize of ${vsize} bytes (segwit counted as 0.25 byte per ` +
        `byte). Use setMaximumFeeRate method to raise your threshold, or ` +
        `pass true to the first arg of extractTransaction.`,
    );
  }
}
function checkInputsForPartialSig(inputs, action) {
  inputs.forEach(input => {
    const throws = (0, bip371_1.isTaprootInput)(input)
      ? (0, bip371_1.checkTaprootInputForSigs)(input, action)
      : (0, psbtutils_1.checkInputForSig)(input, action);
    if (throws)
      throw new Error('Can not modify transaction, signatures exist.');
  });
}
function checkPartialSigSighashes(input) {
  if (!input.sighashType || !input.partialSig) return;
  const { partialSig, sighashType } = input;
  partialSig.forEach(pSig => {
    const { hashType } = bscript.signature.decode(pSig.signature);
    if (sighashType !== hashType) {
      throw new Error('Signature sighash does not match input sighash type');
    }
  });
}
function checkScriptForPubkey(pubkey, script, action) {
  if (!(0, psbtutils_1.pubkeyInScript)(pubkey, script)) {
    throw new Error(
      `Can not ${action} for this input with the key ${pubkey.toString('hex')}`,
    );
  }
}
function checkTxEmpty(tx) {
  const isEmpty = tx.ins.every(
    input =>
      input.script &&
      input.script.length === 0 &&
      input.witness &&
      input.witness.length === 0,
  );
  if (!isEmpty) {
    throw new Error('Format Error: Transaction ScriptSigs are not empty');
  }
}
function checkTxForDupeIns(tx, cache) {
  tx.ins.forEach(input => {
    checkTxInputCache(cache, input);
  });
}
function checkTxInputCache(cache, input) {
  const key =
    (0, bufferutils_1.reverseBuffer)(Buffer.from(input.hash)).toString('hex') +
    ':' +
    input.index;
  if (cache.__TX_IN_CACHE[key]) throw new Error('Duplicate input detected.');
  cache.__TX_IN_CACHE[key] = 1;
}
function scriptCheckerFactory(payment, paymentScriptName) {
  return (inputIndex, scriptPubKey, redeemScript, ioType) => {
    const redeemScriptOutput = payment({
      redeem: { output: redeemScript },
    }).output;
    if (!scriptPubKey.equals(redeemScriptOutput)) {
      throw new Error(
        `${paymentScriptName} for ${ioType} #${inputIndex} doesn't match the scriptPubKey in the prevout`,
      );
    }
  };
}
const checkRedeemScript = scriptCheckerFactory(payments.p2sh, 'Redeem script');
const checkWitnessScript = scriptCheckerFactory(
  payments.p2wsh,
  'Witness script',
);
function getTxCacheValue(key, name, inputs, c) {
  if (!inputs.every(isFinalized))
    throw new Error(`PSBT must be finalized to calculate ${name}`);
  if (key === '__FEE_RATE' && c.__FEE_RATE) return c.__FEE_RATE;
  if (key === '__FEE' && c.__FEE) return c.__FEE;
  let tx;
  let mustFinalize = true;
  if (c.__EXTRACTED_TX) {
    tx = c.__EXTRACTED_TX;
    mustFinalize = false;
  } else {
    tx = c.__TX.clone();
  }
  inputFinalizeGetAmts(inputs, tx, c, mustFinalize);
  if (key === '__FEE_RATE') return c.__FEE_RATE;
  else if (key === '__FEE') return c.__FEE;
}
function getFinalScripts(inputIndex, input, script, isSegwit, isP2SH, isP2WSH) {
  const scriptType = classifyScript(script);
  if (!canFinalize(input, script, scriptType))
    throw new Error(`Can not finalize input #${inputIndex}`);
  return prepareFinalScripts(
    script,
    scriptType,
    input.partialSig,
    isSegwit,
    isP2SH,
    isP2WSH,
  );
}
function prepareFinalScripts(
  script,
  scriptType,
  partialSig,
  isSegwit,
  isP2SH,
  isP2WSH,
) {
  let finalScriptSig;
  let finalScriptWitness;
  // Wow, the payments API is very handy
  const payment = getPayment(script, scriptType, partialSig);
  const p2wsh = !isP2WSH ? null : payments.p2wsh({ redeem: payment });
  const p2sh = !isP2SH ? null : payments.p2sh({ redeem: p2wsh || payment });
  if (isSegwit) {
    if (p2wsh) {
      finalScriptWitness = (0, psbtutils_1.witnessStackToScriptWitness)(
        p2wsh.witness,
      );
    } else {
      finalScriptWitness = (0, psbtutils_1.witnessStackToScriptWitness)(
        payment.witness,
      );
    }
    if (p2sh) {
      finalScriptSig = p2sh.input;
    }
  } else {
    if (p2sh) {
      finalScriptSig = p2sh.input;
    } else {
      finalScriptSig = payment.input;
    }
  }
  return {
    finalScriptSig,
    finalScriptWitness,
  };
}
function getHashAndSighashType(
  inputs,
  inputIndex,
  pubkey,
  cache,
  sighashTypes,
) {
  const input = (0, utils_1.checkForInput)(inputs, inputIndex);
  const { hash, sighashType, script } = getHashForSig(
    inputIndex,
    input,
    cache,
    false,
    sighashTypes,
  );
  checkScriptForPubkey(pubkey, script, 'sign');
  return {
    hash,
    sighashType,
  };
}
function getHashForSig(inputIndex, input, cache, forValidate, sighashTypes) {
  const unsignedTx = cache.__TX;
  const sighashType =
    input.sighashType || transaction_1.Transaction.SIGHASH_ALL;
  checkSighashTypeAllowed(sighashType, sighashTypes);
  let hash;
  let prevout;
  if (input.nonWitnessUtxo) {
    const nonWitnessUtxoTx = nonWitnessUtxoTxFromCache(
      cache,
      input,
      inputIndex,
    );
    const prevoutHash = unsignedTx.ins[inputIndex].hash;
    const utxoHash = nonWitnessUtxoTx.getHash();
    // If a non-witness UTXO is provided, its hash must match the hash specified in the prevout
    if (!prevoutHash.equals(utxoHash)) {
      throw new Error(
        `Non-witness UTXO hash for input #${inputIndex} doesn't match the hash specified in the prevout`,
      );
    }
    const prevoutIndex = unsignedTx.ins[inputIndex].index;
    prevout = nonWitnessUtxoTx.outs[prevoutIndex];
  } else if (input.witnessUtxo) {
    prevout = input.witnessUtxo;
  } else {
    throw new Error('Need a Utxo input item for signing');
  }
  const { meaningfulScript, type } = getMeaningfulScript(
    prevout.script,
    inputIndex,
    'input',
    input.redeemScript,
    input.witnessScript,
  );
  if (['p2sh-p2wsh', 'p2wsh'].indexOf(type) >= 0) {
    hash = unsignedTx.hashForWitnessV0(
      inputIndex,
      meaningfulScript,
      prevout.value,
      sighashType,
    );
  } else if ((0, psbtutils_1.isP2WPKH)(meaningfulScript)) {
    // P2WPKH uses the P2PKH template for prevoutScript when signing
    const signingScript = payments.p2pkh({
      hash: meaningfulScript.slice(2),
    }).output;
    hash = unsignedTx.hashForWitnessV0(
      inputIndex,
      signingScript,
      prevout.value,
      sighashType,
    );
  } else {
    // non-segwit
    if (
      input.nonWitnessUtxo === undefined &&
      cache.__UNSAFE_SIGN_NONSEGWIT === false
    )
      throw new Error(
        `Input #${inputIndex} has witnessUtxo but non-segwit script: ` +
          `${meaningfulScript.toString('hex')}`,
      );
    if (!forValidate && cache.__UNSAFE_SIGN_NONSEGWIT !== false)
      console.warn(
        'Warning: Signing non-segwit inputs without the full parent transaction ' +
          'means there is a chance that a miner could feed you incorrect information ' +
          "to trick you into paying large fees. This behavior is the same as Psbt's predecesor " +
          '(TransactionBuilder - now removed) when signing non-segwit scripts. You are not ' +
          'able to export this Psbt with toBuffer|toBase64|toHex since it is not ' +
          'BIP174 compliant.\n*********************\nPROCEED WITH CAUTION!\n' +
          '*********************',
      );
    hash = unsignedTx.hashForSignature(
      inputIndex,
      meaningfulScript,
      sighashType,
    );
  }
  return {
    script: meaningfulScript,
    sighashType,
    hash,
  };
}
function getAllTaprootHashesForSig(inputIndex, input, inputs, cache) {
  const allPublicKeys = [];
  if (input.tapInternalKey) {
    const key = getPrevoutTaprootKey(inputIndex, input, cache);
    if (key) {
      allPublicKeys.push(key);
    }
  }
  if (input.tapScriptSig) {
    const tapScriptPubkeys = input.tapScriptSig.map(tss => tss.pubkey);
    allPublicKeys.push(...tapScriptPubkeys);
  }
  const allHashes = allPublicKeys.map(pubicKey =>
    getTaprootHashesForSig(inputIndex, input, inputs, pubicKey, cache),
  );
  return allHashes.flat();
}
function getPrevoutTaprootKey(inputIndex, input, cache) {
  const { script } = getScriptAndAmountFromUtxo(inputIndex, input, cache);
  return (0, psbtutils_1.isP2TR)(script) ? script.subarray(2, 34) : null;
}
function trimTaprootSig(signature) {
  return signature.length === 64 ? signature : signature.subarray(0, 64);
}
function getTaprootHashesForSig(
  inputIndex,
  input,
  inputs,
  pubkey,
  cache,
  tapLeafHashToSign,
  allowedSighashTypes,
) {
  const unsignedTx = cache.__TX;
  const sighashType =
    input.sighashType || transaction_1.Transaction.SIGHASH_DEFAULT;
  checkSighashTypeAllowed(sighashType, allowedSighashTypes);
  const prevOuts = inputs.map((i, index) =>
    getScriptAndAmountFromUtxo(index, i, cache),
  );
  const signingScripts = prevOuts.map(o => o.script);
  const values = prevOuts.map(o => o.value);
  const hashes = [];
  if (input.tapInternalKey && !tapLeafHashToSign) {
    const outputKey =
      getPrevoutTaprootKey(inputIndex, input, cache) || Buffer.from([]);
    if ((0, bip371_1.toXOnly)(pubkey).equals(outputKey)) {
      const tapKeyHash = unsignedTx.hashForWitnessV1(
        inputIndex,
        signingScripts,
        values,
        sighashType,
      );
      hashes.push({ pubkey, hash: tapKeyHash });
    }
  }
  const tapLeafHashes = (input.tapLeafScript || [])
    .filter(tapLeaf => (0, psbtutils_1.pubkeyInScript)(pubkey, tapLeaf.script))
    .map(tapLeaf => {
      const hash = (0, bip341_1.tapleafHash)({
        output: tapLeaf.script,
        version: tapLeaf.leafVersion,
      });
      return Object.assign({ hash }, tapLeaf);
    })
    .filter(
      tapLeaf => !tapLeafHashToSign || tapLeafHashToSign.equals(tapLeaf.hash),
    )
    .map(tapLeaf => {
      const tapScriptHash = unsignedTx.hashForWitnessV1(
        inputIndex,
        signingScripts,
        values,
        transaction_1.Transaction.SIGHASH_DEFAULT,
        tapLeaf.hash,
      );
      return {
        pubkey,
        hash: tapScriptHash,
        leafHash: tapLeaf.hash,
      };
    });
  return hashes.concat(tapLeafHashes);
}
function checkSighashTypeAllowed(sighashType, sighashTypes) {
  if (sighashTypes && sighashTypes.indexOf(sighashType) < 0) {
    const str = sighashTypeToString(sighashType);
    throw new Error(
      `Sighash type is not allowed. Retry the sign method passing the ` +
        `sighashTypes array of whitelisted types. Sighash type: ${str}`,
    );
  }
}
function getPayment(script, scriptType, partialSig) {
  let payment;
  switch (scriptType) {
    case 'multisig':
      const sigs = getSortedSigs(script, partialSig);
      payment = payments.p2ms({
        output: script,
        signatures: sigs,
      });
      break;
    case 'pubkey':
      payment = payments.p2pk({
        output: script,
        signature: partialSig[0].signature,
      });
      break;
    case 'pubkeyhash':
      payment = payments.p2pkh({
        output: script,
        pubkey: partialSig[0].pubkey,
        signature: partialSig[0].signature,
      });
      break;
    case 'witnesspubkeyhash':
      payment = payments.p2wpkh({
        output: script,
        pubkey: partialSig[0].pubkey,
        signature: partialSig[0].signature,
      });
      break;
  }
  return payment;
}
function getScriptFromInput(inputIndex, input, cache) {
  const unsignedTx = cache.__TX;
  const res = {
    script: null,
    isSegwit: false,
    isP2SH: false,
    isP2WSH: false,
  };
  res.isP2SH = !!input.redeemScript;
  res.isP2WSH = !!input.witnessScript;
  if (input.witnessScript) {
    res.script = input.witnessScript;
  } else if (input.redeemScript) {
    res.script = input.redeemScript;
  } else {
    if (input.nonWitnessUtxo) {
      const nonWitnessUtxoTx = nonWitnessUtxoTxFromCache(
        cache,
        input,
        inputIndex,
      );
      const prevoutIndex = unsignedTx.ins[inputIndex].index;
      res.script = nonWitnessUtxoTx.outs[prevoutIndex].script;
    } else if (input.witnessUtxo) {
      res.script = input.witnessUtxo.script;
    }
  }
  if (input.witnessScript || (0, psbtutils_1.isP2WPKH)(res.script)) {
    res.isSegwit = true;
  }
  return res;
}
function getSignersFromHD(inputIndex, inputs, hdKeyPair) {
  const input = (0, utils_1.checkForInput)(inputs, inputIndex);
  if (!input.bip32Derivation || input.bip32Derivation.length === 0) {
    throw new Error('Need bip32Derivation to sign with HD');
  }
  const myDerivations = input.bip32Derivation
    .map(bipDv => {
      if (bipDv.masterFingerprint.equals(hdKeyPair.fingerprint)) {
        return bipDv;
      } else {
        return;
      }
    })
    .filter(v => !!v);
  if (myDerivations.length === 0) {
    throw new Error(
      'Need one bip32Derivation masterFingerprint to match the HDSigner fingerprint',
    );
  }
  const signers = myDerivations.map(bipDv => {
    const node = hdKeyPair.derivePath(bipDv.path);
    if (!bipDv.pubkey.equals(node.publicKey)) {
      throw new Error('pubkey did not match bip32Derivation');
    }
    return node;
  });
  return signers;
}
function getSortedSigs(script, partialSig) {
  const p2ms = payments.p2ms({ output: script });
  // for each pubkey in order of p2ms script
  return p2ms.pubkeys
    .map(pk => {
      // filter partialSig array by pubkey being equal
      return (
        partialSig.filter(ps => {
          return ps.pubkey.equals(pk);
        })[0] || {}
      ).signature;
      // Any pubkey without a match will return undefined
      // this last filter removes all the undefined items in the array.
    })
    .filter(v => !!v);
}
function scriptWitnessToWitnessStack(buffer) {
  let offset = 0;
  function readSlice(n) {
    offset += n;
    return buffer.slice(offset - n, offset);
  }
  function readVarInt() {
    const vi = varuint.decode(buffer, offset);
    offset += varuint.decode.bytes;
    return vi;
  }
  function readVarSlice() {
    return readSlice(readVarInt());
  }
  function readVector() {
    const count = readVarInt();
    const vector = [];
    for (let i = 0; i < count; i++) vector.push(readVarSlice());
    return vector;
  }
  return readVector();
}
function sighashTypeToString(sighashType) {
  let text =
    sighashType & transaction_1.Transaction.SIGHASH_ANYONECANPAY
      ? 'SIGHASH_ANYONECANPAY | '
      : '';
  const sigMod = sighashType & 0x1f;
  switch (sigMod) {
    case transaction_1.Transaction.SIGHASH_ALL:
      text += 'SIGHASH_ALL';
      break;
    case transaction_1.Transaction.SIGHASH_SINGLE:
      text += 'SIGHASH_SINGLE';
      break;
    case transaction_1.Transaction.SIGHASH_NONE:
      text += 'SIGHASH_NONE';
      break;
  }
  return text;
}
function addNonWitnessTxCache(cache, input, inputIndex) {
  cache.__NON_WITNESS_UTXO_BUF_CACHE[inputIndex] = input.nonWitnessUtxo;
  const tx = transaction_1.Transaction.fromBuffer(input.nonWitnessUtxo);
  cache.__NON_WITNESS_UTXO_TX_CACHE[inputIndex] = tx;
  const self = cache;
  const selfIndex = inputIndex;
  delete input.nonWitnessUtxo;
  Object.defineProperty(input, 'nonWitnessUtxo', {
    enumerable: true,
    get() {
      const buf = self.__NON_WITNESS_UTXO_BUF_CACHE[selfIndex];
      const txCache = self.__NON_WITNESS_UTXO_TX_CACHE[selfIndex];
      if (buf !== undefined) {
        return buf;
      } else {
        const newBuf = txCache.toBuffer();
        self.__NON_WITNESS_UTXO_BUF_CACHE[selfIndex] = newBuf;
        return newBuf;
      }
    },
    set(data) {
      self.__NON_WITNESS_UTXO_BUF_CACHE[selfIndex] = data;
    },
  });
}
function inputFinalizeGetAmts(inputs, tx, cache, mustFinalize) {
  let inputAmount = 0;
  inputs.forEach((input, idx) => {
    if (mustFinalize && input.finalScriptSig)
      tx.ins[idx].script = input.finalScriptSig;
    if (mustFinalize && input.finalScriptWitness) {
      tx.ins[idx].witness = scriptWitnessToWitnessStack(
        input.finalScriptWitness,
      );
    }
    if (input.witnessUtxo) {
      inputAmount += input.witnessUtxo.value;
    } else if (input.nonWitnessUtxo) {
      const nwTx = nonWitnessUtxoTxFromCache(cache, input, idx);
      const vout = tx.ins[idx].index;
      const out = nwTx.outs[vout];
      inputAmount += out.value;
    }
  });
  const outputAmount = tx.outs.reduce((total, o) => total + o.value, 0);
  const fee = inputAmount - outputAmount;
  if (fee < 0) {
    throw new Error('Outputs are spending more than Inputs');
  }
  const bytes = tx.virtualSize();
  cache.__FEE = fee;
  cache.__EXTRACTED_TX = tx;
  cache.__FEE_RATE = Math.floor(fee / bytes);
}
function nonWitnessUtxoTxFromCache(cache, input, inputIndex) {
  const c = cache.__NON_WITNESS_UTXO_TX_CACHE;
  if (!c[inputIndex]) {
    addNonWitnessTxCache(cache, input, inputIndex);
  }
  return c[inputIndex];
}
function getScriptFromUtxo(inputIndex, input, cache) {
  const { script } = getScriptAndAmountFromUtxo(inputIndex, input, cache);
  return script;
}
function getScriptAndAmountFromUtxo(inputIndex, input, cache) {
  if (input.witnessUtxo !== undefined) {
    return {
      script: input.witnessUtxo.script,
      value: input.witnessUtxo.value,
    };
  } else if (input.nonWitnessUtxo !== undefined) {
    const nonWitnessUtxoTx = nonWitnessUtxoTxFromCache(
      cache,
      input,
      inputIndex,
    );
    const o = nonWitnessUtxoTx.outs[cache.__TX.ins[inputIndex].index];
    return { script: o.script, value: o.value };
  } else {
    throw new Error("Can't find pubkey in input without Utxo data");
  }
}
function pubkeyInInput(pubkey, input, inputIndex, cache) {
  const script = getScriptFromUtxo(inputIndex, input, cache);
  const { meaningfulScript } = getMeaningfulScript(
    script,
    inputIndex,
    'input',
    input.redeemScript,
    input.witnessScript,
  );
  return (0, psbtutils_1.pubkeyInScript)(pubkey, meaningfulScript);
}
function pubkeyInOutput(pubkey, output, outputIndex, cache) {
  const script = cache.__TX.outs[outputIndex].script;
  const { meaningfulScript } = getMeaningfulScript(
    script,
    outputIndex,
    'output',
    output.redeemScript,
    output.witnessScript,
  );
  return (0, psbtutils_1.pubkeyInScript)(pubkey, meaningfulScript);
}
function redeemFromFinalScriptSig(finalScript) {
  if (!finalScript) return;
  const decomp = bscript.decompile(finalScript);
  if (!decomp) return;
  const lastItem = decomp[decomp.length - 1];
  if (
    !Buffer.isBuffer(lastItem) ||
    isPubkeyLike(lastItem) ||
    isSigLike(lastItem)
  )
    return;
  const sDecomp = bscript.decompile(lastItem);
  if (!sDecomp) return;
  return lastItem;
}
function redeemFromFinalWitnessScript(finalScript) {
  if (!finalScript) return;
  const decomp = scriptWitnessToWitnessStack(finalScript);
  const lastItem = decomp[decomp.length - 1];
  if (isPubkeyLike(lastItem)) return;
  const sDecomp = bscript.decompile(lastItem);
  if (!sDecomp) return;
  return lastItem;
}
function compressPubkey(pubkey) {
  if (pubkey.length === 65) {
    const parity = pubkey[64] & 1;
    const newKey = pubkey.slice(0, 33);
    newKey[0] = 2 | parity;
    return newKey;
  }
  return pubkey.slice();
}
function isPubkeyLike(buf) {
  return buf.length === 33 && bscript.isCanonicalPubKey(buf);
}
function isSigLike(buf) {
  return bscript.isCanonicalScriptSignature(buf);
}
function getMeaningfulScript(
  script,
  index,
  ioType,
  redeemScript,
  witnessScript,
) {
  const isP2SH = (0, psbtutils_1.isP2SHScript)(script);
  const isP2SHP2WSH =
    isP2SH && redeemScript && (0, psbtutils_1.isP2WSHScript)(redeemScript);
  const isP2WSH = (0, psbtutils_1.isP2WSHScript)(script);
  if (isP2SH && redeemScript === undefined)
    throw new Error('scriptPubkey is P2SH but redeemScript missing');
  if ((isP2WSH || isP2SHP2WSH) && witnessScript === undefined)
    throw new Error(
      'scriptPubkey or redeemScript is P2WSH but witnessScript missing',
    );
  let meaningfulScript;
  if (isP2SHP2WSH) {
    meaningfulScript = witnessScript;
    checkRedeemScript(index, script, redeemScript, ioType);
    checkWitnessScript(index, redeemScript, witnessScript, ioType);
    checkInvalidP2WSH(meaningfulScript);
  } else if (isP2WSH) {
    meaningfulScript = witnessScript;
    checkWitnessScript(index, script, witnessScript, ioType);
    checkInvalidP2WSH(meaningfulScript);
  } else if (isP2SH) {
    meaningfulScript = redeemScript;
    checkRedeemScript(index, script, redeemScript, ioType);
  } else {
    meaningfulScript = script;
  }
  return {
    meaningfulScript,
    type: isP2SHP2WSH
      ? 'p2sh-p2wsh'
      : isP2SH
      ? 'p2sh'
      : isP2WSH
      ? 'p2wsh'
      : 'raw',
  };
}
function checkInvalidP2WSH(script) {
  if (
    (0, psbtutils_1.isP2WPKH)(script) ||
    (0, psbtutils_1.isP2SHScript)(script)
  ) {
    throw new Error('P2WPKH or P2SH can not be contained within P2WSH');
  }
}
function classifyScript(script) {
  if ((0, psbtutils_1.isP2WPKH)(script)) return 'witnesspubkeyhash';
  if ((0, psbtutils_1.isP2PKH)(script)) return 'pubkeyhash';
  if ((0, psbtutils_1.isP2MS)(script)) return 'multisig';
  if ((0, psbtutils_1.isP2PK)(script)) return 'pubkey';
  return 'nonstandard';
}
function range(n) {
  return [...Array(n).keys()];
}

}).call(this)}).call(this,require("buffer").Buffer)
},{"./address":60,"./bufferutils":63,"./networks":68,"./payments":72,"./payments/bip341":70,"./psbt/bip371":82,"./psbt/psbtutils":83,"./script":85,"./transaction":88,"bip174":41,"bip174/src/lib/converter/varint":37,"bip174/src/lib/utils":43,"buffer":97}],82:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.checkTaprootInputForSigs =
  exports.tapTreeFromList =
  exports.tapTreeToList =
  exports.tweakInternalPubKey =
  exports.checkTaprootOutputFields =
  exports.checkTaprootInputFields =
  exports.isTaprootOutput =
  exports.isTaprootInput =
  exports.serializeTaprootSignature =
  exports.tapScriptFinalizer =
  exports.toXOnly =
    void 0;
const types_1 = require('../types');
const transaction_1 = require('../transaction');
const psbtutils_1 = require('./psbtutils');
const bip341_1 = require('../payments/bip341');
const payments_1 = require('../payments');
const psbtutils_2 = require('./psbtutils');
const toXOnly = pubKey => (pubKey.length === 32 ? pubKey : pubKey.slice(1, 33));
exports.toXOnly = toXOnly;
/**
 * Default tapscript finalizer. It searches for the `tapLeafHashToFinalize` if provided.
 * Otherwise it will search for the tapleaf that has at least one signature and has the shortest path.
 * @param inputIndex the position of the PSBT input.
 * @param input the PSBT input.
 * @param tapLeafHashToFinalize optional, if provided the finalizer will search for a tapleaf that has this hash
 *                              and will try to build the finalScriptWitness.
 * @returns the finalScriptWitness or throws an exception if no tapleaf found.
 */
function tapScriptFinalizer(inputIndex, input, tapLeafHashToFinalize) {
  const tapLeaf = findTapLeafToFinalize(
    input,
    inputIndex,
    tapLeafHashToFinalize,
  );
  try {
    const sigs = sortSignatures(input, tapLeaf);
    const witness = sigs.concat(tapLeaf.script).concat(tapLeaf.controlBlock);
    return {
      finalScriptWitness: (0, psbtutils_1.witnessStackToScriptWitness)(witness),
    };
  } catch (err) {
    throw new Error(`Can not finalize taproot input #${inputIndex}: ${err}`);
  }
}
exports.tapScriptFinalizer = tapScriptFinalizer;
function serializeTaprootSignature(sig, sighashType) {
  const sighashTypeByte = sighashType
    ? Buffer.from([sighashType])
    : Buffer.from([]);
  return Buffer.concat([sig, sighashTypeByte]);
}
exports.serializeTaprootSignature = serializeTaprootSignature;
function isTaprootInput(input) {
  return (
    input &&
    !!(
      input.tapInternalKey ||
      input.tapMerkleRoot ||
      (input.tapLeafScript && input.tapLeafScript.length) ||
      (input.tapBip32Derivation && input.tapBip32Derivation.length) ||
      (input.witnessUtxo && (0, psbtutils_1.isP2TR)(input.witnessUtxo.script))
    )
  );
}
exports.isTaprootInput = isTaprootInput;
function isTaprootOutput(output, script) {
  return (
    output &&
    !!(
      output.tapInternalKey ||
      output.tapTree ||
      (output.tapBip32Derivation && output.tapBip32Derivation.length) ||
      (script && (0, psbtutils_1.isP2TR)(script))
    )
  );
}
exports.isTaprootOutput = isTaprootOutput;
function checkTaprootInputFields(inputData, newInputData, action) {
  checkMixedTaprootAndNonTaprootInputFields(inputData, newInputData, action);
  checkIfTapLeafInTree(inputData, newInputData, action);
}
exports.checkTaprootInputFields = checkTaprootInputFields;
function checkTaprootOutputFields(outputData, newOutputData, action) {
  checkMixedTaprootAndNonTaprootOutputFields(outputData, newOutputData, action);
  checkTaprootScriptPubkey(outputData, newOutputData);
}
exports.checkTaprootOutputFields = checkTaprootOutputFields;
function checkTaprootScriptPubkey(outputData, newOutputData) {
  if (!newOutputData.tapTree && !newOutputData.tapInternalKey) return;
  const tapInternalKey =
    newOutputData.tapInternalKey || outputData.tapInternalKey;
  const tapTree = newOutputData.tapTree || outputData.tapTree;
  if (tapInternalKey) {
    const { script: scriptPubkey } = outputData;
    const script = getTaprootScripPubkey(tapInternalKey, tapTree);
    if (scriptPubkey && !scriptPubkey.equals(script))
      throw new Error('Error adding output. Script or address missmatch.');
  }
}
function getTaprootScripPubkey(tapInternalKey, tapTree) {
  const scriptTree = tapTree && tapTreeFromList(tapTree.leaves);
  const { output } = (0, payments_1.p2tr)({
    internalPubkey: tapInternalKey,
    scriptTree,
  });
  return output;
}
function tweakInternalPubKey(inputIndex, input) {
  const tapInternalKey = input.tapInternalKey;
  const outputKey =
    tapInternalKey &&
    (0, bip341_1.tweakKey)(tapInternalKey, input.tapMerkleRoot);
  if (!outputKey)
    throw new Error(
      `Cannot tweak tap internal key for input #${inputIndex}. Public key: ${
        tapInternalKey && tapInternalKey.toString('hex')
      }`,
    );
  return outputKey.x;
}
exports.tweakInternalPubKey = tweakInternalPubKey;
/**
 * Convert a binary tree to a BIP371 type list. Each element of the list is (according to BIP371):
 * One or more tuples representing the depth, leaf version, and script for a leaf in the Taproot tree,
 * allowing the entire tree to be reconstructed. The tuples must be in depth first search order so that
 * the tree is correctly reconstructed.
 * @param tree the binary tap tree
 * @returns a list of BIP 371 tapleaves
 */
function tapTreeToList(tree) {
  if (!(0, types_1.isTaptree)(tree))
    throw new Error(
      'Cannot convert taptree to tapleaf list. Expecting a tapree structure.',
    );
  return _tapTreeToList(tree);
}
exports.tapTreeToList = tapTreeToList;
/**
 * Convert a BIP371 TapLeaf list to a TapTree (binary).
 * @param leaves a list of tapleaves where each element of the list is (according to BIP371):
 * One or more tuples representing the depth, leaf version, and script for a leaf in the Taproot tree,
 * allowing the entire tree to be reconstructed. The tuples must be in depth first search order so that
 * the tree is correctly reconstructed.
 * @returns the corresponding taptree, or throws an exception if the tree cannot be reconstructed
 */
function tapTreeFromList(leaves = []) {
  if (leaves.length === 1 && leaves[0].depth === 0)
    return {
      output: leaves[0].script,
      version: leaves[0].leafVersion,
    };
  return instertLeavesInTree(leaves);
}
exports.tapTreeFromList = tapTreeFromList;
function checkTaprootInputForSigs(input, action) {
  const sigs = extractTaprootSigs(input);
  return sigs.some(sig =>
    (0, psbtutils_2.signatureBlocksAction)(sig, decodeSchnorrSignature, action),
  );
}
exports.checkTaprootInputForSigs = checkTaprootInputForSigs;
function decodeSchnorrSignature(signature) {
  return {
    signature: signature.slice(0, 64),
    hashType:
      signature.slice(64)[0] || transaction_1.Transaction.SIGHASH_DEFAULT,
  };
}
function extractTaprootSigs(input) {
  const sigs = [];
  if (input.tapKeySig) sigs.push(input.tapKeySig);
  if (input.tapScriptSig)
    sigs.push(...input.tapScriptSig.map(s => s.signature));
  if (!sigs.length) {
    const finalTapKeySig = getTapKeySigFromWithness(input.finalScriptWitness);
    if (finalTapKeySig) sigs.push(finalTapKeySig);
  }
  return sigs;
}
function getTapKeySigFromWithness(finalScriptWitness) {
  if (!finalScriptWitness) return;
  const witness = finalScriptWitness.slice(2);
  // todo: add schnorr signature validation
  if (witness.length === 64 || witness.length === 65) return witness;
}
function _tapTreeToList(tree, leaves = [], depth = 0) {
  if (depth > bip341_1.MAX_TAPTREE_DEPTH)
    throw new Error('Max taptree depth exceeded.');
  if (!tree) return [];
  if ((0, types_1.isTapleaf)(tree)) {
    leaves.push({
      depth,
      leafVersion: tree.version || bip341_1.LEAF_VERSION_TAPSCRIPT,
      script: tree.output,
    });
    return leaves;
  }
  if (tree[0]) _tapTreeToList(tree[0], leaves, depth + 1);
  if (tree[1]) _tapTreeToList(tree[1], leaves, depth + 1);
  return leaves;
}
function instertLeavesInTree(leaves) {
  let tree;
  for (const leaf of leaves) {
    tree = instertLeafInTree(leaf, tree);
    if (!tree) throw new Error(`No room left to insert tapleaf in tree`);
  }
  return tree;
}
function instertLeafInTree(leaf, tree, depth = 0) {
  if (depth > bip341_1.MAX_TAPTREE_DEPTH)
    throw new Error('Max taptree depth exceeded.');
  if (leaf.depth === depth) {
    if (!tree)
      return {
        output: leaf.script,
        version: leaf.leafVersion,
      };
    return;
  }
  if ((0, types_1.isTapleaf)(tree)) return;
  const leftSide = instertLeafInTree(leaf, tree && tree[0], depth + 1);
  if (leftSide) return [leftSide, tree && tree[1]];
  const rightSide = instertLeafInTree(leaf, tree && tree[1], depth + 1);
  if (rightSide) return [tree && tree[0], rightSide];
}
function checkMixedTaprootAndNonTaprootInputFields(
  inputData,
  newInputData,
  action,
) {
  const isBadTaprootUpdate =
    isTaprootInput(inputData) && hasNonTaprootFields(newInputData);
  const isBadNonTaprootUpdate =
    hasNonTaprootFields(inputData) && isTaprootInput(newInputData);
  const hasMixedFields =
    inputData === newInputData &&
    isTaprootInput(newInputData) &&
    hasNonTaprootFields(newInputData); // todo: bad? use !===
  if (isBadTaprootUpdate || isBadNonTaprootUpdate || hasMixedFields)
    throw new Error(
      `Invalid arguments for Psbt.${action}. ` +
        `Cannot use both taproot and non-taproot fields.`,
    );
}
function checkMixedTaprootAndNonTaprootOutputFields(
  inputData,
  newInputData,
  action,
) {
  const isBadTaprootUpdate =
    isTaprootOutput(inputData) && hasNonTaprootFields(newInputData);
  const isBadNonTaprootUpdate =
    hasNonTaprootFields(inputData) && isTaprootOutput(newInputData);
  const hasMixedFields =
    inputData === newInputData &&
    isTaprootOutput(newInputData) &&
    hasNonTaprootFields(newInputData);
  if (isBadTaprootUpdate || isBadNonTaprootUpdate || hasMixedFields)
    throw new Error(
      `Invalid arguments for Psbt.${action}. ` +
        `Cannot use both taproot and non-taproot fields.`,
    );
}
function checkIfTapLeafInTree(inputData, newInputData, action) {
  if (newInputData.tapMerkleRoot) {
    const newLeafsInTree = (newInputData.tapLeafScript || []).every(l =>
      isTapLeafInTree(l, newInputData.tapMerkleRoot),
    );
    const oldLeafsInTree = (inputData.tapLeafScript || []).every(l =>
      isTapLeafInTree(l, newInputData.tapMerkleRoot),
    );
    if (!newLeafsInTree || !oldLeafsInTree)
      throw new Error(
        `Invalid arguments for Psbt.${action}. Tapleaf not part of taptree.`,
      );
  } else if (inputData.tapMerkleRoot) {
    const newLeafsInTree = (newInputData.tapLeafScript || []).every(l =>
      isTapLeafInTree(l, inputData.tapMerkleRoot),
    );
    if (!newLeafsInTree)
      throw new Error(
        `Invalid arguments for Psbt.${action}. Tapleaf not part of taptree.`,
      );
  }
}
function isTapLeafInTree(tapLeaf, merkleRoot) {
  if (!merkleRoot) return true;
  const leafHash = (0, bip341_1.tapleafHash)({
    output: tapLeaf.script,
    version: tapLeaf.leafVersion,
  });
  const rootHash = (0, bip341_1.rootHashFromPath)(
    tapLeaf.controlBlock,
    leafHash,
  );
  return rootHash.equals(merkleRoot);
}
function sortSignatures(input, tapLeaf) {
  const leafHash = (0, bip341_1.tapleafHash)({
    output: tapLeaf.script,
    version: tapLeaf.leafVersion,
  });
  return (input.tapScriptSig || [])
    .filter(tss => tss.leafHash.equals(leafHash))
    .map(tss => addPubkeyPositionInScript(tapLeaf.script, tss))
    .sort((t1, t2) => t2.positionInScript - t1.positionInScript)
    .map(t => t.signature);
}
function addPubkeyPositionInScript(script, tss) {
  return Object.assign(
    {
      positionInScript: (0, psbtutils_1.pubkeyPositionInScript)(
        tss.pubkey,
        script,
      ),
    },
    tss,
  );
}
/**
 * Find tapleaf by hash, or get the signed tapleaf with the shortest path.
 */
function findTapLeafToFinalize(input, inputIndex, leafHashToFinalize) {
  if (!input.tapScriptSig || !input.tapScriptSig.length)
    throw new Error(
      `Can not finalize taproot input #${inputIndex}. No tapleaf script signature provided.`,
    );
  const tapLeaf = (input.tapLeafScript || [])
    .sort((a, b) => a.controlBlock.length - b.controlBlock.length)
    .find(leaf =>
      canFinalizeLeaf(leaf, input.tapScriptSig, leafHashToFinalize),
    );
  if (!tapLeaf)
    throw new Error(
      `Can not finalize taproot input #${inputIndex}. Signature for tapleaf script not found.`,
    );
  return tapLeaf;
}
function canFinalizeLeaf(leaf, tapScriptSig, hash) {
  const leafHash = (0, bip341_1.tapleafHash)({
    output: leaf.script,
    version: leaf.leafVersion,
  });
  const whiteListedHash = !hash || hash.equals(leafHash);
  return (
    whiteListedHash &&
    tapScriptSig.find(tss => tss.leafHash.equals(leafHash)) !== undefined
  );
}
function hasNonTaprootFields(io) {
  return (
    io &&
    !!(
      io.redeemScript ||
      io.witnessScript ||
      (io.bip32Derivation && io.bip32Derivation.length)
    )
  );
}

}).call(this)}).call(this,require("buffer").Buffer)
},{"../payments":72,"../payments/bip341":70,"../transaction":88,"../types":89,"./psbtutils":83,"buffer":97}],83:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.signatureBlocksAction =
  exports.checkInputForSig =
  exports.pubkeyInScript =
  exports.pubkeyPositionInScript =
  exports.witnessStackToScriptWitness =
  exports.isP2TR =
  exports.isP2SHScript =
  exports.isP2WSHScript =
  exports.isP2WPKH =
  exports.isP2PKH =
  exports.isP2PK =
  exports.isP2MS =
    void 0;
const varuint = require('bip174/src/lib/converter/varint');
const bscript = require('../script');
const transaction_1 = require('../transaction');
const crypto_1 = require('../crypto');
const payments = require('../payments');
function isPaymentFactory(payment) {
  return script => {
    try {
      payment({ output: script });
      return true;
    } catch (err) {
      return false;
    }
  };
}
exports.isP2MS = isPaymentFactory(payments.p2ms);
exports.isP2PK = isPaymentFactory(payments.p2pk);
exports.isP2PKH = isPaymentFactory(payments.p2pkh);
exports.isP2WPKH = isPaymentFactory(payments.p2wpkh);
exports.isP2WSHScript = isPaymentFactory(payments.p2wsh);
exports.isP2SHScript = isPaymentFactory(payments.p2sh);
exports.isP2TR = isPaymentFactory(payments.p2tr);
function witnessStackToScriptWitness(witness) {
  let buffer = Buffer.allocUnsafe(0);
  function writeSlice(slice) {
    buffer = Buffer.concat([buffer, Buffer.from(slice)]);
  }
  function writeVarInt(i) {
    const currentLen = buffer.length;
    const varintLen = varuint.encodingLength(i);
    buffer = Buffer.concat([buffer, Buffer.allocUnsafe(varintLen)]);
    varuint.encode(i, buffer, currentLen);
  }
  function writeVarSlice(slice) {
    writeVarInt(slice.length);
    writeSlice(slice);
  }
  function writeVector(vector) {
    writeVarInt(vector.length);
    vector.forEach(writeVarSlice);
  }
  writeVector(witness);
  return buffer;
}
exports.witnessStackToScriptWitness = witnessStackToScriptWitness;
function pubkeyPositionInScript(pubkey, script) {
  const pubkeyHash = (0, crypto_1.hash160)(pubkey);
  const pubkeyXOnly = pubkey.slice(1, 33); // slice before calling?
  const decompiled = bscript.decompile(script);
  if (decompiled === null) throw new Error('Unknown script error');
  return decompiled.findIndex(element => {
    if (typeof element === 'number') return false;
    return (
      element.equals(pubkey) ||
      element.equals(pubkeyHash) ||
      element.equals(pubkeyXOnly)
    );
  });
}
exports.pubkeyPositionInScript = pubkeyPositionInScript;
function pubkeyInScript(pubkey, script) {
  return pubkeyPositionInScript(pubkey, script) !== -1;
}
exports.pubkeyInScript = pubkeyInScript;
function checkInputForSig(input, action) {
  const pSigs = extractPartialSigs(input);
  return pSigs.some(pSig =>
    signatureBlocksAction(pSig, bscript.signature.decode, action),
  );
}
exports.checkInputForSig = checkInputForSig;
function signatureBlocksAction(signature, signatureDecodeFn, action) {
  const { hashType } = signatureDecodeFn(signature);
  const whitelist = [];
  const isAnyoneCanPay =
    hashType & transaction_1.Transaction.SIGHASH_ANYONECANPAY;
  if (isAnyoneCanPay) whitelist.push('addInput');
  const hashMod = hashType & 0x1f;
  switch (hashMod) {
    case transaction_1.Transaction.SIGHASH_ALL:
      break;
    case transaction_1.Transaction.SIGHASH_SINGLE:
    case transaction_1.Transaction.SIGHASH_NONE:
      whitelist.push('addOutput');
      whitelist.push('setInputSequence');
      break;
  }
  if (whitelist.indexOf(action) === -1) {
    return true;
  }
  return false;
}
exports.signatureBlocksAction = signatureBlocksAction;
function extractPartialSigs(input) {
  let pSigs = [];
  if ((input.partialSig || []).length === 0) {
    if (!input.finalScriptSig && !input.finalScriptWitness) return [];
    pSigs = getPsigsFromInputFinalScripts(input);
  } else {
    pSigs = input.partialSig;
  }
  return pSigs.map(p => p.signature);
}
function getPsigsFromInputFinalScripts(input) {
  const scriptItems = !input.finalScriptSig
    ? []
    : bscript.decompile(input.finalScriptSig) || [];
  const witnessItems = !input.finalScriptWitness
    ? []
    : bscript.decompile(input.finalScriptWitness) || [];
  return scriptItems
    .concat(witnessItems)
    .filter(item => {
      return Buffer.isBuffer(item) && bscript.isCanonicalScriptSignature(item);
    })
    .map(sig => ({ signature: sig }));
}

}).call(this)}).call(this,require("buffer").Buffer)
},{"../crypto":64,"../payments":72,"../script":85,"../transaction":88,"bip174/src/lib/converter/varint":37,"buffer":97}],84:[function(require,module,exports){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.decode = exports.encode = exports.encodingLength = void 0;
const ops_1 = require('./ops');
function encodingLength(i) {
  return i < ops_1.OPS.OP_PUSHDATA1 ? 1 : i <= 0xff ? 2 : i <= 0xffff ? 3 : 5;
}
exports.encodingLength = encodingLength;
function encode(buffer, num, offset) {
  const size = encodingLength(num);
  // ~6 bit
  if (size === 1) {
    buffer.writeUInt8(num, offset);
    // 8 bit
  } else if (size === 2) {
    buffer.writeUInt8(ops_1.OPS.OP_PUSHDATA1, offset);
    buffer.writeUInt8(num, offset + 1);
    // 16 bit
  } else if (size === 3) {
    buffer.writeUInt8(ops_1.OPS.OP_PUSHDATA2, offset);
    buffer.writeUInt16LE(num, offset + 1);
    // 32 bit
  } else {
    buffer.writeUInt8(ops_1.OPS.OP_PUSHDATA4, offset);
    buffer.writeUInt32LE(num, offset + 1);
  }
  return size;
}
exports.encode = encode;
function decode(buffer, offset) {
  const opcode = buffer.readUInt8(offset);
  let num;
  let size;
  // ~6 bit
  if (opcode < ops_1.OPS.OP_PUSHDATA1) {
    num = opcode;
    size = 1;
    // 8 bit
  } else if (opcode === ops_1.OPS.OP_PUSHDATA1) {
    if (offset + 2 > buffer.length) return null;
    num = buffer.readUInt8(offset + 1);
    size = 2;
    // 16 bit
  } else if (opcode === ops_1.OPS.OP_PUSHDATA2) {
    if (offset + 3 > buffer.length) return null;
    num = buffer.readUInt16LE(offset + 1);
    size = 3;
    // 32 bit
  } else {
    if (offset + 5 > buffer.length) return null;
    if (opcode !== ops_1.OPS.OP_PUSHDATA4) throw new Error('Unexpected opcode');
    num = buffer.readUInt32LE(offset + 1);
    size = 5;
  }
  return {
    opcode,
    number: num,
    size,
  };
}
exports.decode = decode;

},{"./ops":69}],85:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.signature =
  exports.number =
  exports.isCanonicalScriptSignature =
  exports.isDefinedHashType =
  exports.isCanonicalPubKey =
  exports.toStack =
  exports.fromASM =
  exports.toASM =
  exports.decompile =
  exports.compile =
  exports.countNonPushOnlyOPs =
  exports.isPushOnly =
  exports.OPS =
    void 0;
const bip66 = require('./bip66');
const ops_1 = require('./ops');
Object.defineProperty(exports, 'OPS', {
  enumerable: true,
  get: function () {
    return ops_1.OPS;
  },
});
const pushdata = require('./push_data');
const scriptNumber = require('./script_number');
const scriptSignature = require('./script_signature');
const types = require('./types');
const { typeforce } = types;
const OP_INT_BASE = ops_1.OPS.OP_RESERVED; // OP_1 - 1
function isOPInt(value) {
  return (
    types.Number(value) &&
    (value === ops_1.OPS.OP_0 ||
      (value >= ops_1.OPS.OP_1 && value <= ops_1.OPS.OP_16) ||
      value === ops_1.OPS.OP_1NEGATE)
  );
}
function isPushOnlyChunk(value) {
  return types.Buffer(value) || isOPInt(value);
}
function isPushOnly(value) {
  return types.Array(value) && value.every(isPushOnlyChunk);
}
exports.isPushOnly = isPushOnly;
function countNonPushOnlyOPs(value) {
  return value.length - value.filter(isPushOnlyChunk).length;
}
exports.countNonPushOnlyOPs = countNonPushOnlyOPs;
function asMinimalOP(buffer) {
  if (buffer.length === 0) return ops_1.OPS.OP_0;
  if (buffer.length !== 1) return;
  if (buffer[0] >= 1 && buffer[0] <= 16) return OP_INT_BASE + buffer[0];
  if (buffer[0] === 0x81) return ops_1.OPS.OP_1NEGATE;
}
function chunksIsBuffer(buf) {
  return Buffer.isBuffer(buf);
}
function chunksIsArray(buf) {
  return types.Array(buf);
}
function singleChunkIsBuffer(buf) {
  return Buffer.isBuffer(buf);
}
function compile(chunks) {
  // TODO: remove me
  if (chunksIsBuffer(chunks)) return chunks;
  typeforce(types.Array, chunks);
  const bufferSize = chunks.reduce((accum, chunk) => {
    // data chunk
    if (singleChunkIsBuffer(chunk)) {
      // adhere to BIP62.3, minimal push policy
      if (chunk.length === 1 && asMinimalOP(chunk) !== undefined) {
        return accum + 1;
      }
      return accum + pushdata.encodingLength(chunk.length) + chunk.length;
    }
    // opcode
    return accum + 1;
  }, 0.0);
  const buffer = Buffer.allocUnsafe(bufferSize);
  let offset = 0;
  chunks.forEach(chunk => {
    // data chunk
    if (singleChunkIsBuffer(chunk)) {
      // adhere to BIP62.3, minimal push policy
      const opcode = asMinimalOP(chunk);
      if (opcode !== undefined) {
        buffer.writeUInt8(opcode, offset);
        offset += 1;
        return;
      }
      offset += pushdata.encode(buffer, chunk.length, offset);
      chunk.copy(buffer, offset);
      offset += chunk.length;
      // opcode
    } else {
      buffer.writeUInt8(chunk, offset);
      offset += 1;
    }
  });
  if (offset !== buffer.length) throw new Error('Could not decode chunks');
  return buffer;
}
exports.compile = compile;
function decompile(buffer) {
  // TODO: remove me
  if (chunksIsArray(buffer)) return buffer;
  typeforce(types.Buffer, buffer);
  const chunks = [];
  let i = 0;
  while (i < buffer.length) {
    const opcode = buffer[i];
    // data chunk
    if (opcode > ops_1.OPS.OP_0 && opcode <= ops_1.OPS.OP_PUSHDATA4) {
      const d = pushdata.decode(buffer, i);
      // did reading a pushDataInt fail?
      if (d === null) return null;
      i += d.size;
      // attempt to read too much data?
      if (i + d.number > buffer.length) return null;
      const data = buffer.slice(i, i + d.number);
      i += d.number;
      // decompile minimally
      const op = asMinimalOP(data);
      if (op !== undefined) {
        chunks.push(op);
      } else {
        chunks.push(data);
      }
      // opcode
    } else {
      chunks.push(opcode);
      i += 1;
    }
  }
  return chunks;
}
exports.decompile = decompile;
function toASM(chunks) {
  if (chunksIsBuffer(chunks)) {
    chunks = decompile(chunks);
  }
  return chunks
    .map(chunk => {
      // data?
      if (singleChunkIsBuffer(chunk)) {
        const op = asMinimalOP(chunk);
        if (op === undefined) return chunk.toString('hex');
        chunk = op;
      }
      // opcode!
      return ops_1.REVERSE_OPS[chunk];
    })
    .join(' ');
}
exports.toASM = toASM;
function fromASM(asm) {
  typeforce(types.String, asm);
  return compile(
    asm.split(' ').map(chunkStr => {
      // opcode?
      if (ops_1.OPS[chunkStr] !== undefined) return ops_1.OPS[chunkStr];
      typeforce(types.Hex, chunkStr);
      // data!
      return Buffer.from(chunkStr, 'hex');
    }),
  );
}
exports.fromASM = fromASM;
function toStack(chunks) {
  chunks = decompile(chunks);
  typeforce(isPushOnly, chunks);
  return chunks.map(op => {
    if (singleChunkIsBuffer(op)) return op;
    if (op === ops_1.OPS.OP_0) return Buffer.allocUnsafe(0);
    return scriptNumber.encode(op - OP_INT_BASE);
  });
}
exports.toStack = toStack;
function isCanonicalPubKey(buffer) {
  return types.isPoint(buffer);
}
exports.isCanonicalPubKey = isCanonicalPubKey;
function isDefinedHashType(hashType) {
  const hashTypeMod = hashType & ~0x80;
  // return hashTypeMod > SIGHASH_ALL && hashTypeMod < SIGHASH_SINGLE
  return hashTypeMod > 0x00 && hashTypeMod < 0x04;
}
exports.isDefinedHashType = isDefinedHashType;
function isCanonicalScriptSignature(buffer) {
  if (!Buffer.isBuffer(buffer)) return false;
  if (!isDefinedHashType(buffer[buffer.length - 1])) return false;
  return bip66.check(buffer.slice(0, -1));
}
exports.isCanonicalScriptSignature = isCanonicalScriptSignature;
exports.number = scriptNumber;
exports.signature = scriptSignature;

}).call(this)}).call(this,require("buffer").Buffer)
},{"./bip66":61,"./ops":69,"./push_data":84,"./script_number":86,"./script_signature":87,"./types":89,"buffer":97}],86:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.encode = exports.decode = void 0;
function decode(buffer, maxLength, minimal) {
  maxLength = maxLength || 4;
  minimal = minimal === undefined ? true : minimal;
  const length = buffer.length;
  if (length === 0) return 0;
  if (length > maxLength) throw new TypeError('Script number overflow');
  if (minimal) {
    if ((buffer[length - 1] & 0x7f) === 0) {
      if (length <= 1 || (buffer[length - 2] & 0x80) === 0)
        throw new Error('Non-minimally encoded script number');
    }
  }
  // 40-bit
  if (length === 5) {
    const a = buffer.readUInt32LE(0);
    const b = buffer.readUInt8(4);
    if (b & 0x80) return -((b & ~0x80) * 0x100000000 + a);
    return b * 0x100000000 + a;
  }
  // 32-bit / 24-bit / 16-bit / 8-bit
  let result = 0;
  for (let i = 0; i < length; ++i) {
    result |= buffer[i] << (8 * i);
  }
  if (buffer[length - 1] & 0x80)
    return -(result & ~(0x80 << (8 * (length - 1))));
  return result;
}
exports.decode = decode;
function scriptNumSize(i) {
  return i > 0x7fffffff
    ? 5
    : i > 0x7fffff
    ? 4
    : i > 0x7fff
    ? 3
    : i > 0x7f
    ? 2
    : i > 0x00
    ? 1
    : 0;
}
function encode(_number) {
  let value = Math.abs(_number);
  const size = scriptNumSize(value);
  const buffer = Buffer.allocUnsafe(size);
  const negative = _number < 0;
  for (let i = 0; i < size; ++i) {
    buffer.writeUInt8(value & 0xff, i);
    value >>= 8;
  }
  if (buffer[size - 1] & 0x80) {
    buffer.writeUInt8(negative ? 0x80 : 0x00, size - 1);
  } else if (negative) {
    buffer[size - 1] |= 0x80;
  }
  return buffer;
}
exports.encode = encode;

}).call(this)}).call(this,require("buffer").Buffer)
},{"buffer":97}],87:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.encode = exports.decode = void 0;
const bip66 = require('./bip66');
const types = require('./types');
const { typeforce } = types;
const ZERO = Buffer.alloc(1, 0);
function toDER(x) {
  let i = 0;
  while (x[i] === 0) ++i;
  if (i === x.length) return ZERO;
  x = x.slice(i);
  if (x[0] & 0x80) return Buffer.concat([ZERO, x], 1 + x.length);
  return x;
}
function fromDER(x) {
  if (x[0] === 0x00) x = x.slice(1);
  const buffer = Buffer.alloc(32, 0);
  const bstart = Math.max(0, 32 - x.length);
  x.copy(buffer, bstart);
  return buffer;
}
// BIP62: 1 byte hashType flag (only 0x01, 0x02, 0x03, 0x81, 0x82 and 0x83 are allowed)
function decode(buffer) {
  const hashType = buffer.readUInt8(buffer.length - 1);
  const hashTypeMod = hashType & ~0x80;
  if (hashTypeMod <= 0 || hashTypeMod >= 4)
    throw new Error('Invalid hashType ' + hashType);
  const decoded = bip66.decode(buffer.slice(0, -1));
  const r = fromDER(decoded.r);
  const s = fromDER(decoded.s);
  const signature = Buffer.concat([r, s], 64);
  return { signature, hashType };
}
exports.decode = decode;
function encode(signature, hashType) {
  typeforce(
    {
      signature: types.BufferN(64),
      hashType: types.UInt8,
    },
    { signature, hashType },
  );
  const hashTypeMod = hashType & ~0x80;
  if (hashTypeMod <= 0 || hashTypeMod >= 4)
    throw new Error('Invalid hashType ' + hashType);
  const hashTypeBuffer = Buffer.allocUnsafe(1);
  hashTypeBuffer.writeUInt8(hashType, 0);
  const r = toDER(signature.slice(0, 32));
  const s = toDER(signature.slice(32, 64));
  return Buffer.concat([bip66.encode(r, s), hashTypeBuffer]);
}
exports.encode = encode;

}).call(this)}).call(this,require("buffer").Buffer)
},{"./bip66":61,"./types":89,"buffer":97}],88:[function(require,module,exports){
(function (Buffer){(function (){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.Transaction = void 0;
const bufferutils_1 = require('./bufferutils');
const bcrypto = require('./crypto');
const bscript = require('./script');
const script_1 = require('./script');
const types = require('./types');
const { typeforce } = types;
function varSliceSize(someScript) {
  const length = someScript.length;
  return bufferutils_1.varuint.encodingLength(length) + length;
}
function vectorSize(someVector) {
  const length = someVector.length;
  return (
    bufferutils_1.varuint.encodingLength(length) +
    someVector.reduce((sum, witness) => {
      return sum + varSliceSize(witness);
    }, 0)
  );
}
const EMPTY_BUFFER = Buffer.allocUnsafe(0);
const EMPTY_WITNESS = [];
const ZERO = Buffer.from(
  '0000000000000000000000000000000000000000000000000000000000000000',
  'hex',
);
const ONE = Buffer.from(
  '0000000000000000000000000000000000000000000000000000000000000001',
  'hex',
);
const VALUE_UINT64_MAX = Buffer.from('ffffffffffffffff', 'hex');
const BLANK_OUTPUT = {
  script: EMPTY_BUFFER,
  valueBuffer: VALUE_UINT64_MAX,
};
function isOutput(out) {
  return out.value !== undefined;
}
class Transaction {
  constructor() {
    this.version = 1;
    this.locktime = 0;
    this.ins = [];
    this.outs = [];
  }
  static fromBuffer(buffer, _NO_STRICT) {
    const bufferReader = new bufferutils_1.BufferReader(buffer);
    const tx = new Transaction();
    tx.version = bufferReader.readInt32();
    const marker = bufferReader.readUInt8();
    const flag = bufferReader.readUInt8();
    let hasWitnesses = false;
    if (
      marker === Transaction.ADVANCED_TRANSACTION_MARKER &&
      flag === Transaction.ADVANCED_TRANSACTION_FLAG
    ) {
      hasWitnesses = true;
    } else {
      bufferReader.offset -= 2;
    }
    const vinLen = bufferReader.readVarInt();
    for (let i = 0; i < vinLen; ++i) {
      tx.ins.push({
        hash: bufferReader.readSlice(32),
        index: bufferReader.readUInt32(),
        script: bufferReader.readVarSlice(),
        sequence: bufferReader.readUInt32(),
        witness: EMPTY_WITNESS,
      });
    }
    const voutLen = bufferReader.readVarInt();
    for (let i = 0; i < voutLen; ++i) {
      tx.outs.push({
        value: bufferReader.readUInt64(),
        script: bufferReader.readVarSlice(),
      });
    }
    if (hasWitnesses) {
      for (let i = 0; i < vinLen; ++i) {
        tx.ins[i].witness = bufferReader.readVector();
      }
      // was this pointless?
      if (!tx.hasWitnesses())
        throw new Error('Transaction has superfluous witness data');
    }
    tx.locktime = bufferReader.readUInt32();
    if (_NO_STRICT) return tx;
    if (bufferReader.offset !== buffer.length)
      throw new Error('Transaction has unexpected data');
    return tx;
  }
  static fromHex(hex) {
    return Transaction.fromBuffer(Buffer.from(hex, 'hex'), false);
  }
  static isCoinbaseHash(buffer) {
    typeforce(types.Hash256bit, buffer);
    for (let i = 0; i < 32; ++i) {
      if (buffer[i] !== 0) return false;
    }
    return true;
  }
  isCoinbase() {
    return (
      this.ins.length === 1 && Transaction.isCoinbaseHash(this.ins[0].hash)
    );
  }
  addInput(hash, index, sequence, scriptSig) {
    typeforce(
      types.tuple(
        types.Hash256bit,
        types.UInt32,
        types.maybe(types.UInt32),
        types.maybe(types.Buffer),
      ),
      arguments,
    );
    if (types.Null(sequence)) {
      sequence = Transaction.DEFAULT_SEQUENCE;
    }
    // Add the input and return the input's index
    return (
      this.ins.push({
        hash,
        index,
        script: scriptSig || EMPTY_BUFFER,
        sequence: sequence,
        witness: EMPTY_WITNESS,
      }) - 1
    );
  }
  addOutput(scriptPubKey, value) {
    typeforce(types.tuple(types.Buffer, types.Satoshi), arguments);
    // Add the output and return the output's index
    return (
      this.outs.push({
        script: scriptPubKey,
        value,
      }) - 1
    );
  }
  hasWitnesses() {
    return this.ins.some(x => {
      return x.witness.length !== 0;
    });
  }
  weight() {
    const base = this.byteLength(false);
    const total = this.byteLength(true);
    return base * 3 + total;
  }
  virtualSize() {
    return Math.ceil(this.weight() / 4);
  }
  byteLength(_ALLOW_WITNESS = true) {
    const hasWitnesses = _ALLOW_WITNESS && this.hasWitnesses();
    return (
      (hasWitnesses ? 10 : 8) +
      bufferutils_1.varuint.encodingLength(this.ins.length) +
      bufferutils_1.varuint.encodingLength(this.outs.length) +
      this.ins.reduce((sum, input) => {
        return sum + 40 + varSliceSize(input.script);
      }, 0) +
      this.outs.reduce((sum, output) => {
        return sum + 8 + varSliceSize(output.script);
      }, 0) +
      (hasWitnesses
        ? this.ins.reduce((sum, input) => {
            return sum + vectorSize(input.witness);
          }, 0)
        : 0)
    );
  }
  clone() {
    const newTx = new Transaction();
    newTx.version = this.version;
    newTx.locktime = this.locktime;
    newTx.ins = this.ins.map(txIn => {
      return {
        hash: txIn.hash,
        index: txIn.index,
        script: txIn.script,
        sequence: txIn.sequence,
        witness: txIn.witness,
      };
    });
    newTx.outs = this.outs.map(txOut => {
      return {
        script: txOut.script,
        value: txOut.value,
      };
    });
    return newTx;
  }
  /**
   * Hash transaction for signing a specific input.
   *
   * Bitcoin uses a different hash for each signed transaction input.
   * This method copies the transaction, makes the necessary changes based on the
   * hashType, and then hashes the result.
   * This hash can then be used to sign the provided transaction input.
   */
  hashForSignature(inIndex, prevOutScript, hashType) {
    typeforce(
      types.tuple(types.UInt32, types.Buffer, /* types.UInt8 */ types.Number),
      arguments,
    );
    // https://github.com/bitcoin/bitcoin/blob/master/src/test/sighash_tests.cpp#L29
    if (inIndex >= this.ins.length) return ONE;
    // ignore OP_CODESEPARATOR
    const ourScript = bscript.compile(
      bscript.decompile(prevOutScript).filter(x => {
        return x !== script_1.OPS.OP_CODESEPARATOR;
      }),
    );
    const txTmp = this.clone();
    // SIGHASH_NONE: ignore all outputs? (wildcard payee)
    if ((hashType & 0x1f) === Transaction.SIGHASH_NONE) {
      txTmp.outs = [];
      // ignore sequence numbers (except at inIndex)
      txTmp.ins.forEach((input, i) => {
        if (i === inIndex) return;
        input.sequence = 0;
      });
      // SIGHASH_SINGLE: ignore all outputs, except at the same index?
    } else if ((hashType & 0x1f) === Transaction.SIGHASH_SINGLE) {
      // https://github.com/bitcoin/bitcoin/blob/master/src/test/sighash_tests.cpp#L60
      if (inIndex >= this.outs.length) return ONE;
      // truncate outputs after
      txTmp.outs.length = inIndex + 1;
      // "blank" outputs before
      for (let i = 0; i < inIndex; i++) {
        txTmp.outs[i] = BLANK_OUTPUT;
      }
      // ignore sequence numbers (except at inIndex)
      txTmp.ins.forEach((input, y) => {
        if (y === inIndex) return;
        input.sequence = 0;
      });
    }
    // SIGHASH_ANYONECANPAY: ignore inputs entirely?
    if (hashType & Transaction.SIGHASH_ANYONECANPAY) {
      txTmp.ins = [txTmp.ins[inIndex]];
      txTmp.ins[0].script = ourScript;
      // SIGHASH_ALL: only ignore input scripts
    } else {
      // "blank" others input scripts
      txTmp.ins.forEach(input => {
        input.script = EMPTY_BUFFER;
      });
      txTmp.ins[inIndex].script = ourScript;
    }
    // serialize and hash
    const buffer = Buffer.allocUnsafe(txTmp.byteLength(false) + 4);
    buffer.writeInt32LE(hashType, buffer.length - 4);
    txTmp.__toBuffer(buffer, 0, false);
    return bcrypto.hash256(buffer);
  }
  hashForWitnessV1(inIndex, prevOutScripts, values, hashType, leafHash, annex) {
    // https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#common-signature-message
    typeforce(
      types.tuple(
        types.UInt32,
        typeforce.arrayOf(types.Buffer),
        typeforce.arrayOf(types.Satoshi),
        types.UInt32,
      ),
      arguments,
    );
    if (
      values.length !== this.ins.length ||
      prevOutScripts.length !== this.ins.length
    ) {
      throw new Error('Must supply prevout script and value for all inputs');
    }
    const outputType =
      hashType === Transaction.SIGHASH_DEFAULT
        ? Transaction.SIGHASH_ALL
        : hashType & Transaction.SIGHASH_OUTPUT_MASK;
    const inputType = hashType & Transaction.SIGHASH_INPUT_MASK;
    const isAnyoneCanPay = inputType === Transaction.SIGHASH_ANYONECANPAY;
    const isNone = outputType === Transaction.SIGHASH_NONE;
    const isSingle = outputType === Transaction.SIGHASH_SINGLE;
    let hashPrevouts = EMPTY_BUFFER;
    let hashAmounts = EMPTY_BUFFER;
    let hashScriptPubKeys = EMPTY_BUFFER;
    let hashSequences = EMPTY_BUFFER;
    let hashOutputs = EMPTY_BUFFER;
    if (!isAnyoneCanPay) {
      let bufferWriter = bufferutils_1.BufferWriter.withCapacity(
        36 * this.ins.length,
      );
      this.ins.forEach(txIn => {
        bufferWriter.writeSlice(txIn.hash);
        bufferWriter.writeUInt32(txIn.index);
      });
      hashPrevouts = bcrypto.sha256(bufferWriter.end());
      bufferWriter = bufferutils_1.BufferWriter.withCapacity(
        8 * this.ins.length,
      );
      values.forEach(value => bufferWriter.writeUInt64(value));
      hashAmounts = bcrypto.sha256(bufferWriter.end());
      bufferWriter = bufferutils_1.BufferWriter.withCapacity(
        prevOutScripts.map(varSliceSize).reduce((a, b) => a + b),
      );
      prevOutScripts.forEach(prevOutScript =>
        bufferWriter.writeVarSlice(prevOutScript),
      );
      hashScriptPubKeys = bcrypto.sha256(bufferWriter.end());
      bufferWriter = bufferutils_1.BufferWriter.withCapacity(
        4 * this.ins.length,
      );
      this.ins.forEach(txIn => bufferWriter.writeUInt32(txIn.sequence));
      hashSequences = bcrypto.sha256(bufferWriter.end());
    }
    if (!(isNone || isSingle)) {
      const txOutsSize = this.outs
        .map(output => 8 + varSliceSize(output.script))
        .reduce((a, b) => a + b);
      const bufferWriter = bufferutils_1.BufferWriter.withCapacity(txOutsSize);
      this.outs.forEach(out => {
        bufferWriter.writeUInt64(out.value);
        bufferWriter.writeVarSlice(out.script);
      });
      hashOutputs = bcrypto.sha256(bufferWriter.end());
    } else if (isSingle && inIndex < this.outs.length) {
      const output = this.outs[inIndex];
      const bufferWriter = bufferutils_1.BufferWriter.withCapacity(
        8 + varSliceSize(output.script),
      );
      bufferWriter.writeUInt64(output.value);
      bufferWriter.writeVarSlice(output.script);
      hashOutputs = bcrypto.sha256(bufferWriter.end());
    }
    const spendType = (leafHash ? 2 : 0) + (annex ? 1 : 0);
    // Length calculation from:
    // https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#cite_note-14
    // With extension from:
    // https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki#signature-validation
    const sigMsgSize =
      174 -
      (isAnyoneCanPay ? 49 : 0) -
      (isNone ? 32 : 0) +
      (annex ? 32 : 0) +
      (leafHash ? 37 : 0);
    const sigMsgWriter = bufferutils_1.BufferWriter.withCapacity(sigMsgSize);
    sigMsgWriter.writeUInt8(hashType);
    // Transaction
    sigMsgWriter.writeInt32(this.version);
    sigMsgWriter.writeUInt32(this.locktime);
    sigMsgWriter.writeSlice(hashPrevouts);
    sigMsgWriter.writeSlice(hashAmounts);
    sigMsgWriter.writeSlice(hashScriptPubKeys);
    sigMsgWriter.writeSlice(hashSequences);
    if (!(isNone || isSingle)) {
      sigMsgWriter.writeSlice(hashOutputs);
    }
    // Input
    sigMsgWriter.writeUInt8(spendType);
    if (isAnyoneCanPay) {
      const input = this.ins[inIndex];
      sigMsgWriter.writeSlice(input.hash);
      sigMsgWriter.writeUInt32(input.index);
      sigMsgWriter.writeUInt64(values[inIndex]);
      sigMsgWriter.writeVarSlice(prevOutScripts[inIndex]);
      sigMsgWriter.writeUInt32(input.sequence);
    } else {
      sigMsgWriter.writeUInt32(inIndex);
    }
    if (annex) {
      const bufferWriter = bufferutils_1.BufferWriter.withCapacity(
        varSliceSize(annex),
      );
      bufferWriter.writeVarSlice(annex);
      sigMsgWriter.writeSlice(bcrypto.sha256(bufferWriter.end()));
    }
    // Output
    if (isSingle) {
      sigMsgWriter.writeSlice(hashOutputs);
    }
    // BIP342 extension
    if (leafHash) {
      sigMsgWriter.writeSlice(leafHash);
      sigMsgWriter.writeUInt8(0);
      sigMsgWriter.writeUInt32(0xffffffff);
    }
    // Extra zero byte because:
    // https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#cite_note-19
    return bcrypto.taggedHash(
      'TapSighash',
      Buffer.concat([Buffer.from([0x00]), sigMsgWriter.end()]),
    );
  }
  hashForWitnessV0(inIndex, prevOutScript, value, hashType) {
    typeforce(
      types.tuple(types.UInt32, types.Buffer, types.Satoshi, types.UInt32),
      arguments,
    );
    let tbuffer = Buffer.from([]);
    let bufferWriter;
    let hashOutputs = ZERO;
    let hashPrevouts = ZERO;
    let hashSequence = ZERO;
    if (!(hashType & Transaction.SIGHASH_ANYONECANPAY)) {
      tbuffer = Buffer.allocUnsafe(36 * this.ins.length);
      bufferWriter = new bufferutils_1.BufferWriter(tbuffer, 0);
      this.ins.forEach(txIn => {
        bufferWriter.writeSlice(txIn.hash);
        bufferWriter.writeUInt32(txIn.index);
      });
      hashPrevouts = bcrypto.hash256(tbuffer);
    }
    if (
      !(hashType & Transaction.SIGHASH_ANYONECANPAY) &&
      (hashType & 0x1f) !== Transaction.SIGHASH_SINGLE &&
      (hashType & 0x1f) !== Transaction.SIGHASH_NONE
    ) {
      tbuffer = Buffer.allocUnsafe(4 * this.ins.length);
      bufferWriter = new bufferutils_1.BufferWriter(tbuffer, 0);
      this.ins.forEach(txIn => {
        bufferWriter.writeUInt32(txIn.sequence);
      });
      hashSequence = bcrypto.hash256(tbuffer);
    }
    if (
      (hashType & 0x1f) !== Transaction.SIGHASH_SINGLE &&
      (hashType & 0x1f) !== Transaction.SIGHASH_NONE
    ) {
      const txOutsSize = this.outs.reduce((sum, output) => {
        return sum + 8 + varSliceSize(output.script);
      }, 0);
      tbuffer = Buffer.allocUnsafe(txOutsSize);
      bufferWriter = new bufferutils_1.BufferWriter(tbuffer, 0);
      this.outs.forEach(out => {
        bufferWriter.writeUInt64(out.value);
        bufferWriter.writeVarSlice(out.script);
      });
      hashOutputs = bcrypto.hash256(tbuffer);
    } else if (
      (hashType & 0x1f) === Transaction.SIGHASH_SINGLE &&
      inIndex < this.outs.length
    ) {
      const output = this.outs[inIndex];
      tbuffer = Buffer.allocUnsafe(8 + varSliceSize(output.script));
      bufferWriter = new bufferutils_1.BufferWriter(tbuffer, 0);
      bufferWriter.writeUInt64(output.value);
      bufferWriter.writeVarSlice(output.script);
      hashOutputs = bcrypto.hash256(tbuffer);
    }
    tbuffer = Buffer.allocUnsafe(156 + varSliceSize(prevOutScript));
    bufferWriter = new bufferutils_1.BufferWriter(tbuffer, 0);
    const input = this.ins[inIndex];
    bufferWriter.writeInt32(this.version);
    bufferWriter.writeSlice(hashPrevouts);
    bufferWriter.writeSlice(hashSequence);
    bufferWriter.writeSlice(input.hash);
    bufferWriter.writeUInt32(input.index);
    bufferWriter.writeVarSlice(prevOutScript);
    bufferWriter.writeUInt64(value);
    bufferWriter.writeUInt32(input.sequence);
    bufferWriter.writeSlice(hashOutputs);
    bufferWriter.writeUInt32(this.locktime);
    bufferWriter.writeUInt32(hashType);
    return bcrypto.hash256(tbuffer);
  }
  getHash(forWitness) {
    // wtxid for coinbase is always 32 bytes of 0x00
    if (forWitness && this.isCoinbase()) return Buffer.alloc(32, 0);
    return bcrypto.hash256(this.__toBuffer(undefined, undefined, forWitness));
  }
  getId() {
    // transaction hash's are displayed in reverse order
    return (0, bufferutils_1.reverseBuffer)(this.getHash(false)).toString(
      'hex',
    );
  }
  toBuffer(buffer, initialOffset) {
    return this.__toBuffer(buffer, initialOffset, true);
  }
  toHex() {
    return this.toBuffer(undefined, undefined).toString('hex');
  }
  setInputScript(index, scriptSig) {
    typeforce(types.tuple(types.Number, types.Buffer), arguments);
    this.ins[index].script = scriptSig;
  }
  setWitness(index, witness) {
    typeforce(types.tuple(types.Number, [types.Buffer]), arguments);
    this.ins[index].witness = witness;
  }
  __toBuffer(buffer, initialOffset, _ALLOW_WITNESS = false) {
    if (!buffer) buffer = Buffer.allocUnsafe(this.byteLength(_ALLOW_WITNESS));
    const bufferWriter = new bufferutils_1.BufferWriter(
      buffer,
      initialOffset || 0,
    );
    bufferWriter.writeInt32(this.version);
    const hasWitnesses = _ALLOW_WITNESS && this.hasWitnesses();
    if (hasWitnesses) {
      bufferWriter.writeUInt8(Transaction.ADVANCED_TRANSACTION_MARKER);
      bufferWriter.writeUInt8(Transaction.ADVANCED_TRANSACTION_FLAG);
    }
    bufferWriter.writeVarInt(this.ins.length);
    this.ins.forEach(txIn => {
      bufferWriter.writeSlice(txIn.hash);
      bufferWriter.writeUInt32(txIn.index);
      bufferWriter.writeVarSlice(txIn.script);
      bufferWriter.writeUInt32(txIn.sequence);
    });
    bufferWriter.writeVarInt(this.outs.length);
    this.outs.forEach(txOut => {
      if (isOutput(txOut)) {
        bufferWriter.writeUInt64(txOut.value);
      } else {
        bufferWriter.writeSlice(txOut.valueBuffer);
      }
      bufferWriter.writeVarSlice(txOut.script);
    });
    if (hasWitnesses) {
      this.ins.forEach(input => {
        bufferWriter.writeVector(input.witness);
      });
    }
    bufferWriter.writeUInt32(this.locktime);
    // avoid slicing unless necessary
    if (initialOffset !== undefined)
      return buffer.slice(initialOffset, bufferWriter.offset);
    return buffer;
  }
}
exports.Transaction = Transaction;
Transaction.DEFAULT_SEQUENCE = 0xffffffff;
Transaction.SIGHASH_DEFAULT = 0x00;
Transaction.SIGHASH_ALL = 0x01;
Transaction.SIGHASH_NONE = 0x02;
Transaction.SIGHASH_SINGLE = 0x03;
Transaction.SIGHASH_ANYONECANPAY = 0x80;
Transaction.SIGHASH_OUTPUT_MASK = 0x03;
Transaction.SIGHASH_INPUT_MASK = 0x80;
Transaction.ADVANCED_TRANSACTION_MARKER = 0x00;
Transaction.ADVANCED_TRANSACTION_FLAG = 0x01;

}).call(this)}).call(this,require("buffer").Buffer)
},{"./bufferutils":63,"./crypto":64,"./script":85,"./types":89,"buffer":97}],89:[function(require,module,exports){
'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.oneOf =
  exports.Null =
  exports.BufferN =
  exports.Function =
  exports.UInt32 =
  exports.UInt8 =
  exports.tuple =
  exports.maybe =
  exports.Hex =
  exports.Buffer =
  exports.String =
  exports.Boolean =
  exports.Array =
  exports.Number =
  exports.Hash256bit =
  exports.Hash160bit =
  exports.Buffer256bit =
  exports.isTaptree =
  exports.isTapleaf =
  exports.TAPLEAF_VERSION_MASK =
  exports.Network =
  exports.ECPoint =
  exports.Satoshi =
  exports.Signer =
  exports.BIP32Path =
  exports.UInt31 =
  exports.isPoint =
  exports.typeforce =
    void 0;
const buffer_1 = require('buffer');
exports.typeforce = require('typeforce');
const ZERO32 = buffer_1.Buffer.alloc(32, 0);
const EC_P = buffer_1.Buffer.from(
  'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f',
  'hex',
);
function isPoint(p) {
  if (!buffer_1.Buffer.isBuffer(p)) return false;
  if (p.length < 33) return false;
  const t = p[0];
  const x = p.slice(1, 33);
  if (x.compare(ZERO32) === 0) return false;
  if (x.compare(EC_P) >= 0) return false;
  if ((t === 0x02 || t === 0x03) && p.length === 33) {
    return true;
  }
  const y = p.slice(33);
  if (y.compare(ZERO32) === 0) return false;
  if (y.compare(EC_P) >= 0) return false;
  if (t === 0x04 && p.length === 65) return true;
  return false;
}
exports.isPoint = isPoint;
const UINT31_MAX = Math.pow(2, 31) - 1;
function UInt31(value) {
  return exports.typeforce.UInt32(value) && value <= UINT31_MAX;
}
exports.UInt31 = UInt31;
function BIP32Path(value) {
  return (
    exports.typeforce.String(value) && !!value.match(/^(m\/)?(\d+'?\/)*\d+'?$/)
  );
}
exports.BIP32Path = BIP32Path;
BIP32Path.toJSON = () => {
  return 'BIP32 derivation path';
};
function Signer(obj) {
  return (
    (exports.typeforce.Buffer(obj.publicKey) ||
      typeof obj.getPublicKey === 'function') &&
    typeof obj.sign === 'function'
  );
}
exports.Signer = Signer;
const SATOSHI_MAX = 21 * 1e14;
function Satoshi(value) {
  return exports.typeforce.UInt53(value) && value <= SATOSHI_MAX;
}
exports.Satoshi = Satoshi;
// external dependent types
exports.ECPoint = exports.typeforce.quacksLike('Point');
// exposed, external API
exports.Network = exports.typeforce.compile({
  messagePrefix: exports.typeforce.oneOf(
    exports.typeforce.Buffer,
    exports.typeforce.String,
  ),
  bip32: {
    public: exports.typeforce.UInt32,
    private: exports.typeforce.UInt32,
  },
  pubKeyHash: exports.typeforce.UInt8,
  scriptHash: exports.typeforce.UInt8,
  wif: exports.typeforce.UInt8,
});
exports.TAPLEAF_VERSION_MASK = 0xfe;
function isTapleaf(o) {
  if (!o || !('output' in o)) return false;
  if (!buffer_1.Buffer.isBuffer(o.output)) return false;
  if (o.version !== undefined)
    return (o.version & exports.TAPLEAF_VERSION_MASK) === o.version;
  return true;
}
exports.isTapleaf = isTapleaf;
function isTaptree(scriptTree) {
  if (!(0, exports.Array)(scriptTree)) return isTapleaf(scriptTree);
  if (scriptTree.length !== 2) return false;
  return scriptTree.every(t => isTaptree(t));
}
exports.isTaptree = isTaptree;
exports.Buffer256bit = exports.typeforce.BufferN(32);
exports.Hash160bit = exports.typeforce.BufferN(20);
exports.Hash256bit = exports.typeforce.BufferN(32);
exports.Number = exports.typeforce.Number;
exports.Array = exports.typeforce.Array;
exports.Boolean = exports.typeforce.Boolean;
exports.String = exports.typeforce.String;
exports.Buffer = exports.typeforce.Buffer;
exports.Hex = exports.typeforce.Hex;
exports.maybe = exports.typeforce.maybe;
exports.tuple = exports.typeforce.tuple;
exports.UInt8 = exports.typeforce.UInt8;
exports.UInt32 = exports.typeforce.UInt32;
exports.Function = exports.typeforce.Function;
exports.BufferN = exports.typeforce.BufferN;
exports.Null = exports.typeforce.Null;
exports.oneOf = exports.typeforce.oneOf;

},{"buffer":97,"typeforce":93}],90:[function(require,module,exports){
/*! safe-buffer. MIT License. Feross Aboukhadijeh <https://feross.org/opensource> */
/* eslint-disable node/no-deprecated-api */
var buffer = require('buffer')
var Buffer = buffer.Buffer

// alternative to using Object.keys for old browsers
function copyProps (src, dst) {
  for (var key in src) {
    dst[key] = src[key]
  }
}
if (Buffer.from && Buffer.alloc && Buffer.allocUnsafe && Buffer.allocUnsafeSlow) {
  module.exports = buffer
} else {
  // Copy properties from require('buffer')
  copyProps(buffer, exports)
  exports.Buffer = SafeBuffer
}

function SafeBuffer (arg, encodingOrOffset, length) {
  return Buffer(arg, encodingOrOffset, length)
}

SafeBuffer.prototype = Object.create(Buffer.prototype)

// Copy static methods from Buffer
copyProps(Buffer, SafeBuffer)

SafeBuffer.from = function (arg, encodingOrOffset, length) {
  if (typeof arg === 'number') {
    throw new TypeError('Argument must not be a number')
  }
  return Buffer(arg, encodingOrOffset, length)
}

SafeBuffer.alloc = function (size, fill, encoding) {
  if (typeof size !== 'number') {
    throw new TypeError('Argument must be a number')
  }
  var buf = Buffer(size)
  if (fill !== undefined) {
    if (typeof encoding === 'string') {
      buf.fill(fill, encoding)
    } else {
      buf.fill(fill)
    }
  } else {
    buf.fill(0)
  }
  return buf
}

SafeBuffer.allocUnsafe = function (size) {
  if (typeof size !== 'number') {
    throw new TypeError('Argument must be a number')
  }
  return Buffer(size)
}

SafeBuffer.allocUnsafeSlow = function (size) {
  if (typeof size !== 'number') {
    throw new TypeError('Argument must be a number')
  }
  return buffer.SlowBuffer(size)
}

},{"buffer":97}],91:[function(require,module,exports){
var native = require('./native')

function getTypeName (fn) {
  return fn.name || fn.toString().match(/function (.*?)\s*\(/)[1]
}

function getValueTypeName (value) {
  return native.Nil(value) ? '' : getTypeName(value.constructor)
}

function getValue (value) {
  if (native.Function(value)) return ''
  if (native.String(value)) return JSON.stringify(value)
  if (value && native.Object(value)) return ''
  return value
}

function captureStackTrace (e, t) {
  if (Error.captureStackTrace) {
    Error.captureStackTrace(e, t)
  }
}

function tfJSON (type) {
  if (native.Function(type)) return type.toJSON ? type.toJSON() : getTypeName(type)
  if (native.Array(type)) return 'Array'
  if (type && native.Object(type)) return 'Object'

  return type !== undefined ? type : ''
}

function tfErrorString (type, value, valueTypeName) {
  var valueJson = getValue(value)

  return 'Expected ' + tfJSON(type) + ', got' +
    (valueTypeName !== '' ? ' ' + valueTypeName : '') +
    (valueJson !== '' ? ' ' + valueJson : '')
}

function TfTypeError (type, value, valueTypeName) {
  valueTypeName = valueTypeName || getValueTypeName(value)
  this.message = tfErrorString(type, value, valueTypeName)

  captureStackTrace(this, TfTypeError)
  this.__type = type
  this.__value = value
  this.__valueTypeName = valueTypeName
}

TfTypeError.prototype = Object.create(Error.prototype)
TfTypeError.prototype.constructor = TfTypeError

function tfPropertyErrorString (type, label, name, value, valueTypeName) {
  var description = '" of type '
  if (label === 'key') description = '" with key type '

  return tfErrorString('property "' + tfJSON(name) + description + tfJSON(type), value, valueTypeName)
}

function TfPropertyTypeError (type, property, label, value, valueTypeName) {
  if (type) {
    valueTypeName = valueTypeName || getValueTypeName(value)
    this.message = tfPropertyErrorString(type, label, property, value, valueTypeName)
  } else {
    this.message = 'Unexpected property "' + property + '"'
  }

  captureStackTrace(this, TfTypeError)
  this.__label = label
  this.__property = property
  this.__type = type
  this.__value = value
  this.__valueTypeName = valueTypeName
}

TfPropertyTypeError.prototype = Object.create(Error.prototype)
TfPropertyTypeError.prototype.constructor = TfTypeError

function tfCustomError (expected, actual) {
  return new TfTypeError(expected, {}, actual)
}

function tfSubError (e, property, label) {
  // sub child?
  if (e instanceof TfPropertyTypeError) {
    property = property + '.' + e.__property

    e = new TfPropertyTypeError(
      e.__type, property, e.__label, e.__value, e.__valueTypeName
    )

  // child?
  } else if (e instanceof TfTypeError) {
    e = new TfPropertyTypeError(
      e.__type, property, label, e.__value, e.__valueTypeName
    )
  }

  captureStackTrace(e)
  return e
}

module.exports = {
  TfTypeError: TfTypeError,
  TfPropertyTypeError: TfPropertyTypeError,
  tfCustomError: tfCustomError,
  tfSubError: tfSubError,
  tfJSON: tfJSON,
  getValueTypeName: getValueTypeName
}

},{"./native":94}],92:[function(require,module,exports){
(function (Buffer){(function (){
var NATIVE = require('./native')
var ERRORS = require('./errors')

function _Buffer (value) {
  return Buffer.isBuffer(value)
}

function Hex (value) {
  return typeof value === 'string' && /^([0-9a-f]{2})+$/i.test(value)
}

function _LengthN (type, length) {
  var name = type.toJSON()

  function Length (value) {
    if (!type(value)) return false
    if (value.length === length) return true

    throw ERRORS.tfCustomError(name + '(Length: ' + length + ')', name + '(Length: ' + value.length + ')')
  }
  Length.toJSON = function () { return name }

  return Length
}

var _ArrayN = _LengthN.bind(null, NATIVE.Array)
var _BufferN = _LengthN.bind(null, _Buffer)
var _HexN = _LengthN.bind(null, Hex)
var _StringN = _LengthN.bind(null, NATIVE.String)

function Range (a, b, f) {
  f = f || NATIVE.Number
  function _range (value, strict) {
    return f(value, strict) && (value > a) && (value < b)
  }
  _range.toJSON = function () {
    return `${f.toJSON()} between [${a}, ${b}]`
  }
  return _range
}

var INT53_MAX = Math.pow(2, 53) - 1

function Finite (value) {
  return typeof value === 'number' && isFinite(value)
}
function Int8 (value) { return ((value << 24) >> 24) === value }
function Int16 (value) { return ((value << 16) >> 16) === value }
function Int32 (value) { return (value | 0) === value }
function Int53 (value) {
  return typeof value === 'number' &&
    value >= -INT53_MAX &&
    value <= INT53_MAX &&
    Math.floor(value) === value
}
function UInt8 (value) { return (value & 0xff) === value }
function UInt16 (value) { return (value & 0xffff) === value }
function UInt32 (value) { return (value >>> 0) === value }
function UInt53 (value) {
  return typeof value === 'number' &&
    value >= 0 &&
    value <= INT53_MAX &&
    Math.floor(value) === value
}

var types = {
  ArrayN: _ArrayN,
  Buffer: _Buffer,
  BufferN: _BufferN,
  Finite: Finite,
  Hex: Hex,
  HexN: _HexN,
  Int8: Int8,
  Int16: Int16,
  Int32: Int32,
  Int53: Int53,
  Range: Range,
  StringN: _StringN,
  UInt8: UInt8,
  UInt16: UInt16,
  UInt32: UInt32,
  UInt53: UInt53
}

for (var typeName in types) {
  types[typeName].toJSON = function (t) {
    return t
  }.bind(null, typeName)
}

module.exports = types

}).call(this)}).call(this,{"isBuffer":require("../../../../../../usr/local/lib/node_modules/browserify/node_modules/is-buffer/index.js")})
},{"../../../../../../usr/local/lib/node_modules/browserify/node_modules/is-buffer/index.js":99,"./errors":91,"./native":94}],93:[function(require,module,exports){
var ERRORS = require('./errors')
var NATIVE = require('./native')

// short-hand
var tfJSON = ERRORS.tfJSON
var TfTypeError = ERRORS.TfTypeError
var TfPropertyTypeError = ERRORS.TfPropertyTypeError
var tfSubError = ERRORS.tfSubError
var getValueTypeName = ERRORS.getValueTypeName

var TYPES = {
  arrayOf: function arrayOf (type, options) {
    type = compile(type)
    options = options || {}

    function _arrayOf (array, strict) {
      if (!NATIVE.Array(array)) return false
      if (NATIVE.Nil(array)) return false
      if (options.minLength !== undefined && array.length < options.minLength) return false
      if (options.maxLength !== undefined && array.length > options.maxLength) return false
      if (options.length !== undefined && array.length !== options.length) return false

      return array.every(function (value, i) {
        try {
          return typeforce(type, value, strict)
        } catch (e) {
          throw tfSubError(e, i)
        }
      })
    }
    _arrayOf.toJSON = function () {
      var str = '[' + tfJSON(type) + ']'
      if (options.length !== undefined) {
        str += '{' + options.length + '}'
      } else if (options.minLength !== undefined || options.maxLength !== undefined) {
        str += '{' +
          (options.minLength === undefined ? 0 : options.minLength) + ',' +
          (options.maxLength === undefined ? Infinity : options.maxLength) + '}'
      }
      return str
    }

    return _arrayOf
  },

  maybe: function maybe (type) {
    type = compile(type)

    function _maybe (value, strict) {
      return NATIVE.Nil(value) || type(value, strict, maybe)
    }
    _maybe.toJSON = function () { return '?' + tfJSON(type) }

    return _maybe
  },

  map: function map (propertyType, propertyKeyType) {
    propertyType = compile(propertyType)
    if (propertyKeyType) propertyKeyType = compile(propertyKeyType)

    function _map (value, strict) {
      if (!NATIVE.Object(value)) return false
      if (NATIVE.Nil(value)) return false

      for (var propertyName in value) {
        try {
          if (propertyKeyType) {
            typeforce(propertyKeyType, propertyName, strict)
          }
        } catch (e) {
          throw tfSubError(e, propertyName, 'key')
        }

        try {
          var propertyValue = value[propertyName]
          typeforce(propertyType, propertyValue, strict)
        } catch (e) {
          throw tfSubError(e, propertyName)
        }
      }

      return true
    }

    if (propertyKeyType) {
      _map.toJSON = function () {
        return '{' + tfJSON(propertyKeyType) + ': ' + tfJSON(propertyType) + '}'
      }
    } else {
      _map.toJSON = function () { return '{' + tfJSON(propertyType) + '}' }
    }

    return _map
  },

  object: function object (uncompiled) {
    var type = {}

    for (var typePropertyName in uncompiled) {
      type[typePropertyName] = compile(uncompiled[typePropertyName])
    }

    function _object (value, strict) {
      if (!NATIVE.Object(value)) return false
      if (NATIVE.Nil(value)) return false

      var propertyName

      try {
        for (propertyName in type) {
          var propertyType = type[propertyName]
          var propertyValue = value[propertyName]

          typeforce(propertyType, propertyValue, strict)
        }
      } catch (e) {
        throw tfSubError(e, propertyName)
      }

      if (strict) {
        for (propertyName in value) {
          if (type[propertyName]) continue

          throw new TfPropertyTypeError(undefined, propertyName)
        }
      }

      return true
    }
    _object.toJSON = function () { return tfJSON(type) }

    return _object
  },

  anyOf: function anyOf () {
    var types = [].slice.call(arguments).map(compile)

    function _anyOf (value, strict) {
      return types.some(function (type) {
        try {
          return typeforce(type, value, strict)
        } catch (e) {
          return false
        }
      })
    }
    _anyOf.toJSON = function () { return types.map(tfJSON).join('|') }

    return _anyOf
  },

  allOf: function allOf () {
    var types = [].slice.call(arguments).map(compile)

    function _allOf (value, strict) {
      return types.every(function (type) {
        try {
          return typeforce(type, value, strict)
        } catch (e) {
          return false
        }
      })
    }
    _allOf.toJSON = function () { return types.map(tfJSON).join(' & ') }

    return _allOf
  },

  quacksLike: function quacksLike (type) {
    function _quacksLike (value) {
      return type === getValueTypeName(value)
    }
    _quacksLike.toJSON = function () { return type }

    return _quacksLike
  },

  tuple: function tuple () {
    var types = [].slice.call(arguments).map(compile)

    function _tuple (values, strict) {
      if (NATIVE.Nil(values)) return false
      if (NATIVE.Nil(values.length)) return false
      if (strict && (values.length !== types.length)) return false

      return types.every(function (type, i) {
        try {
          return typeforce(type, values[i], strict)
        } catch (e) {
          throw tfSubError(e, i)
        }
      })
    }
    _tuple.toJSON = function () { return '(' + types.map(tfJSON).join(', ') + ')' }

    return _tuple
  },

  value: function value (expected) {
    function _value (actual) {
      return actual === expected
    }
    _value.toJSON = function () { return expected }

    return _value
  }
}

// TODO: deprecate
TYPES.oneOf = TYPES.anyOf

function compile (type) {
  if (NATIVE.String(type)) {
    if (type[0] === '?') return TYPES.maybe(type.slice(1))

    return NATIVE[type] || TYPES.quacksLike(type)
  } else if (type && NATIVE.Object(type)) {
    if (NATIVE.Array(type)) {
      if (type.length !== 1) throw new TypeError('Expected compile() parameter of type Array of length 1')
      return TYPES.arrayOf(type[0])
    }

    return TYPES.object(type)
  } else if (NATIVE.Function(type)) {
    return type
  }

  return TYPES.value(type)
}

function typeforce (type, value, strict, surrogate) {
  if (NATIVE.Function(type)) {
    if (type(value, strict)) return true

    throw new TfTypeError(surrogate || type, value)
  }

  // JIT
  return typeforce(compile(type), value, strict)
}

// assign types to typeforce function
for (var typeName in NATIVE) {
  typeforce[typeName] = NATIVE[typeName]
}

for (typeName in TYPES) {
  typeforce[typeName] = TYPES[typeName]
}

var EXTRA = require('./extra')
for (typeName in EXTRA) {
  typeforce[typeName] = EXTRA[typeName]
}

typeforce.compile = compile
typeforce.TfTypeError = TfTypeError
typeforce.TfPropertyTypeError = TfPropertyTypeError

module.exports = typeforce

},{"./errors":91,"./extra":92,"./native":94}],94:[function(require,module,exports){
var types = {
  Array: function (value) { return value !== null && value !== undefined && value.constructor === Array },
  Boolean: function (value) { return typeof value === 'boolean' },
  Function: function (value) { return typeof value === 'function' },
  Nil: function (value) { return value === undefined || value === null },
  Number: function (value) { return typeof value === 'number' },
  Object: function (value) { return typeof value === 'object' },
  String: function (value) { return typeof value === 'string' },
  '': function () { return true }
}

// TODO: deprecate
types.Null = types.Nil

for (var typeName in types) {
  types[typeName].toJSON = function (t) {
    return t
  }.bind(null, typeName)
}

module.exports = types

},{}],95:[function(require,module,exports){
'use strict'
var Buffer = require('safe-buffer').Buffer

// Number.MAX_SAFE_INTEGER
var MAX_SAFE_INTEGER = 9007199254740991

function checkUInt53 (n) {
  if (n < 0 || n > MAX_SAFE_INTEGER || n % 1 !== 0) throw new RangeError('value out of range')
}

function encode (number, buffer, offset) {
  checkUInt53(number)

  if (!buffer) buffer = Buffer.allocUnsafe(encodingLength(number))
  if (!Buffer.isBuffer(buffer)) throw new TypeError('buffer must be a Buffer instance')
  if (!offset) offset = 0

  // 8 bit
  if (number < 0xfd) {
    buffer.writeUInt8(number, offset)
    encode.bytes = 1

  // 16 bit
  } else if (number <= 0xffff) {
    buffer.writeUInt8(0xfd, offset)
    buffer.writeUInt16LE(number, offset + 1)
    encode.bytes = 3

  // 32 bit
  } else if (number <= 0xffffffff) {
    buffer.writeUInt8(0xfe, offset)
    buffer.writeUInt32LE(number, offset + 1)
    encode.bytes = 5

  // 64 bit
  } else {
    buffer.writeUInt8(0xff, offset)
    buffer.writeUInt32LE(number >>> 0, offset + 1)
    buffer.writeUInt32LE((number / 0x100000000) | 0, offset + 5)
    encode.bytes = 9
  }

  return buffer
}

function decode (buffer, offset) {
  if (!Buffer.isBuffer(buffer)) throw new TypeError('buffer must be a Buffer instance')
  if (!offset) offset = 0

  var first = buffer.readUInt8(offset)

  // 8 bit
  if (first < 0xfd) {
    decode.bytes = 1
    return first

  // 16 bit
  } else if (first === 0xfd) {
    decode.bytes = 3
    return buffer.readUInt16LE(offset + 1)

  // 32 bit
  } else if (first === 0xfe) {
    decode.bytes = 5
    return buffer.readUInt32LE(offset + 1)

  // 64 bit
  } else {
    decode.bytes = 9
    var lo = buffer.readUInt32LE(offset + 1)
    var hi = buffer.readUInt32LE(offset + 5)
    var number = hi * 0x0100000000 + lo
    checkUInt53(number)

    return number
  }
}

function encodingLength (number) {
  checkUInt53(number)

  return (
    number < 0xfd ? 1
      : number <= 0xffff ? 3
        : number <= 0xffffffff ? 5
          : 9
  )
}

module.exports = { encode: encode, decode: decode, encodingLength: encodingLength }

},{"safe-buffer":90}],96:[function(require,module,exports){
'use strict'

exports.byteLength = byteLength
exports.toByteArray = toByteArray
exports.fromByteArray = fromByteArray

var lookup = []
var revLookup = []
var Arr = typeof Uint8Array !== 'undefined' ? Uint8Array : Array

var code = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
for (var i = 0, len = code.length; i < len; ++i) {
  lookup[i] = code[i]
  revLookup[code.charCodeAt(i)] = i
}

// Support decoding URL-safe base64 strings, as Node.js does.
// See: https://en.wikipedia.org/wiki/Base64#URL_applications
revLookup['-'.charCodeAt(0)] = 62
revLookup['_'.charCodeAt(0)] = 63

function getLens (b64) {
  var len = b64.length

  if (len % 4 > 0) {
    throw new Error('Invalid string. Length must be a multiple of 4')
  }

  // Trim off extra bytes after placeholder bytes are found
  // See: https://github.com/beatgammit/base64-js/issues/42
  var validLen = b64.indexOf('=')
  if (validLen === -1) validLen = len

  var placeHoldersLen = validLen === len
    ? 0
    : 4 - (validLen % 4)

  return [validLen, placeHoldersLen]
}

// base64 is 4/3 + up to two characters of the original data
function byteLength (b64) {
  var lens = getLens(b64)
  var validLen = lens[0]
  var placeHoldersLen = lens[1]
  return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
}

function _byteLength (b64, validLen, placeHoldersLen) {
  return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
}

function toByteArray (b64) {
  var tmp
  var lens = getLens(b64)
  var validLen = lens[0]
  var placeHoldersLen = lens[1]

  var arr = new Arr(_byteLength(b64, validLen, placeHoldersLen))

  var curByte = 0

  // if there are placeholders, only get up to the last complete 4 chars
  var len = placeHoldersLen > 0
    ? validLen - 4
    : validLen

  var i
  for (i = 0; i < len; i += 4) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 18) |
      (revLookup[b64.charCodeAt(i + 1)] << 12) |
      (revLookup[b64.charCodeAt(i + 2)] << 6) |
      revLookup[b64.charCodeAt(i + 3)]
    arr[curByte++] = (tmp >> 16) & 0xFF
    arr[curByte++] = (tmp >> 8) & 0xFF
    arr[curByte++] = tmp & 0xFF
  }

  if (placeHoldersLen === 2) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 2) |
      (revLookup[b64.charCodeAt(i + 1)] >> 4)
    arr[curByte++] = tmp & 0xFF
  }

  if (placeHoldersLen === 1) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 10) |
      (revLookup[b64.charCodeAt(i + 1)] << 4) |
      (revLookup[b64.charCodeAt(i + 2)] >> 2)
    arr[curByte++] = (tmp >> 8) & 0xFF
    arr[curByte++] = tmp & 0xFF
  }

  return arr
}

function tripletToBase64 (num) {
  return lookup[num >> 18 & 0x3F] +
    lookup[num >> 12 & 0x3F] +
    lookup[num >> 6 & 0x3F] +
    lookup[num & 0x3F]
}

function encodeChunk (uint8, start, end) {
  var tmp
  var output = []
  for (var i = start; i < end; i += 3) {
    tmp =
      ((uint8[i] << 16) & 0xFF0000) +
      ((uint8[i + 1] << 8) & 0xFF00) +
      (uint8[i + 2] & 0xFF)
    output.push(tripletToBase64(tmp))
  }
  return output.join('')
}

function fromByteArray (uint8) {
  var tmp
  var len = uint8.length
  var extraBytes = len % 3 // if we have 1 byte left, pad 2 bytes
  var parts = []
  var maxChunkLength = 16383 // must be multiple of 3

  // go through the array every three bytes, we'll deal with trailing stuff later
  for (var i = 0, len2 = len - extraBytes; i < len2; i += maxChunkLength) {
    parts.push(encodeChunk(uint8, i, (i + maxChunkLength) > len2 ? len2 : (i + maxChunkLength)))
  }

  // pad the end with zeros, but make sure to not forget the extra bytes
  if (extraBytes === 1) {
    tmp = uint8[len - 1]
    parts.push(
      lookup[tmp >> 2] +
      lookup[(tmp << 4) & 0x3F] +
      '=='
    )
  } else if (extraBytes === 2) {
    tmp = (uint8[len - 2] << 8) + uint8[len - 1]
    parts.push(
      lookup[tmp >> 10] +
      lookup[(tmp >> 4) & 0x3F] +
      lookup[(tmp << 2) & 0x3F] +
      '='
    )
  }

  return parts.join('')
}

},{}],97:[function(require,module,exports){
(function (Buffer){(function (){
/*!
 * The buffer module from node.js, for the browser.
 *
 * @author   Feross Aboukhadijeh <https://feross.org>
 * @license  MIT
 */
/* eslint-disable no-proto */

'use strict'

var base64 = require('base64-js')
var ieee754 = require('ieee754')

exports.Buffer = Buffer
exports.SlowBuffer = SlowBuffer
exports.INSPECT_MAX_BYTES = 50

var K_MAX_LENGTH = 0x7fffffff
exports.kMaxLength = K_MAX_LENGTH

/**
 * If `Buffer.TYPED_ARRAY_SUPPORT`:
 *   === true    Use Uint8Array implementation (fastest)
 *   === false   Print warning and recommend using `buffer` v4.x which has an Object
 *               implementation (most compatible, even IE6)
 *
 * Browsers that support typed arrays are IE 10+, Firefox 4+, Chrome 7+, Safari 5.1+,
 * Opera 11.6+, iOS 4.2+.
 *
 * We report that the browser does not support typed arrays if the are not subclassable
 * using __proto__. Firefox 4-29 lacks support for adding new properties to `Uint8Array`
 * (See: https://bugzilla.mozilla.org/show_bug.cgi?id=695438). IE 10 lacks support
 * for __proto__ and has a buggy typed array implementation.
 */
Buffer.TYPED_ARRAY_SUPPORT = typedArraySupport()

if (!Buffer.TYPED_ARRAY_SUPPORT && typeof console !== 'undefined' &&
    typeof console.error === 'function') {
  console.error(
    'This browser lacks typed array (Uint8Array) support which is required by ' +
    '`buffer` v5.x. Use `buffer` v4.x if you require old browser support.'
  )
}

function typedArraySupport () {
  // Can typed array instances can be augmented?
  try {
    var arr = new Uint8Array(1)
    arr.__proto__ = { __proto__: Uint8Array.prototype, foo: function () { return 42 } }
    return arr.foo() === 42
  } catch (e) {
    return false
  }
}

Object.defineProperty(Buffer.prototype, 'parent', {
  enumerable: true,
  get: function () {
    if (!Buffer.isBuffer(this)) return undefined
    return this.buffer
  }
})

Object.defineProperty(Buffer.prototype, 'offset', {
  enumerable: true,
  get: function () {
    if (!Buffer.isBuffer(this)) return undefined
    return this.byteOffset
  }
})

function createBuffer (length) {
  if (length > K_MAX_LENGTH) {
    throw new RangeError('The value "' + length + '" is invalid for option "size"')
  }
  // Return an augmented `Uint8Array` instance
  var buf = new Uint8Array(length)
  buf.__proto__ = Buffer.prototype
  return buf
}

/**
 * The Buffer constructor returns instances of `Uint8Array` that have their
 * prototype changed to `Buffer.prototype`. Furthermore, `Buffer` is a subclass of
 * `Uint8Array`, so the returned instances will have all the node `Buffer` methods
 * and the `Uint8Array` methods. Square bracket notation works as expected -- it
 * returns a single octet.
 *
 * The `Uint8Array` prototype remains unmodified.
 */

function Buffer (arg, encodingOrOffset, length) {
  // Common case.
  if (typeof arg === 'number') {
    if (typeof encodingOrOffset === 'string') {
      throw new TypeError(
        'The "string" argument must be of type string. Received type number'
      )
    }
    return allocUnsafe(arg)
  }
  return from(arg, encodingOrOffset, length)
}

// Fix subarray() in ES2016. See: https://github.com/feross/buffer/pull/97
if (typeof Symbol !== 'undefined' && Symbol.species != null &&
    Buffer[Symbol.species] === Buffer) {
  Object.defineProperty(Buffer, Symbol.species, {
    value: null,
    configurable: true,
    enumerable: false,
    writable: false
  })
}

Buffer.poolSize = 8192 // not used by this implementation

function from (value, encodingOrOffset, length) {
  if (typeof value === 'string') {
    return fromString(value, encodingOrOffset)
  }

  if (ArrayBuffer.isView(value)) {
    return fromArrayLike(value)
  }

  if (value == null) {
    throw TypeError(
      'The first argument must be one of type string, Buffer, ArrayBuffer, Array, ' +
      'or Array-like Object. Received type ' + (typeof value)
    )
  }

  if (isInstance(value, ArrayBuffer) ||
      (value && isInstance(value.buffer, ArrayBuffer))) {
    return fromArrayBuffer(value, encodingOrOffset, length)
  }

  if (typeof value === 'number') {
    throw new TypeError(
      'The "value" argument must not be of type number. Received type number'
    )
  }

  var valueOf = value.valueOf && value.valueOf()
  if (valueOf != null && valueOf !== value) {
    return Buffer.from(valueOf, encodingOrOffset, length)
  }

  var b = fromObject(value)
  if (b) return b

  if (typeof Symbol !== 'undefined' && Symbol.toPrimitive != null &&
      typeof value[Symbol.toPrimitive] === 'function') {
    return Buffer.from(
      value[Symbol.toPrimitive]('string'), encodingOrOffset, length
    )
  }

  throw new TypeError(
    'The first argument must be one of type string, Buffer, ArrayBuffer, Array, ' +
    'or Array-like Object. Received type ' + (typeof value)
  )
}

/**
 * Functionally equivalent to Buffer(arg, encoding) but throws a TypeError
 * if value is a number.
 * Buffer.from(str[, encoding])
 * Buffer.from(array)
 * Buffer.from(buffer)
 * Buffer.from(arrayBuffer[, byteOffset[, length]])
 **/
Buffer.from = function (value, encodingOrOffset, length) {
  return from(value, encodingOrOffset, length)
}

// Note: Change prototype *after* Buffer.from is defined to workaround Chrome bug:
// https://github.com/feross/buffer/pull/148
Buffer.prototype.__proto__ = Uint8Array.prototype
Buffer.__proto__ = Uint8Array

function assertSize (size) {
  if (typeof size !== 'number') {
    throw new TypeError('"size" argument must be of type number')
  } else if (size < 0) {
    throw new RangeError('The value "' + size + '" is invalid for option "size"')
  }
}

function alloc (size, fill, encoding) {
  assertSize(size)
  if (size <= 0) {
    return createBuffer(size)
  }
  if (fill !== undefined) {
    // Only pay attention to encoding if it's a string. This
    // prevents accidentally sending in a number that would
    // be interpretted as a start offset.
    return typeof encoding === 'string'
      ? createBuffer(size).fill(fill, encoding)
      : createBuffer(size).fill(fill)
  }
  return createBuffer(size)
}

/**
 * Creates a new filled Buffer instance.
 * alloc(size[, fill[, encoding]])
 **/
Buffer.alloc = function (size, fill, encoding) {
  return alloc(size, fill, encoding)
}

function allocUnsafe (size) {
  assertSize(size)
  return createBuffer(size < 0 ? 0 : checked(size) | 0)
}

/**
 * Equivalent to Buffer(num), by default creates a non-zero-filled Buffer instance.
 * */
Buffer.allocUnsafe = function (size) {
  return allocUnsafe(size)
}
/**
 * Equivalent to SlowBuffer(num), by default creates a non-zero-filled Buffer instance.
 */
Buffer.allocUnsafeSlow = function (size) {
  return allocUnsafe(size)
}

function fromString (string, encoding) {
  if (typeof encoding !== 'string' || encoding === '') {
    encoding = 'utf8'
  }

  if (!Buffer.isEncoding(encoding)) {
    throw new TypeError('Unknown encoding: ' + encoding)
  }

  var length = byteLength(string, encoding) | 0
  var buf = createBuffer(length)

  var actual = buf.write(string, encoding)

  if (actual !== length) {
    // Writing a hex string, for example, that contains invalid characters will
    // cause everything after the first invalid character to be ignored. (e.g.
    // 'abxxcd' will be treated as 'ab')
    buf = buf.slice(0, actual)
  }

  return buf
}

function fromArrayLike (array) {
  var length = array.length < 0 ? 0 : checked(array.length) | 0
  var buf = createBuffer(length)
  for (var i = 0; i < length; i += 1) {
    buf[i] = array[i] & 255
  }
  return buf
}

function fromArrayBuffer (array, byteOffset, length) {
  if (byteOffset < 0 || array.byteLength < byteOffset) {
    throw new RangeError('"offset" is outside of buffer bounds')
  }

  if (array.byteLength < byteOffset + (length || 0)) {
    throw new RangeError('"length" is outside of buffer bounds')
  }

  var buf
  if (byteOffset === undefined && length === undefined) {
    buf = new Uint8Array(array)
  } else if (length === undefined) {
    buf = new Uint8Array(array, byteOffset)
  } else {
    buf = new Uint8Array(array, byteOffset, length)
  }

  // Return an augmented `Uint8Array` instance
  buf.__proto__ = Buffer.prototype
  return buf
}

function fromObject (obj) {
  if (Buffer.isBuffer(obj)) {
    var len = checked(obj.length) | 0
    var buf = createBuffer(len)

    if (buf.length === 0) {
      return buf
    }

    obj.copy(buf, 0, 0, len)
    return buf
  }

  if (obj.length !== undefined) {
    if (typeof obj.length !== 'number' || numberIsNaN(obj.length)) {
      return createBuffer(0)
    }
    return fromArrayLike(obj)
  }

  if (obj.type === 'Buffer' && Array.isArray(obj.data)) {
    return fromArrayLike(obj.data)
  }
}

function checked (length) {
  // Note: cannot use `length < K_MAX_LENGTH` here because that fails when
  // length is NaN (which is otherwise coerced to zero.)
  if (length >= K_MAX_LENGTH) {
    throw new RangeError('Attempt to allocate Buffer larger than maximum ' +
                         'size: 0x' + K_MAX_LENGTH.toString(16) + ' bytes')
  }
  return length | 0
}

function SlowBuffer (length) {
  if (+length != length) { // eslint-disable-line eqeqeq
    length = 0
  }
  return Buffer.alloc(+length)
}

Buffer.isBuffer = function isBuffer (b) {
  return b != null && b._isBuffer === true &&
    b !== Buffer.prototype // so Buffer.isBuffer(Buffer.prototype) will be false
}

Buffer.compare = function compare (a, b) {
  if (isInstance(a, Uint8Array)) a = Buffer.from(a, a.offset, a.byteLength)
  if (isInstance(b, Uint8Array)) b = Buffer.from(b, b.offset, b.byteLength)
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
    throw new TypeError(
      'The "buf1", "buf2" arguments must be one of type Buffer or Uint8Array'
    )
  }

  if (a === b) return 0

  var x = a.length
  var y = b.length

  for (var i = 0, len = Math.min(x, y); i < len; ++i) {
    if (a[i] !== b[i]) {
      x = a[i]
      y = b[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

Buffer.isEncoding = function isEncoding (encoding) {
  switch (String(encoding).toLowerCase()) {
    case 'hex':
    case 'utf8':
    case 'utf-8':
    case 'ascii':
    case 'latin1':
    case 'binary':
    case 'base64':
    case 'ucs2':
    case 'ucs-2':
    case 'utf16le':
    case 'utf-16le':
      return true
    default:
      return false
  }
}

Buffer.concat = function concat (list, length) {
  if (!Array.isArray(list)) {
    throw new TypeError('"list" argument must be an Array of Buffers')
  }

  if (list.length === 0) {
    return Buffer.alloc(0)
  }

  var i
  if (length === undefined) {
    length = 0
    for (i = 0; i < list.length; ++i) {
      length += list[i].length
    }
  }

  var buffer = Buffer.allocUnsafe(length)
  var pos = 0
  for (i = 0; i < list.length; ++i) {
    var buf = list[i]
    if (isInstance(buf, Uint8Array)) {
      buf = Buffer.from(buf)
    }
    if (!Buffer.isBuffer(buf)) {
      throw new TypeError('"list" argument must be an Array of Buffers')
    }
    buf.copy(buffer, pos)
    pos += buf.length
  }
  return buffer
}

function byteLength (string, encoding) {
  if (Buffer.isBuffer(string)) {
    return string.length
  }
  if (ArrayBuffer.isView(string) || isInstance(string, ArrayBuffer)) {
    return string.byteLength
  }
  if (typeof string !== 'string') {
    throw new TypeError(
      'The "string" argument must be one of type string, Buffer, or ArrayBuffer. ' +
      'Received type ' + typeof string
    )
  }

  var len = string.length
  var mustMatch = (arguments.length > 2 && arguments[2] === true)
  if (!mustMatch && len === 0) return 0

  // Use a for loop to avoid recursion
  var loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'ascii':
      case 'latin1':
      case 'binary':
        return len
      case 'utf8':
      case 'utf-8':
        return utf8ToBytes(string).length
      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return len * 2
      case 'hex':
        return len >>> 1
      case 'base64':
        return base64ToBytes(string).length
      default:
        if (loweredCase) {
          return mustMatch ? -1 : utf8ToBytes(string).length // assume utf8
        }
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}
Buffer.byteLength = byteLength

function slowToString (encoding, start, end) {
  var loweredCase = false

  // No need to verify that "this.length <= MAX_UINT32" since it's a read-only
  // property of a typed array.

  // This behaves neither like String nor Uint8Array in that we set start/end
  // to their upper/lower bounds if the value passed is out of range.
  // undefined is handled specially as per ECMA-262 6th Edition,
  // Section 13.3.3.7 Runtime Semantics: KeyedBindingInitialization.
  if (start === undefined || start < 0) {
    start = 0
  }
  // Return early if start > this.length. Done here to prevent potential uint32
  // coercion fail below.
  if (start > this.length) {
    return ''
  }

  if (end === undefined || end > this.length) {
    end = this.length
  }

  if (end <= 0) {
    return ''
  }

  // Force coersion to uint32. This will also coerce falsey/NaN values to 0.
  end >>>= 0
  start >>>= 0

  if (end <= start) {
    return ''
  }

  if (!encoding) encoding = 'utf8'

  while (true) {
    switch (encoding) {
      case 'hex':
        return hexSlice(this, start, end)

      case 'utf8':
      case 'utf-8':
        return utf8Slice(this, start, end)

      case 'ascii':
        return asciiSlice(this, start, end)

      case 'latin1':
      case 'binary':
        return latin1Slice(this, start, end)

      case 'base64':
        return base64Slice(this, start, end)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return utf16leSlice(this, start, end)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = (encoding + '').toLowerCase()
        loweredCase = true
    }
  }
}

// This property is used by `Buffer.isBuffer` (and the `is-buffer` npm package)
// to detect a Buffer instance. It's not possible to use `instanceof Buffer`
// reliably in a browserify context because there could be multiple different
// copies of the 'buffer' package in use. This method works even for Buffer
// instances that were created from another copy of the `buffer` package.
// See: https://github.com/feross/buffer/issues/154
Buffer.prototype._isBuffer = true

function swap (b, n, m) {
  var i = b[n]
  b[n] = b[m]
  b[m] = i
}

Buffer.prototype.swap16 = function swap16 () {
  var len = this.length
  if (len % 2 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 16-bits')
  }
  for (var i = 0; i < len; i += 2) {
    swap(this, i, i + 1)
  }
  return this
}

Buffer.prototype.swap32 = function swap32 () {
  var len = this.length
  if (len % 4 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 32-bits')
  }
  for (var i = 0; i < len; i += 4) {
    swap(this, i, i + 3)
    swap(this, i + 1, i + 2)
  }
  return this
}

Buffer.prototype.swap64 = function swap64 () {
  var len = this.length
  if (len % 8 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 64-bits')
  }
  for (var i = 0; i < len; i += 8) {
    swap(this, i, i + 7)
    swap(this, i + 1, i + 6)
    swap(this, i + 2, i + 5)
    swap(this, i + 3, i + 4)
  }
  return this
}

Buffer.prototype.toString = function toString () {
  var length = this.length
  if (length === 0) return ''
  if (arguments.length === 0) return utf8Slice(this, 0, length)
  return slowToString.apply(this, arguments)
}

Buffer.prototype.toLocaleString = Buffer.prototype.toString

Buffer.prototype.equals = function equals (b) {
  if (!Buffer.isBuffer(b)) throw new TypeError('Argument must be a Buffer')
  if (this === b) return true
  return Buffer.compare(this, b) === 0
}

Buffer.prototype.inspect = function inspect () {
  var str = ''
  var max = exports.INSPECT_MAX_BYTES
  str = this.toString('hex', 0, max).replace(/(.{2})/g, '$1 ').trim()
  if (this.length > max) str += ' ... '
  return '<Buffer ' + str + '>'
}

Buffer.prototype.compare = function compare (target, start, end, thisStart, thisEnd) {
  if (isInstance(target, Uint8Array)) {
    target = Buffer.from(target, target.offset, target.byteLength)
  }
  if (!Buffer.isBuffer(target)) {
    throw new TypeError(
      'The "target" argument must be one of type Buffer or Uint8Array. ' +
      'Received type ' + (typeof target)
    )
  }

  if (start === undefined) {
    start = 0
  }
  if (end === undefined) {
    end = target ? target.length : 0
  }
  if (thisStart === undefined) {
    thisStart = 0
  }
  if (thisEnd === undefined) {
    thisEnd = this.length
  }

  if (start < 0 || end > target.length || thisStart < 0 || thisEnd > this.length) {
    throw new RangeError('out of range index')
  }

  if (thisStart >= thisEnd && start >= end) {
    return 0
  }
  if (thisStart >= thisEnd) {
    return -1
  }
  if (start >= end) {
    return 1
  }

  start >>>= 0
  end >>>= 0
  thisStart >>>= 0
  thisEnd >>>= 0

  if (this === target) return 0

  var x = thisEnd - thisStart
  var y = end - start
  var len = Math.min(x, y)

  var thisCopy = this.slice(thisStart, thisEnd)
  var targetCopy = target.slice(start, end)

  for (var i = 0; i < len; ++i) {
    if (thisCopy[i] !== targetCopy[i]) {
      x = thisCopy[i]
      y = targetCopy[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

// Finds either the first index of `val` in `buffer` at offset >= `byteOffset`,
// OR the last index of `val` in `buffer` at offset <= `byteOffset`.
//
// Arguments:
// - buffer - a Buffer to search
// - val - a string, Buffer, or number
// - byteOffset - an index into `buffer`; will be clamped to an int32
// - encoding - an optional encoding, relevant is val is a string
// - dir - true for indexOf, false for lastIndexOf
function bidirectionalIndexOf (buffer, val, byteOffset, encoding, dir) {
  // Empty buffer means no match
  if (buffer.length === 0) return -1

  // Normalize byteOffset
  if (typeof byteOffset === 'string') {
    encoding = byteOffset
    byteOffset = 0
  } else if (byteOffset > 0x7fffffff) {
    byteOffset = 0x7fffffff
  } else if (byteOffset < -0x80000000) {
    byteOffset = -0x80000000
  }
  byteOffset = +byteOffset // Coerce to Number.
  if (numberIsNaN(byteOffset)) {
    // byteOffset: it it's undefined, null, NaN, "foo", etc, search whole buffer
    byteOffset = dir ? 0 : (buffer.length - 1)
  }

  // Normalize byteOffset: negative offsets start from the end of the buffer
  if (byteOffset < 0) byteOffset = buffer.length + byteOffset
  if (byteOffset >= buffer.length) {
    if (dir) return -1
    else byteOffset = buffer.length - 1
  } else if (byteOffset < 0) {
    if (dir) byteOffset = 0
    else return -1
  }

  // Normalize val
  if (typeof val === 'string') {
    val = Buffer.from(val, encoding)
  }

  // Finally, search either indexOf (if dir is true) or lastIndexOf
  if (Buffer.isBuffer(val)) {
    // Special case: looking for empty string/buffer always fails
    if (val.length === 0) {
      return -1
    }
    return arrayIndexOf(buffer, val, byteOffset, encoding, dir)
  } else if (typeof val === 'number') {
    val = val & 0xFF // Search for a byte value [0-255]
    if (typeof Uint8Array.prototype.indexOf === 'function') {
      if (dir) {
        return Uint8Array.prototype.indexOf.call(buffer, val, byteOffset)
      } else {
        return Uint8Array.prototype.lastIndexOf.call(buffer, val, byteOffset)
      }
    }
    return arrayIndexOf(buffer, [ val ], byteOffset, encoding, dir)
  }

  throw new TypeError('val must be string, number or Buffer')
}

function arrayIndexOf (arr, val, byteOffset, encoding, dir) {
  var indexSize = 1
  var arrLength = arr.length
  var valLength = val.length

  if (encoding !== undefined) {
    encoding = String(encoding).toLowerCase()
    if (encoding === 'ucs2' || encoding === 'ucs-2' ||
        encoding === 'utf16le' || encoding === 'utf-16le') {
      if (arr.length < 2 || val.length < 2) {
        return -1
      }
      indexSize = 2
      arrLength /= 2
      valLength /= 2
      byteOffset /= 2
    }
  }

  function read (buf, i) {
    if (indexSize === 1) {
      return buf[i]
    } else {
      return buf.readUInt16BE(i * indexSize)
    }
  }

  var i
  if (dir) {
    var foundIndex = -1
    for (i = byteOffset; i < arrLength; i++) {
      if (read(arr, i) === read(val, foundIndex === -1 ? 0 : i - foundIndex)) {
        if (foundIndex === -1) foundIndex = i
        if (i - foundIndex + 1 === valLength) return foundIndex * indexSize
      } else {
        if (foundIndex !== -1) i -= i - foundIndex
        foundIndex = -1
      }
    }
  } else {
    if (byteOffset + valLength > arrLength) byteOffset = arrLength - valLength
    for (i = byteOffset; i >= 0; i--) {
      var found = true
      for (var j = 0; j < valLength; j++) {
        if (read(arr, i + j) !== read(val, j)) {
          found = false
          break
        }
      }
      if (found) return i
    }
  }

  return -1
}

Buffer.prototype.includes = function includes (val, byteOffset, encoding) {
  return this.indexOf(val, byteOffset, encoding) !== -1
}

Buffer.prototype.indexOf = function indexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, true)
}

Buffer.prototype.lastIndexOf = function lastIndexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, false)
}

function hexWrite (buf, string, offset, length) {
  offset = Number(offset) || 0
  var remaining = buf.length - offset
  if (!length) {
    length = remaining
  } else {
    length = Number(length)
    if (length > remaining) {
      length = remaining
    }
  }

  var strLen = string.length

  if (length > strLen / 2) {
    length = strLen / 2
  }
  for (var i = 0; i < length; ++i) {
    var parsed = parseInt(string.substr(i * 2, 2), 16)
    if (numberIsNaN(parsed)) return i
    buf[offset + i] = parsed
  }
  return i
}

function utf8Write (buf, string, offset, length) {
  return blitBuffer(utf8ToBytes(string, buf.length - offset), buf, offset, length)
}

function asciiWrite (buf, string, offset, length) {
  return blitBuffer(asciiToBytes(string), buf, offset, length)
}

function latin1Write (buf, string, offset, length) {
  return asciiWrite(buf, string, offset, length)
}

function base64Write (buf, string, offset, length) {
  return blitBuffer(base64ToBytes(string), buf, offset, length)
}

function ucs2Write (buf, string, offset, length) {
  return blitBuffer(utf16leToBytes(string, buf.length - offset), buf, offset, length)
}

Buffer.prototype.write = function write (string, offset, length, encoding) {
  // Buffer#write(string)
  if (offset === undefined) {
    encoding = 'utf8'
    length = this.length
    offset = 0
  // Buffer#write(string, encoding)
  } else if (length === undefined && typeof offset === 'string') {
    encoding = offset
    length = this.length
    offset = 0
  // Buffer#write(string, offset[, length][, encoding])
  } else if (isFinite(offset)) {
    offset = offset >>> 0
    if (isFinite(length)) {
      length = length >>> 0
      if (encoding === undefined) encoding = 'utf8'
    } else {
      encoding = length
      length = undefined
    }
  } else {
    throw new Error(
      'Buffer.write(string, encoding, offset[, length]) is no longer supported'
    )
  }

  var remaining = this.length - offset
  if (length === undefined || length > remaining) length = remaining

  if ((string.length > 0 && (length < 0 || offset < 0)) || offset > this.length) {
    throw new RangeError('Attempt to write outside buffer bounds')
  }

  if (!encoding) encoding = 'utf8'

  var loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'hex':
        return hexWrite(this, string, offset, length)

      case 'utf8':
      case 'utf-8':
        return utf8Write(this, string, offset, length)

      case 'ascii':
        return asciiWrite(this, string, offset, length)

      case 'latin1':
      case 'binary':
        return latin1Write(this, string, offset, length)

      case 'base64':
        // Warning: maxLength not taken into account in base64Write
        return base64Write(this, string, offset, length)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return ucs2Write(this, string, offset, length)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}

Buffer.prototype.toJSON = function toJSON () {
  return {
    type: 'Buffer',
    data: Array.prototype.slice.call(this._arr || this, 0)
  }
}

function base64Slice (buf, start, end) {
  if (start === 0 && end === buf.length) {
    return base64.fromByteArray(buf)
  } else {
    return base64.fromByteArray(buf.slice(start, end))
  }
}

function utf8Slice (buf, start, end) {
  end = Math.min(buf.length, end)
  var res = []

  var i = start
  while (i < end) {
    var firstByte = buf[i]
    var codePoint = null
    var bytesPerSequence = (firstByte > 0xEF) ? 4
      : (firstByte > 0xDF) ? 3
        : (firstByte > 0xBF) ? 2
          : 1

    if (i + bytesPerSequence <= end) {
      var secondByte, thirdByte, fourthByte, tempCodePoint

      switch (bytesPerSequence) {
        case 1:
          if (firstByte < 0x80) {
            codePoint = firstByte
          }
          break
        case 2:
          secondByte = buf[i + 1]
          if ((secondByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0x1F) << 0x6 | (secondByte & 0x3F)
            if (tempCodePoint > 0x7F) {
              codePoint = tempCodePoint
            }
          }
          break
        case 3:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0xC | (secondByte & 0x3F) << 0x6 | (thirdByte & 0x3F)
            if (tempCodePoint > 0x7FF && (tempCodePoint < 0xD800 || tempCodePoint > 0xDFFF)) {
              codePoint = tempCodePoint
            }
          }
          break
        case 4:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          fourthByte = buf[i + 3]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80 && (fourthByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0x12 | (secondByte & 0x3F) << 0xC | (thirdByte & 0x3F) << 0x6 | (fourthByte & 0x3F)
            if (tempCodePoint > 0xFFFF && tempCodePoint < 0x110000) {
              codePoint = tempCodePoint
            }
          }
      }
    }

    if (codePoint === null) {
      // we did not generate a valid codePoint so insert a
      // replacement char (U+FFFD) and advance only 1 byte
      codePoint = 0xFFFD
      bytesPerSequence = 1
    } else if (codePoint > 0xFFFF) {
      // encode to utf16 (surrogate pair dance)
      codePoint -= 0x10000
      res.push(codePoint >>> 10 & 0x3FF | 0xD800)
      codePoint = 0xDC00 | codePoint & 0x3FF
    }

    res.push(codePoint)
    i += bytesPerSequence
  }

  return decodeCodePointsArray(res)
}

// Based on http://stackoverflow.com/a/22747272/680742, the browser with
// the lowest limit is Chrome, with 0x10000 args.
// We go 1 magnitude less, for safety
var MAX_ARGUMENTS_LENGTH = 0x1000

function decodeCodePointsArray (codePoints) {
  var len = codePoints.length
  if (len <= MAX_ARGUMENTS_LENGTH) {
    return String.fromCharCode.apply(String, codePoints) // avoid extra slice()
  }

  // Decode in chunks to avoid "call stack size exceeded".
  var res = ''
  var i = 0
  while (i < len) {
    res += String.fromCharCode.apply(
      String,
      codePoints.slice(i, i += MAX_ARGUMENTS_LENGTH)
    )
  }
  return res
}

function asciiSlice (buf, start, end) {
  var ret = ''
  end = Math.min(buf.length, end)

  for (var i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i] & 0x7F)
  }
  return ret
}

function latin1Slice (buf, start, end) {
  var ret = ''
  end = Math.min(buf.length, end)

  for (var i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i])
  }
  return ret
}

function hexSlice (buf, start, end) {
  var len = buf.length

  if (!start || start < 0) start = 0
  if (!end || end < 0 || end > len) end = len

  var out = ''
  for (var i = start; i < end; ++i) {
    out += toHex(buf[i])
  }
  return out
}

function utf16leSlice (buf, start, end) {
  var bytes = buf.slice(start, end)
  var res = ''
  for (var i = 0; i < bytes.length; i += 2) {
    res += String.fromCharCode(bytes[i] + (bytes[i + 1] * 256))
  }
  return res
}

Buffer.prototype.slice = function slice (start, end) {
  var len = this.length
  start = ~~start
  end = end === undefined ? len : ~~end

  if (start < 0) {
    start += len
    if (start < 0) start = 0
  } else if (start > len) {
    start = len
  }

  if (end < 0) {
    end += len
    if (end < 0) end = 0
  } else if (end > len) {
    end = len
  }

  if (end < start) end = start

  var newBuf = this.subarray(start, end)
  // Return an augmented `Uint8Array` instance
  newBuf.__proto__ = Buffer.prototype
  return newBuf
}

/*
 * Need to make sure that buffer isn't trying to write out of bounds.
 */
function checkOffset (offset, ext, length) {
  if ((offset % 1) !== 0 || offset < 0) throw new RangeError('offset is not uint')
  if (offset + ext > length) throw new RangeError('Trying to access beyond buffer length')
}

Buffer.prototype.readUIntLE = function readUIntLE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var val = this[offset]
  var mul = 1
  var i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }

  return val
}

Buffer.prototype.readUIntBE = function readUIntBE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    checkOffset(offset, byteLength, this.length)
  }

  var val = this[offset + --byteLength]
  var mul = 1
  while (byteLength > 0 && (mul *= 0x100)) {
    val += this[offset + --byteLength] * mul
  }

  return val
}

Buffer.prototype.readUInt8 = function readUInt8 (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 1, this.length)
  return this[offset]
}

Buffer.prototype.readUInt16LE = function readUInt16LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  return this[offset] | (this[offset + 1] << 8)
}

Buffer.prototype.readUInt16BE = function readUInt16BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  return (this[offset] << 8) | this[offset + 1]
}

Buffer.prototype.readUInt32LE = function readUInt32LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return ((this[offset]) |
      (this[offset + 1] << 8) |
      (this[offset + 2] << 16)) +
      (this[offset + 3] * 0x1000000)
}

Buffer.prototype.readUInt32BE = function readUInt32BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] * 0x1000000) +
    ((this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    this[offset + 3])
}

Buffer.prototype.readIntLE = function readIntLE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var val = this[offset]
  var mul = 1
  var i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readIntBE = function readIntBE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var i = byteLength
  var mul = 1
  var val = this[offset + --i]
  while (i > 0 && (mul *= 0x100)) {
    val += this[offset + --i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readInt8 = function readInt8 (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 1, this.length)
  if (!(this[offset] & 0x80)) return (this[offset])
  return ((0xff - this[offset] + 1) * -1)
}

Buffer.prototype.readInt16LE = function readInt16LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  var val = this[offset] | (this[offset + 1] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt16BE = function readInt16BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  var val = this[offset + 1] | (this[offset] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt32LE = function readInt32LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset]) |
    (this[offset + 1] << 8) |
    (this[offset + 2] << 16) |
    (this[offset + 3] << 24)
}

Buffer.prototype.readInt32BE = function readInt32BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] << 24) |
    (this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    (this[offset + 3])
}

Buffer.prototype.readFloatLE = function readFloatLE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, true, 23, 4)
}

Buffer.prototype.readFloatBE = function readFloatBE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, false, 23, 4)
}

Buffer.prototype.readDoubleLE = function readDoubleLE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, true, 52, 8)
}

Buffer.prototype.readDoubleBE = function readDoubleBE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, false, 52, 8)
}

function checkInt (buf, value, offset, ext, max, min) {
  if (!Buffer.isBuffer(buf)) throw new TypeError('"buffer" argument must be a Buffer instance')
  if (value > max || value < min) throw new RangeError('"value" argument is out of bounds')
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
}

Buffer.prototype.writeUIntLE = function writeUIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    var maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  var mul = 1
  var i = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUIntBE = function writeUIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    var maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  var i = byteLength - 1
  var mul = 1
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUInt8 = function writeUInt8 (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 1, 0xff, 0)
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeUInt16LE = function writeUInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  return offset + 2
}

Buffer.prototype.writeUInt16BE = function writeUInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  this[offset] = (value >>> 8)
  this[offset + 1] = (value & 0xff)
  return offset + 2
}

Buffer.prototype.writeUInt32LE = function writeUInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  this[offset + 3] = (value >>> 24)
  this[offset + 2] = (value >>> 16)
  this[offset + 1] = (value >>> 8)
  this[offset] = (value & 0xff)
  return offset + 4
}

Buffer.prototype.writeUInt32BE = function writeUInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  this[offset] = (value >>> 24)
  this[offset + 1] = (value >>> 16)
  this[offset + 2] = (value >>> 8)
  this[offset + 3] = (value & 0xff)
  return offset + 4
}

Buffer.prototype.writeIntLE = function writeIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    var limit = Math.pow(2, (8 * byteLength) - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  var i = 0
  var mul = 1
  var sub = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i - 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeIntBE = function writeIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    var limit = Math.pow(2, (8 * byteLength) - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  var i = byteLength - 1
  var mul = 1
  var sub = 0
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i + 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeInt8 = function writeInt8 (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 1, 0x7f, -0x80)
  if (value < 0) value = 0xff + value + 1
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeInt16LE = function writeInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  return offset + 2
}

Buffer.prototype.writeInt16BE = function writeInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  this[offset] = (value >>> 8)
  this[offset + 1] = (value & 0xff)
  return offset + 2
}

Buffer.prototype.writeInt32LE = function writeInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  this[offset + 2] = (value >>> 16)
  this[offset + 3] = (value >>> 24)
  return offset + 4
}

Buffer.prototype.writeInt32BE = function writeInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  if (value < 0) value = 0xffffffff + value + 1
  this[offset] = (value >>> 24)
  this[offset + 1] = (value >>> 16)
  this[offset + 2] = (value >>> 8)
  this[offset + 3] = (value & 0xff)
  return offset + 4
}

function checkIEEE754 (buf, value, offset, ext, max, min) {
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
  if (offset < 0) throw new RangeError('Index out of range')
}

function writeFloat (buf, value, offset, littleEndian, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 4, 3.4028234663852886e+38, -3.4028234663852886e+38)
  }
  ieee754.write(buf, value, offset, littleEndian, 23, 4)
  return offset + 4
}

Buffer.prototype.writeFloatLE = function writeFloatLE (value, offset, noAssert) {
  return writeFloat(this, value, offset, true, noAssert)
}

Buffer.prototype.writeFloatBE = function writeFloatBE (value, offset, noAssert) {
  return writeFloat(this, value, offset, false, noAssert)
}

function writeDouble (buf, value, offset, littleEndian, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 8, 1.7976931348623157E+308, -1.7976931348623157E+308)
  }
  ieee754.write(buf, value, offset, littleEndian, 52, 8)
  return offset + 8
}

Buffer.prototype.writeDoubleLE = function writeDoubleLE (value, offset, noAssert) {
  return writeDouble(this, value, offset, true, noAssert)
}

Buffer.prototype.writeDoubleBE = function writeDoubleBE (value, offset, noAssert) {
  return writeDouble(this, value, offset, false, noAssert)
}

// copy(targetBuffer, targetStart=0, sourceStart=0, sourceEnd=buffer.length)
Buffer.prototype.copy = function copy (target, targetStart, start, end) {
  if (!Buffer.isBuffer(target)) throw new TypeError('argument should be a Buffer')
  if (!start) start = 0
  if (!end && end !== 0) end = this.length
  if (targetStart >= target.length) targetStart = target.length
  if (!targetStart) targetStart = 0
  if (end > 0 && end < start) end = start

  // Copy 0 bytes; we're done
  if (end === start) return 0
  if (target.length === 0 || this.length === 0) return 0

  // Fatal error conditions
  if (targetStart < 0) {
    throw new RangeError('targetStart out of bounds')
  }
  if (start < 0 || start >= this.length) throw new RangeError('Index out of range')
  if (end < 0) throw new RangeError('sourceEnd out of bounds')

  // Are we oob?
  if (end > this.length) end = this.length
  if (target.length - targetStart < end - start) {
    end = target.length - targetStart + start
  }

  var len = end - start

  if (this === target && typeof Uint8Array.prototype.copyWithin === 'function') {
    // Use built-in when available, missing from IE11
    this.copyWithin(targetStart, start, end)
  } else if (this === target && start < targetStart && targetStart < end) {
    // descending copy from end
    for (var i = len - 1; i >= 0; --i) {
      target[i + targetStart] = this[i + start]
    }
  } else {
    Uint8Array.prototype.set.call(
      target,
      this.subarray(start, end),
      targetStart
    )
  }

  return len
}

// Usage:
//    buffer.fill(number[, offset[, end]])
//    buffer.fill(buffer[, offset[, end]])
//    buffer.fill(string[, offset[, end]][, encoding])
Buffer.prototype.fill = function fill (val, start, end, encoding) {
  // Handle string cases:
  if (typeof val === 'string') {
    if (typeof start === 'string') {
      encoding = start
      start = 0
      end = this.length
    } else if (typeof end === 'string') {
      encoding = end
      end = this.length
    }
    if (encoding !== undefined && typeof encoding !== 'string') {
      throw new TypeError('encoding must be a string')
    }
    if (typeof encoding === 'string' && !Buffer.isEncoding(encoding)) {
      throw new TypeError('Unknown encoding: ' + encoding)
    }
    if (val.length === 1) {
      var code = val.charCodeAt(0)
      if ((encoding === 'utf8' && code < 128) ||
          encoding === 'latin1') {
        // Fast path: If `val` fits into a single byte, use that numeric value.
        val = code
      }
    }
  } else if (typeof val === 'number') {
    val = val & 255
  }

  // Invalid ranges are not set to a default, so can range check early.
  if (start < 0 || this.length < start || this.length < end) {
    throw new RangeError('Out of range index')
  }

  if (end <= start) {
    return this
  }

  start = start >>> 0
  end = end === undefined ? this.length : end >>> 0

  if (!val) val = 0

  var i
  if (typeof val === 'number') {
    for (i = start; i < end; ++i) {
      this[i] = val
    }
  } else {
    var bytes = Buffer.isBuffer(val)
      ? val
      : Buffer.from(val, encoding)
    var len = bytes.length
    if (len === 0) {
      throw new TypeError('The value "' + val +
        '" is invalid for argument "value"')
    }
    for (i = 0; i < end - start; ++i) {
      this[i + start] = bytes[i % len]
    }
  }

  return this
}

// HELPER FUNCTIONS
// ================

var INVALID_BASE64_RE = /[^+/0-9A-Za-z-_]/g

function base64clean (str) {
  // Node takes equal signs as end of the Base64 encoding
  str = str.split('=')[0]
  // Node strips out invalid characters like \n and \t from the string, base64-js does not
  str = str.trim().replace(INVALID_BASE64_RE, '')
  // Node converts strings with length < 2 to ''
  if (str.length < 2) return ''
  // Node allows for non-padded base64 strings (missing trailing ===), base64-js does not
  while (str.length % 4 !== 0) {
    str = str + '='
  }
  return str
}

function toHex (n) {
  if (n < 16) return '0' + n.toString(16)
  return n.toString(16)
}

function utf8ToBytes (string, units) {
  units = units || Infinity
  var codePoint
  var length = string.length
  var leadSurrogate = null
  var bytes = []

  for (var i = 0; i < length; ++i) {
    codePoint = string.charCodeAt(i)

    // is surrogate component
    if (codePoint > 0xD7FF && codePoint < 0xE000) {
      // last char was a lead
      if (!leadSurrogate) {
        // no lead yet
        if (codePoint > 0xDBFF) {
          // unexpected trail
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        } else if (i + 1 === length) {
          // unpaired lead
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        }

        // valid lead
        leadSurrogate = codePoint

        continue
      }

      // 2 leads in a row
      if (codePoint < 0xDC00) {
        if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
        leadSurrogate = codePoint
        continue
      }

      // valid surrogate pair
      codePoint = (leadSurrogate - 0xD800 << 10 | codePoint - 0xDC00) + 0x10000
    } else if (leadSurrogate) {
      // valid bmp char, but last char was a lead
      if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
    }

    leadSurrogate = null

    // encode utf8
    if (codePoint < 0x80) {
      if ((units -= 1) < 0) break
      bytes.push(codePoint)
    } else if (codePoint < 0x800) {
      if ((units -= 2) < 0) break
      bytes.push(
        codePoint >> 0x6 | 0xC0,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x10000) {
      if ((units -= 3) < 0) break
      bytes.push(
        codePoint >> 0xC | 0xE0,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x110000) {
      if ((units -= 4) < 0) break
      bytes.push(
        codePoint >> 0x12 | 0xF0,
        codePoint >> 0xC & 0x3F | 0x80,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else {
      throw new Error('Invalid code point')
    }
  }

  return bytes
}

function asciiToBytes (str) {
  var byteArray = []
  for (var i = 0; i < str.length; ++i) {
    // Node's code seems to be doing this and not & 0x7F..
    byteArray.push(str.charCodeAt(i) & 0xFF)
  }
  return byteArray
}

function utf16leToBytes (str, units) {
  var c, hi, lo
  var byteArray = []
  for (var i = 0; i < str.length; ++i) {
    if ((units -= 2) < 0) break

    c = str.charCodeAt(i)
    hi = c >> 8
    lo = c % 256
    byteArray.push(lo)
    byteArray.push(hi)
  }

  return byteArray
}

function base64ToBytes (str) {
  return base64.toByteArray(base64clean(str))
}

function blitBuffer (src, dst, offset, length) {
  for (var i = 0; i < length; ++i) {
    if ((i + offset >= dst.length) || (i >= src.length)) break
    dst[i + offset] = src[i]
  }
  return i
}

// ArrayBuffer or Uint8Array objects from other contexts (i.e. iframes) do not pass
// the `instanceof` check but they should be treated as of that type.
// See: https://github.com/feross/buffer/issues/166
function isInstance (obj, type) {
  return obj instanceof type ||
    (obj != null && obj.constructor != null && obj.constructor.name != null &&
      obj.constructor.name === type.name)
}
function numberIsNaN (obj) {
  // For IE11 support
  return obj !== obj // eslint-disable-line no-self-compare
}

}).call(this)}).call(this,require("buffer").Buffer)
},{"base64-js":96,"buffer":97,"ieee754":98}],98:[function(require,module,exports){
/*! ieee754. BSD-3-Clause License. Feross Aboukhadijeh <https://feross.org/opensource> */
exports.read = function (buffer, offset, isLE, mLen, nBytes) {
  var e, m
  var eLen = (nBytes * 8) - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var nBits = -7
  var i = isLE ? (nBytes - 1) : 0
  var d = isLE ? -1 : 1
  var s = buffer[offset + i]

  i += d

  e = s & ((1 << (-nBits)) - 1)
  s >>= (-nBits)
  nBits += eLen
  for (; nBits > 0; e = (e * 256) + buffer[offset + i], i += d, nBits -= 8) {}

  m = e & ((1 << (-nBits)) - 1)
  e >>= (-nBits)
  nBits += mLen
  for (; nBits > 0; m = (m * 256) + buffer[offset + i], i += d, nBits -= 8) {}

  if (e === 0) {
    e = 1 - eBias
  } else if (e === eMax) {
    return m ? NaN : ((s ? -1 : 1) * Infinity)
  } else {
    m = m + Math.pow(2, mLen)
    e = e - eBias
  }
  return (s ? -1 : 1) * m * Math.pow(2, e - mLen)
}

exports.write = function (buffer, value, offset, isLE, mLen, nBytes) {
  var e, m, c
  var eLen = (nBytes * 8) - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var rt = (mLen === 23 ? Math.pow(2, -24) - Math.pow(2, -77) : 0)
  var i = isLE ? 0 : (nBytes - 1)
  var d = isLE ? 1 : -1
  var s = value < 0 || (value === 0 && 1 / value < 0) ? 1 : 0

  value = Math.abs(value)

  if (isNaN(value) || value === Infinity) {
    m = isNaN(value) ? 1 : 0
    e = eMax
  } else {
    e = Math.floor(Math.log(value) / Math.LN2)
    if (value * (c = Math.pow(2, -e)) < 1) {
      e--
      c *= 2
    }
    if (e + eBias >= 1) {
      value += rt / c
    } else {
      value += rt * Math.pow(2, 1 - eBias)
    }
    if (value * c >= 2) {
      e++
      c /= 2
    }

    if (e + eBias >= eMax) {
      m = 0
      e = eMax
    } else if (e + eBias >= 1) {
      m = ((value * c) - 1) * Math.pow(2, mLen)
      e = e + eBias
    } else {
      m = value * Math.pow(2, eBias - 1) * Math.pow(2, mLen)
      e = 0
    }
  }

  for (; mLen >= 8; buffer[offset + i] = m & 0xff, i += d, m /= 256, mLen -= 8) {}

  e = (e << mLen) | m
  eLen += mLen
  for (; eLen > 0; buffer[offset + i] = e & 0xff, i += d, e /= 256, eLen -= 8) {}

  buffer[offset + i - d] |= s * 128
}

},{}],99:[function(require,module,exports){
/*!
 * Determine if an object is a Buffer
 *
 * @author   Feross Aboukhadijeh <https://feross.org>
 * @license  MIT
 */

// The _isBuffer check is for Safari 5-7 support, because it's missing
// Object.prototype.constructor. Remove this eventually
module.exports = function (obj) {
  return obj != null && (isBuffer(obj) || isSlowBuffer(obj) || !!obj._isBuffer)
}

function isBuffer (obj) {
  return !!obj.constructor && typeof obj.constructor.isBuffer === 'function' && obj.constructor.isBuffer(obj)
}

// For Node v0.10 support. Remove this eventually.
function isSlowBuffer (obj) {
  return typeof obj.readFloatLE === 'function' && typeof obj.slice === 'function' && isBuffer(obj.slice(0, 0))
}

},{}]},{},[1]);

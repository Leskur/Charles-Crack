function rotateLeft(x, y) {
  return (x << (y & 31)) | (x >>> (32 - (y & 31))) | 0;
}

function rotateRight(x, y) {
  return (x >>> (y & 31)) | (x << (32 - (y & 31))) | 0;
}

function pkLong(a, b) {
  return BigInt(a >>> 0) | (BigInt(b) << 32n);
}

class CkCipher {
  constructor(ckKey) {
    this.rounds = 12;
    this.roundKeys = 2 * (this.rounds + 1);
    this.rk = new Array(this.roundKeys);

    let ld = [
      Number(ckKey & 0xffffffffn),
      Number((ckKey >> 32n) & 0xffffffffn),
    ];
    this.rk[0] = -1209970333;
    for (let i = 1; i < this.roundKeys; i++) {
      this.rk[i] = this.rk[i - 1] + -1640531527;
    }

    let a = 0,
      b = 0,
      i = 0,
      j = 0;
    for (let k = 0; k < 3 * this.roundKeys; k++) {
      this.rk[i] = rotateLeft(this.rk[i] + (a + b), 3);
      a = this.rk[i];
      ld[j] = rotateLeft(ld[j] + (a + b), a + b);
      b = ld[j];
      i = (i + 1) % this.roundKeys;
      j = (j + 1) % 2;
    }
  }

  encrypt(inp) {
    let a = Number(inp & 0xffffffffn) + this.rk[0];
    let b = Number((inp >> 32n) & 0xffffffffn) + this.rk[1];
    for (let r = 1; r <= this.rounds; r++) {
      a = rotateLeft(a ^ b, b) + this.rk[2 * r];
      b = rotateLeft(b ^ a, a) + this.rk[2 * r + 1];
    }
    return pkLong(a, b);
  }

  decrypt(inp) {
    let a = Number(inp & 0xffffffffn);
    let b = Number((inp >> 32n) & 0xffffffffn);
    for (let i = this.rounds; i > 0; i--) {
      b = rotateRight(b - this.rk[2 * i + 1], a) ^ a;
      a = rotateRight(a - this.rk[2 * i], b) ^ b;
    }
    b -= this.rk[1];
    a -= this.rk[0];
    return pkLong(a, b);
  }
}

function crack(text) {
  const name = Buffer.from(text, "utf8");
  const length = name.length + 4;
  const padded = (-length & (8 - 1)) + length;

  let buff = Buffer.alloc(padded);
  buff.writeUInt32BE(name.length, 0);
  name.copy(buff, 4);

  const ckName = 0x7a21c951691cd470n;
  const ckKey = -5408575981733630035n;

  const ck = new CkCipher(ckName);
  let outBuff = [];

  for (let i = 0; i < padded; i += 8) {
    const nowVar = buff.readBigInt64BE(i);
    let dd = ck.encrypt(nowVar);
    if (dd < 0n) dd += 1n << 64n; // ✅ 转成无符号 64 位
    let bytes = Buffer.alloc(8);
    bytes.writeBigUInt64BE(dd, 0);
    outBuff.push(...bytes);
  }

  let n = 0;
  for (let b of outBuff) {
    const signed = new Int8Array([b])[0]; // ✅ 正确模拟 Go 的 int8(b)
    n = rotateLeft(n ^ signed, 3);
  }

  const prefix = n ^ 0x54882f8a;
  const suffix = Math.floor(Math.random() * 0x7fffffff);

  let inside;
  if (
    suffix >> 16 === 0x0401 ||
    suffix >> 16 === 0x0402 ||
    suffix >> 16 === 0x0403
  ) {
    inside = (BigInt(prefix) << 32n) | BigInt(suffix);
  } else {
    inside = (BigInt(prefix) << 32n) | BigInt(0x01000000 | (suffix & 0xffffff));
  }

  const out = new CkCipher(ckKey).decrypt(inside);

  let n2 = 0n;
  for (let i = 56n; i >= 0; i -= 8n) {
    n2 ^= (inside >> i) & 0xffn;
  }

  let vv = Number(n2 & 0xffn);
  if (vv < 0) vv = -vv;

  return (
    vv.toString(16).padStart(2, "0") +
    (out & 0xffffffffffffffffn).toString(16).padStart(16, "0")
  );
}

// 测试
const name = "charles";
console.log("charles =>", crack(name));
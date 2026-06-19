// SMC Server 鈥?Express + SM2/SM3/SM4 + SQLite
const crypto = require('crypto'); const fs = require('fs'); const path = require('path')
const express = require('express'); const cors = require('cors'); const multer = require('multer')
const initSqlJs = require('sql.js')

// ==================== SM4/SM3/SM2 (same as before) ====================
const SBOX=[0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48]
const FK=[0xa3b1bac6,0x56aa3350,0x677d9197,0xb27022dc];const CK=[0x00070e15,0x1c232a31,0x383f464d,0x545b6269,0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,0x30373e45,0x4c535a61,0x686f767d,0x848b9299,0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,0x10171e25,0x2c333a41,0x484f565d,0x646b7279]
function rotl(x,n){return((x<<n)|(x>>>32-n))>>>0}
function sm4Sbox(x){return SBOX[x&0xff]|(SBOX[(x>>>8)&0xff]<<8)|(SBOX[(x>>>16)&0xff]<<16)|(SBOX[(x>>>24)&0xff]<<24)}
function sm4L(x){return x^rotl(x,2)^rotl(x,10)^rotl(x,18)^rotl(x,24)}
function sm4Lprime(x){return x^rotl(x,13)^rotl(x,23)}
function sm4T(x){return sm4L(sm4Sbox(x))}
function sm4Tprime(x){return sm4Lprime(sm4Sbox(x))}
function expandKey(key){const mk=[],k=[],rk=[];for(let i=0;i<4;i++)mk[i]=(key[i*4]<<24)|(key[i*4+1]<<16)|(key[i*4+2]<<8)|key[i*4+3];for(let i=0;i<4;i++)k[i]=mk[i]^FK[i];for(let i=0;i<32;i++){rk[i]=k[i]^sm4Tprime(k[i+1]^k[i+2]^k[i+3]^CK[i]);k[i+4]=rk[i]}return rk}
function sm4Round(X,rk){const x=[];for(let i=0;i<4;i++)x[i]=(X[i*4]<<24)|(X[i*4+1]<<16)|(X[i*4+2]<<8)|X[i*4+3];for(let i=0;i<32;i++)x.push(x[i]^sm4T(x[i+1]^x[i+2]^x[i+3]^rk[i]));const out=new Uint8Array(16);for(let i=0;i<4;i++){const v=x[35-i];out[i*4]=(v>>>24)&0xff;out[i*4+1]=(v>>>16)&0xff;out[i*4+2]=(v>>>8)&0xff;out[i*4+3]=v&0xff}return out}
function sm4Encrypt(b,rk){return sm4Round(b,rk)}
function sm4Decrypt(b,rk){return sm4Round(b,[...rk].reverse())}
function xorBlock(a,b){const r=new Uint8Array(16);for(let i=0;i<16;i++)r[i]=a[i]^b[i];return r}
function hexToBytes(hex){hex=hex.replace(/\s/g,'');if(hex.length%2!==0)throw new Error('hex');const b=new Uint8Array(hex.length/2);for(let i=0;i<b.length;i++)b[i]=parseInt(hex.substr(i*2,2),16);return b}
function bytesToHex(b){return Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join('')}
function sm4EncryptCBC(plaintext,key){const rk=expandKey(key);const iv=crypto.randomBytes(16);const padLen=16-(plaintext.length%16);const pl=plaintext.length+padLen;const padded=new Uint8Array(pl);padded.set(plaintext);for(let i=plaintext.length;i<pl;i++)padded[i]=padLen;const bc=pl/16;const result=new Uint8Array(16+pl);result.set(iv);let prev=iv;for(let i=0;i<bc;i++){const block=padded.slice(i*16,i*16+16);prev=sm4Encrypt(xorBlock(block,prev),rk);result.set(prev,16+i*16)}return result}
function sm4DecryptCBC(ct,key){if(ct.length<32)throw new Error('short');const rk=expandKey(key);const iv=ct.slice(0,16);const c=ct.slice(16);const bc=c.length/16;const result=new Uint8Array(c.length);let prev=iv;for(let i=0;i<bc;i++){const block=c.slice(i*16,i*16+16);const dec=sm4Decrypt(block,rk);result.set(xorBlock(dec,prev),i*16);prev=block}const padLen=result[result.length-1];if(padLen<1||padLen>16)throw new Error('PKCS7');for(let i=1;i<padLen;i++)if(result[result.length-1-i]!==padLen)throw new Error('PKCS7');return result.slice(0,result.length-padLen)}
function sm4EncryptCBCFromHex(pt,kh){return bytesToHex(sm4EncryptCBC(new TextEncoder().encode(pt),hexToBytes(kh)))}
function sm4DecryptCBCToText(ch,kh){return new TextDecoder().decode(sm4DecryptCBC(hexToBytes(ch),hexToBytes(kh)))}
const IV=[0x7380166f,0x4914b2b9,0x172442d7,0xda8a0600,0xa96f30bc,0x163138aa,0xe38dee4d,0xb0fb0e4e]
function _p0(x){return x^rotl(x,9)^rotl(x,17)};function _p1(x){return x^rotl(x,15)^rotl(x,23)}
function _ff0(x,y,z){return x^y^z};function _ff1(x,y,z){return(x&y)|(x&z)|(y&z)}
function _gg0(x,y,z){return x^y^z};function _gg1(x,y,z){return(x&y)|(~x&z)}
function sm3Hash(message){const msgBytes=typeof message==='string'?new TextEncoder().encode(message):new Uint8Array(message);const len=msgBytes.length*8;const padLen=(448-(len+1)%512+512)%512;const totalBytes=(len+1+padLen+64)/8;const padded=new Uint8Array(totalBytes);padded.set(msgBytes);padded[msgBytes.length]=0x80;const view=new DataView(padded.buffer);view.setUint32(totalBytes-4,len&0xffffffff);view.setUint32(totalBytes-8,Math.floor(len/0x100000000));const V=[...IV];const W=new Uint32Array(68),W1=new Uint32Array(64);for(let block=0;block<totalBytes;block+=64){for(let i=0;i<16;i++)W[i]=view.getUint32(block+i*4);for(let i=16;i<68;i++)W[i]=_p1(W[i-16]^W[i-9]^rotl(W[i-3],15))^rotl(W[i-13],7)^W[i-6];for(let i=0;i<64;i++)W1[i]=W[i]^W[i+4];let A=V[0],B=V[1],C=V[2],D=V[3],E=V[4],F=V[5],G=V[6],H=V[7];for(let j=0;j<64;j++){const Tj=j<16?0x79cc4519:0x7a879d8a;const SS1=rotl(rotl(A,12)+E+rotl(Tj,j%32),7);const SS2=SS1^rotl(A,12);const TT1=j<16?_ff0(A,B,C)+D+SS2+W1[j]:_ff1(A,B,C)+D+SS2+W1[j];const TT2=j<16?_gg0(E,F,G)+H+SS1+W[j]:_gg1(E,F,G)+H+SS1+W[j];D=C;C=rotl(B,9);B=A;A=TT1;H=G;G=rotl(F,19);F=E;E=_p0(TT2)}V[0]^=A;V[1]^=B;V[2]^=C;V[3]^=D;V[4]^=E;V[5]^=F;V[6]^=G;V[7]^=H}const hash=new Uint8Array(32);const dv=new DataView(hash.buffer);for(let i=0;i<8;i++)dv.setUint32(i*4,V[i]);return hash}
function sm3HashHex(m){return bytesToHex(sm3Hash(m))}
function sm3HMACHex(key,message){const bs=64;let k=typeof key==='string'?new TextEncoder().encode(key):new Uint8Array(key);if(k.length>bs)k=sm3Hash(k);const ipad=new Uint8Array(bs),opad=new Uint8Array(bs);for(let i=0;i<bs;i++){ipad[i]=0x36;opad[i]=0x5c}for(let i=0;i<k.length;i++){ipad[i]^=k[i];opad[i]^=k[i]}const inner=new Uint8Array(bs+(typeof message==='string'?new TextEncoder().encode(message).length:message.length));inner.set(ipad);if(typeof message==='string')inner.set(new TextEncoder().encode(message),bs);else inner.set(new Uint8Array(message),bs);const ih=sm3Hash(inner);const outer=new Uint8Array(bs+32);outer.set(opad);outer.set(ih,bs);return bytesToHex(sm3Hash(outer))}
const P=0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffffn;const A=0xfffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffcn;const B=0x28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93n;const N=0xfffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123n;const GX=0x32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7n;const GY=0xbc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0n
function mod(a,m){const r=a%m;return r<0n?r+m:r}
function modMul(a,b,m){return mod(a*b,m)}
function modPow(a,e,m){if(e===0n)return 1n;let r=1n,b=mod(a,m);while(e>0n){if(e&1n)r=modMul(r,b,m);b=modMul(b,b,m);e>>=1n}return r}
function modInv(a,m){return modPow(a,m-2n,m)}
class ECPoint{constructor(x,y,i=false){this.x=x;this.y=y;this.isInfinity=i}}
const INF=new ECPoint(0n,0n,true)
function pointAdd(p1,p2){if(p1.isInfinity)return p2;if(p2.isInfinity)return p1;if(p1.x===p2.x&&p1.y===mod(-p2.y,P))return INF;let lam;if(p1.x===p2.x&&p1.y===p2.y){if(p1.y===0n)return INF;lam=modMul(modMul(3n*p1.x*p1.x+A,modInv(2n*p1.y,P),P),1n,P)}else{lam=modMul(mod(p2.y-p1.y,P),modInv(mod(p2.x-p1.x,P),P),P)}return new ECPoint(mod(lam*lam-p1.x-p2.x,P),mod(lam*(p1.x-mod(lam*lam-p1.x-p2.x,P))-p1.y,P))}
function pointMul(k,p){if(k===0n)return INF;let r=INF,a=p,s=mod(k,N);while(s>0n){if(s&1n)r=pointAdd(r,a);a=pointAdd(a,a);s>>=1n}return r}
const G=new ECPoint(GX,GY)
function bytesToHex32(n){return n.toString(16).padStart(64,'0')}
function parsePK(hex){return new ECPoint(BigInt('0x'+hex.slice(2,66)),BigInt('0x'+hex.slice(66,130)))}
function computeZA(pk){const id='31323334353637383132333435363738';const entla='0080';const aH='FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC';const bH='28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93';const gxH='32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7';const gyH='BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0';return sm3Hash(hexToBytes(entla+id+aH+bH+gxH+gyH+pk.slice(2,66)+pk.slice(66,130)))}
function hashZAm(ZA,m){const c=new Uint8Array(ZA.length+m.length);c.set(ZA);c.set(m,ZA.length);return sm3Hash(c)}
function sm2GenKey(){let d;do{const b=crypto.randomBytes(32);d=BigInt('0x'+bytesToHex(b))}while(d>=N||d===0n);const pp=pointMul(d,G);return{privateKey:bytesToHex32(d),publicKey:'04'+bytesToHex32(pp.x)+bytesToHex32(pp.y)}}
function sm2Sign(msg,pkH,privH){const d=BigInt('0x'+privH);const mb=typeof msg==='string'?new TextEncoder().encode(msg):new Uint8Array(msg);const ZA=computeZA(pkH);const eH=hashZAm(ZA,mb);const e=BigInt('0x'+bytesToHex(eH));let r,s;while(true){const kb=crypto.randomBytes(32);const k=BigInt('0x'+bytesToHex(kb))%N;if(k===0n)continue;const kG=pointMul(k,G);r=mod(e+kG.x,N);if(r===0n||mod(r+k,N)===0n)continue;const d1=modInv(1n+d,N);s=modMul(d1,mod(k-modMul(r,d,N),N),N);if(s!==0n)break}return{r:bytesToHex32(r),s:bytesToHex32(s)}}
function sm2Verify(msg,sig,pkH){const r=BigInt('0x'+sig.r),s=BigInt('0x'+sig.s);if(r<1n||r>=N||s<1n||s>=N)return false;const mb=typeof msg==='string'?new TextEncoder().encode(msg):new Uint8Array(msg);const ZA=computeZA(pkH);const eH=hashZAm(ZA,mb);const e=BigInt('0x'+bytesToHex(eH));const t=mod(r+s,N);if(t===0n)return false;const pp=parsePK(pkH);if(!pp)return false;const sG_tP=pointAdd(pointMul(s,G),pointMul(t,pp));return mod(e+sG_tP.x,N)===r}
function kdf(z,klen){const ct=new Uint8Array(4);const hs=[];for(let i=0;i*32<klen;i++){ct[0]=(i+1)>>>24;ct[1]=((i+1)>>>16)&0xff;ct[2]=((i+1)>>>8)&0xff;ct[3]=(i+1)&0xff;const inp=new Uint8Array(z.length+4);inp.set(z);inp.set(ct,z.length);hs.push(sm3Hash(inp))}const r=new Uint8Array(hs.length*32);hs.forEach((h,i)=>r.set(h,i*32));return r.slice(0,klen)}
function sm2Encrypt(msg,pkH){const pp=parsePK(pkH);if(!pp||pp.isInfinity)throw new Error('invalid key');const mb=typeof msg==='string'?new TextEncoder().encode(msg):new Uint8Array(msg);let k,C1,S;do{k=BigInt('0x'+bytesToHex(crypto.randomBytes(32)))%N}while(k===0n);C1=pointMul(k,G);S=pointMul(k,pp);if(S.isInfinity)throw new Error('encrypt fail');const c1b=hexToBytes('04'+bytesToHex32(C1.x)+bytesToHex32(C1.y));const sb=hexToBytes(bytesToHex32(S.x)+bytesToHex32(S.y));const t=kdf(sb,mb.length);const C2=new Uint8Array(mb.length);for(let i=0;i<mb.length;i++)C2[i]=mb[i]^t[i];const c3i=new Uint8Array(sb.length+mb.length);c3i.set(sb);c3i.set(mb,sb.length);return bytesToHex(c1b)+bytesToHex(sm3Hash(c3i))+bytesToHex(C2)}
function sm2Decrypt(ch,privH){const d=BigInt('0x'+privH);if(ch.length<194)throw new Error('short');const C1=parsePK(ch.slice(0,130));const C3=hexToBytes(ch.slice(130,194));const C2=hexToBytes(ch.slice(194));if(!C1||C1.isInfinity)throw new Error('C1 fail');const S=pointMul(d,C1);if(S.isInfinity)throw new Error('dec fail');const sb=hexToBytes(bytesToHex32(S.x)+bytesToHex32(S.y));const t=kdf(sb,C2.length);const M=new Uint8Array(C2.length);for(let i=0;i<C2.length;i++)M[i]=C2[i]^t[i];const ui=new Uint8Array(sb.length+M.length);ui.set(sb);ui.set(M,sb.length);if(!sm3Hash(ui).every((b,i)=>b===C3[i]))throw new Error('C3 fail');return M}

// ==================== SQLite 鏁版嵁搴?====================
let db, _SQL
function getDataDir(){const d=path.join(process.env.APPDATA||path.join(process.env.HOME,'.local/share'),'smc-platform');try{fs.mkdirSync(d,{recursive:true})}catch{};return d}
function saveDB(){try{fs.writeFileSync(path.join(getDataDir(),'smc.db'),db.export())}catch{}}

function initDB(){
  db=new _SQL.Database()
  const dbPath=path.join(getDataDir(),'smc.db')
  try{const buf=fs.readFileSync(dbPath);if(buf.length>0)db=new _SQL.Database(buf);else{db.run('CREATE TABLE users(username TEXT PRIMARY KEY,password_hash TEXT NOT NULL,pub_key TEXT DEFAULT "",created TEXT NOT NULL,role TEXT DEFAULT "user")');db.run('CREATE TABLE files(id TEXT PRIMARY KEY,owner TEXT NOT NULL,name TEXT NOT NULL,original_name TEXT,size INTEGER NOT NULL,sm3_hash TEXT NOT NULL,pub_key TEXT NOT NULL,signature TEXT,encrypted_key TEXT,uploaded_at TEXT NOT NULL)');db.run('CREATE TABLE shares(file_id TEXT NOT NULL,username TEXT NOT NULL,granted_at TEXT NOT NULL,PRIMARY KEY(file_id,username))');db.run('CREATE TABLE api_keys(name TEXT PRIMARY KEY,key TEXT NOT NULL,created TEXT NOT NULL,last_used TEXT,usage_count INTEGER DEFAULT 0)');db.run('CREATE TABLE audit_logs(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT NOT NULL,action TEXT NOT NULL,target TEXT,detail TEXT,created_at TEXT NOT NULL)')}}catch{db.run('CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY,password_hash TEXT NOT NULL,pub_key TEXT DEFAULT "",created TEXT NOT NULL,role TEXT DEFAULT "user")');db.run('CREATE TABLE IF NOT EXISTS files(id TEXT PRIMARY KEY,owner TEXT NOT NULL,name TEXT NOT NULL,original_name TEXT,size INTEGER NOT NULL,sm3_hash TEXT NOT NULL,pub_key TEXT NOT NULL,signature TEXT,encrypted_key TEXT,uploaded_at TEXT NOT NULL)');db.run('CREATE TABLE IF NOT EXISTS shares(file_id TEXT NOT NULL,username TEXT NOT NULL,granted_at TEXT NOT NULL,PRIMARY KEY(file_id,username))');db.run('CREATE TABLE IF NOT EXISTS api_keys(name TEXT PRIMARY KEY,key TEXT NOT NULL,created TEXT NOT NULL,last_used TEXT,usage_count INTEGER DEFAULT 0)');db.run('CREATE TABLE IF NOT EXISTS audit_logs(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT NOT NULL,action TEXT NOT NULL,target TEXT,detail TEXT,created_at TEXT NOT NULL)')}
  saveDB()
}

// ==================== Admin HTML ====================
const ADMIN_HTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ShieldX Admin</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}body{font-family:"Microsoft YaHei",sans-serif;background:#f0f2f5;color:#1a1a2e;display:flex;min-height:100vh}
.login-box{width:400px;margin:100px auto;padding:40px;background:#fff;border-radius:14px;box-shadow:0 4px 24px rgba(0,0,0,.08);text-align:center}
.login-box h1{font-size:24px;margin-bottom:24px;color:#1a1a2e}.login-box input{width:100%;padding:12px 16px;margin-bottom:12px;border:1px solid #e0e0e0;border-radius:8px;font-size:14px}
.login-box button{width:100%;padding:12px;background:#1a1a2e;color:#fff;border:none;border-radius:8px;font-size:14px;cursor:pointer;font-weight:600}
.login-box .err{color:#ff3b30;margin-top:8px;font-size:13px}
.sidebar{width:220px;background:#1a1a2e;color:#fff;padding:20px 0;display:flex;flex-direction:column}
.sidebar h2{padding:0 20px 24px;font-size:18px;border-bottom:1px solid rgba(255,255,255,.1);margin-bottom:8px}
.sidebar a{color:rgba(255,255,255,.7);text-decoration:none;padding:12px 20px;display:block;font-size:14px;cursor:pointer;transition:.2s}
.sidebar a:hover,.sidebar a.active{background:rgba(255,255,255,.08);color:#fff}
.main{flex:1;padding:24px 32px;overflow-y:auto}.main h3{font-size:20px;margin-bottom:20px;font-weight:600}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}
.card{background:#fff;border-radius:12px;padding:20px;box-shadow:0 2px 12px rgba(0,0,0,.04)}
.card .num{font-size:32px;font-weight:700;color:#1a1a2e}.card .label{font-size:13px;color:#888;margin-top:4px}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,.04)}
th,td{padding:12px 16px;text-align:left;font-size:13px;border-bottom:1px solid #f0f0f0}
th{background:#fafafa;font-weight:600;color:#555}tr:hover{background:#f8f9ff}
.btn-sm{padding:4px 12px;border:none;border-radius:6px;font-size:12px;cursor:pointer;font-weight:600}
.btn-danger{background:#ff3b30;color:#fff}.btn-danger:hover{background:#e0352b}
.empty{text-align:center;padding:40px;color:#999}.hidden{display:none}
.meta{font-size:12px;color:#aaa;margin-bottom:12px}
</style></head>
<body>
<div id="loginPage" class="login-box">
<h1>ShieldX Admin</h1>
<input id="adminUser" placeholder="绠＄悊鍛樼敤鎴峰悕" autocomplete="off"><input id="adminPwd" type="password" placeholder="绠＄悊鍛樺瘑鐮?>
<button onclick="doAdminLogin()">绠＄悊鍛樼櫥褰?/button><div id="loginErr" class="err"></div>
</div>
<div id="app" class="hidden" style="display:none;display:flex;width:100%">
<div class="sidebar">
<h2>ShieldX Admin</h2>
<a onclick="showTab('dashboard')" id="tab-dashboard" class="active">浠〃鐩?/a>
<a onclick="showTab('users')" id="tab-users">鐢ㄦ埛绠＄悊</a>
<a onclick="showTab('files')" id="tab-files">鏂囦欢绠＄悊</a>
<a onclick="showTab('logs')" id="tab-logs">瀹¤鏃ュ織</a>
<a onclick="doLogout()" style="margin-top:auto;color:#ff3b30">閫€鍑虹櫥褰?/a>
</div>
<div class="main" id="content"></div>
</div>
<script>
var token='';
function api(path,method,body){var opts={method:method||'GET',headers:{Authorization:'Bearer '+token}};if(body){opts.headers['Content-Type']='application/json';opts.body=JSON.stringify(body)}return fetch(path,opts).then(r=>{if(!r.ok)return r.json().then(d=>{throw new Error(d.error||'Error')});return r.json()})}
async function doAdminLogin(){try{var r=await api('/api/admin/login','POST',{username:document.getElementById('adminUser').value,password:document.getElementById('adminPwd').value});token=r.token;document.getElementById('loginPage').style.display='none';document.getElementById('app').style.display='flex';showTab('dashboard')}catch(e){document.getElementById('loginErr').textContent=e.message}}
async function showTab(t){
document.querySelectorAll('.sidebar a').forEach(a=>a.classList.remove('active'));
document.getElementById('tab-'+t).classList.add('active');
var c=document.getElementById('content');
if(t==='dashboard'){var s=await api('/api/admin/stats');c.innerHTML='<h3>浠〃鐩?/h3><div class=cards><div class=card><div class=num>'+s.users+'</div><div class=label>鐢ㄦ埛鎬绘暟</div></div><div class=card><div class=num>'+s.files+'</div><div class=label>鏂囦欢鎬绘暟</div></div><div class=card><div class=num>'+s.shares+'</div><div class=label>鍒嗕韩娆℃暟</div></div><div class=card><div class=num>'+s.auditLogs+'</div><div class=label>瀹¤鏃ュ織</div></div></div>'}
if(t==='users'){var u=await api('/api/admin/users');c.innerHTML='<h3>鐢ㄦ埛绠＄悊</h3><div class=meta>鍏?'+u.length+' 涓敤鎴?/div><table><tr><th>鐢ㄦ埛鍚?/th><th>娉ㄥ唽鏃堕棿</th><th>瑙掕壊</th><th>鎿嶄綔</th></tr>'+(u.length===0?'<tr><td colspan=4 class=empty>鏆傛棤鐢ㄦ埛</td></tr>':u.map(function(x){return'<tr><td>'+x.username+'</td><td>'+x.created.slice(0,10)+'</td><td>'+x.role+'</td><td><button class="btn-sm btn-danger" onclick="delUser(\\''+x.username+'\\')">鍒犻櫎</button></td></tr>'}).join(''))+'</table>'}
if(t==='files'){var f=await api('/api/admin/files');c.innerHTML='<h3>鏂囦欢绠＄悊</h3><div class=meta>鍏?'+f.length+' 涓枃浠?/div><table><tr><th>ID</th><th>鎵€鏈夎€?/th><th>鏂囦欢鍚?/th><th>澶у皬</th><th>涓婁紶鏃堕棿</th><th>鎿嶄綔</th></tr>'+(f.length===0?'<tr><td colspan=6 class=empty>鏆傛棤鏂囦欢</td></tr>':f.map(function(x){var sz=x.size<1024?x.size+'B':x.size<1048576?(x.size/1024).toFixed(1)+'KB':(x.size/1048576).toFixed(1)+'MB';return'<tr><td style=font-size:11px>'+x.id.slice(0,12)+'...</td><td>'+x.owner+'</td><td>'+x.name+'</td><td>'+sz+'</td><td>'+x.uploadedAt.slice(0,10)+'</td><td><button class="btn-sm btn-danger" onclick="delFile(\\''+x.id+'\\')">鍒犻櫎</button></td></tr>'}).join(''))+'</table>'}
if(t==='logs'){var l=await api('/api/admin/logs');c.innerHTML='<h3>瀹¤鏃ュ織</h3><table><tr><th>鏃堕棿</th><th>鐢ㄦ埛</th><th>鎿嶄綔</th><th>璇︽儏</th></tr>'+(l.length===0?'<tr><td colspan=4 class=empty>鏆傛棤鏃ュ織</td></tr>':l.map(function(x){return'<tr><td>'+x.createdAt.slice(0,19)+'</td><td>'+x.username+'</td><td>'+x.action+'</td><td>'+x.detail+'</td></tr>'}).join(''))+'</table>'}
}
async function delUser(u){if(!confirm('纭畾鍒犻櫎鐢ㄦ埛 '+u+'锛熸鎿嶄綔涓嶅彲鎾ら攢銆?))return;await api('/api/admin/users/'+encodeURIComponent(u),'DELETE');showTab('users')}
async function delFile(id){if(!confirm('纭畾鍒犻櫎鏂囦欢锛?))return;await api('/api/admin/files/'+id,'DELETE');showTab('files')}
function doLogout(){token='';document.getElementById('loginPage').style.display='';document.getElementById('app').style.display='none'}
</script></body></html>`

// ==================== Express ====================
async function startServer(){
  _SQL=await initSqlJs();initDB()
  const PORT=process.env.PORT||process.env.API_PORT||3456
  const app=express();app.use(cors());app.use(express.json({limit:'1mb'}))
  const uploadFile=multer({storage:multer.memoryStorage(),limits:{fileSize:500*1024*1024}}).single('file')
  const STORAGE_DIR=()=>{const d=path.join(getDataDir(),'storage');try{fs.mkdirSync(d,{recursive:true})}catch{};return d}
  function fileUid(){return crypto.randomBytes(12).toString('hex')}

  function auth(req,res,next){const key=(req.headers['authorization']||'').replace('Bearer ','');if(!key)return res.status(401).json({error:'no key'});const r=db.exec('SELECT * FROM api_keys WHERE key=?',[key]);if(!r.length||!r[0].values.length)return res.status(403).json({error:'bad key'});db.run('UPDATE api_keys SET last_used=?,usage_count=usage_count+1 WHERE key=?',[new Date().toISOString(),key]);next()}

  // API Keys
  app.post('/api/keys/create',(req,res)=>{const{name}=req.body;if(!name)return res.status(400).json({error:'missing name'});const r=db.exec('SELECT * FROM api_keys WHERE name=?',[name]);if(r.length&&r[0].values.length)return res.status(400).json({error:'exists'});const k='sk-'+crypto.randomBytes(24).toString('hex');db.run('INSERT INTO api_keys VALUES(?,?,?,NULL,0)',[name,k,new Date().toISOString()]);saveDB();res.json({name,key:k})})
  app.get('/api/keys/list',(req,res)=>{const r=db.exec('SELECT * FROM api_keys');const keys=(r[0]||{values:[]}).values.map(v=>({name:v[0],key:v[1].slice(0,7)+'***'+v[1].slice(-4),created:v[2],lastUsed:v[3],usage:v[4]}));res.json(keys)})
  app.delete('/api/keys/:name',(req,res)=>{db.run('DELETE FROM api_keys WHERE name=?',[req.params.name]);saveDB();res.json({ok:true})})

  // SM3/SM4/SM2 API
  app.post('/api/sm3/hash',auth,(req,res)=>{const{data}=req.body;if(!data)return res.status(400).json({error:'missing'});res.json({hash:sm3HashHex(data)})})
  app.post('/api/sm3/hmac',auth,(req,res)=>{const{key,data}=req.body;res.json({hmac:sm3HMACHex(key,data)})})
  app.post('/api/sm4/encrypt',auth,(req,res)=>{const{p,k}=req.body;try{res.json({c:sm4EncryptCBCFromHex(p,k)})}catch(e){res.status(400).json({error:e.message})}})
  app.post('/api/sm4/decrypt',auth,(req,res)=>{const{c,k}=req.body;try{res.json({p:sm4DecryptCBCToText(c,k)})}catch(e){res.status(400).json({error:e.message})}})
  app.post('/api/sm2/keygen',auth,(req,res)=>{res.json(sm2GenKey())})
  app.post('/api/sm2/sign',auth,(req,res)=>{const{m,pk,sk}=req.body;try{res.json(sm2Sign(m,pk,sk))}catch(e){res.status(400).json({error:e.message})}})
  app.post('/api/sm2/verify',auth,(req,res)=>{const{m,r,s,pk}=req.body;try{res.json({v:sm2Verify(m,{r,s},pk)})}catch(e){res.status(400).json({error:e.message})}})
  app.post('/api/sm2/encrypt',auth,(req,res)=>{const{m,pk}=req.body;try{res.json({c:sm2Encrypt(m,pk)})}catch(e){res.status(400).json({error:e.message})}})
  app.post('/api/sm2/decrypt',auth,(req,res)=>{const{c,sk}=req.body;try{res.json({p:new TextDecoder().decode(sm2Decrypt(c,sk))})}catch(e){res.status(400).json({error:e.message})}})

  // ===== 瀹¤鏃ュ織 =====
  const sessions={}
  function addLog(username,action,target,detail){
    try{db.run('INSERT INTO audit_logs(username,action,target,detail,created_at) VALUES(?,?,?,?,?)',[username||'unknown',action,target||'',detail||'',new Date().toISOString()]);saveDB()}catch{}
  }
  function adminAuth(req,res,next){
    const token=(req.headers['authorization']||'').replace('Bearer ','')
    const s=sessions[token]
    if(!s||s.expires<Date.now())return res.status(401).json({error:'璇峰厛鐧诲綍'})
    const ur=db.exec('SELECT role FROM users WHERE username=?',[s.username])
    if(!ur.length||ur[0].values[0][0]!=='admin')return res.status(403).json({error:'闇€绠＄悊鍛樻潈闄?})
    req.user=s.username;next()
  }
  function userAuth(req,res,next){const token=(req.headers['authorization']||'').replace('Bearer ','');const s=sessions[token];if(!s||s.expires<Date.now())return res.status(401).json({error:'not logged in'});req.user=s.username;next()}

  // ===== 绠＄悊鍛樼郴缁?=====
  app.post('/api/admin/login',(req,res)=>{
    const{username,password}=req.body
    const r=db.exec('SELECT * FROM users WHERE username=? AND password_hash=? AND role=?',[username,sm3HashHex(password),'admin'])
    if(!r.length||!r[0].values.length)return res.status(403).json({error:'绠＄悊鍛橀獙璇佸け璐?})
    const token=crypto.randomBytes(32).toString('hex')
    sessions[token]={username,expires:Date.now()+86400000}
    addLog(username,'admin_login','','绠＄悊鍛樼櫥褰?)
    res.json({ok:true,token})
  })
  app.get('/api/admin/stats',adminAuth,(req,res)=>{
    const uc=db.exec('SELECT COUNT(*) FROM users');const fc=db.exec('SELECT COUNT(*) FROM files');const sc=db.exec('SELECT COUNT(*) FROM shares');const ac=db.exec('SELECT COUNT(*) FROM audit_logs')
    res.json({users:uc[0].values[0][0],files:fc[0].values[0][0],shares:sc[0].values[0][0],auditLogs:ac[0].values[0][0]})
  })
  app.get('/api/admin/users',adminAuth,(req,res)=>{
    const r=db.exec('SELECT username,created,role FROM users ORDER BY created DESC')
    res.json((r[0]||{values:[]}).values.map(v=>({username:v[0],created:v[1],role:v[2]||'user'})))
  })
  app.delete('/api/admin/users/:username',adminAuth,(req,res)=>{
    if(req.params.username===req.user)return res.status(400).json({error:'涓嶈兘鍒犻櫎鑷繁'})
    db.run('DELETE FROM shares WHERE file_id IN (SELECT id FROM files WHERE owner=?)',[req.params.username])
    db.run('DELETE FROM shares WHERE username=?',[req.params.username])
    db.run('DELETE FROM files WHERE owner=?',[req.params.username])
    db.run('DELETE FROM users WHERE username=?',[req.params.username])
    saveDB();addLog(req.user,'delete_user',req.params.username,'绠＄悊鍛樺垹闄ょ敤鎴?)
    res.json({ok:true})
  })
  app.get('/api/admin/files',adminAuth,(req,res)=>{
    const r=db.exec('SELECT id,owner,original_name,size,uploaded_at FROM files ORDER BY uploaded_at DESC')
    res.json((r[0]||{values:[]}).values.map(v=>({id:v[0],owner:v[1],name:v[2],size:v[3],uploadedAt:v[4]})))
  })
  app.delete('/api/admin/files/:id',adminAuth,(req,res)=>{
    db.run('DELETE FROM shares WHERE file_id=?',[req.params.id]);db.run('DELETE FROM files WHERE id=?',[req.params.id]);saveDB();addLog(req.user,'delete_file',req.params.id,'绠＄悊鍛樺垹闄ゆ枃浠?);res.json({ok:true})
  })
  app.get('/api/admin/logs',adminAuth,(req,res)=>{
    const r=db.exec('SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200')
    res.json((r[0]||{values:[]}).values.map(v=>({id:v[0],username:v[1],action:v[2],target:v[3],detail:v[4],createdAt:v[5]})))
  })

  // ===== 鐢ㄦ埛绯荤粺 (SQLite) =====
  app.post('/api/user/register',(req,res)=>{
    const{username,password}=req.body
    if(!username||!password)return res.status(400).json({error:'missing fields'})
    if(!/^[a-zA-Z0-9_涓€-榫{2,20}$/.test(username))return res.status(400).json({error:'invalid username'})
    const r=db.exec('SELECT * FROM users WHERE username=?',[username])
    if(r.length&&r[0].values.length)return res.status(400).json({error:'exists'})
    db.run('INSERT INTO users VALUES(?,?,?,?,?)',[username,sm3HashHex(password),'',new Date().toISOString(),'user'])
    saveDB();addLog(username,'register','','鏂扮敤鎴锋敞鍐?);res.json({ok:true,username})
  })
  app.post('/api/user/login',(req,res)=>{
    const{username,password}=req.body
    const r=db.exec('SELECT * FROM users WHERE username=? AND password_hash=?',[username,sm3HashHex(password)])
    if(!r.length||!r[0].values.length)return res.status(401).json({error:'wrong credentials'})
    const token=crypto.randomBytes(32).toString('hex')
    sessions[token]={username,expires:Date.now()+86400000}
    const pubKey=r[0].values[0][2]||''
    addLog(username,'login','','鐢ㄦ埛鐧诲綍');res.json({ok:true,username,token,pubKey})
  })
  app.get('/api/user/info',(req,res)=>{
    const token=(req.headers['authorization']||'').replace('Bearer ','')
    const s=sessions[token];if(!s||s.expires<Date.now())return res.status(401).json({error:'not logged in'})
    const r=db.exec('SELECT * FROM users WHERE username=?',[s.username])
    res.json({username:s.username,pubKey:(r[0]||{values:[[null,'','']]})[0].values[0][2]||''})
  })
  app.post('/api/user/savePubKey',(req,res)=>{
    const token=(req.headers['authorization']||'').replace('Bearer ','')
    const s=sessions[token];if(!s)return res.status(401).json({error:'not logged in'})
    db.run('UPDATE users SET pub_key=? WHERE username=?',[req.body.pubKey||'',s.username]);saveDB();res.json({ok:true})
  })
  app.get('/api/users/list',(req,res)=>{
    const token=(req.headers['authorization']||'').replace('Bearer ','')
    if(!sessions[token])return res.status(401).json({error:'not logged in'})
    const r=db.exec('SELECT username,pub_key FROM users ORDER BY username')
    res.json((r[0]||{values:[]}).values.map(v=>({username:v[0],pubKey:v[1]||'鏈缃?})))
  })
  app.post('/api/user/logout',(req,res)=>{const token=(req.headers['authorization']||'').replace('Bearer ','');delete sessions[token];res.json({ok:true})})

  // ===== 鏂囦欢 (SQLite) =====
  app.post('/api/files/upload',userAuth,(req,res)=>{uploadFile(req,res,function(err){if(err)return res.status(err.code==='LIMIT_FILE_SIZE'?413:500).json({error:err.message});try{const{name,originalName,sm3Hash,pubKey,signature,encryptedKey}=req.body;if(!req.file||!req.file.buffer)return res.status(400).json({error:'no file'});if(!name||!pubKey||!sm3Hash)return res.status(400).json({error:'missing fields'});const id=fileUid();fs.writeFileSync(path.join(STORAGE_DIR(),id+'.enc'),req.file.buffer);let sig=null;try{sig=typeof signature==='string'?JSON.parse(signature):signature}catch{};db.run('INSERT INTO files VALUES(?,?,?,?,?,?,?,?,?,?)',[id,req.user,name,originalName||name,req.file.size,sm3Hash,pubKey,sig?JSON.stringify(sig):'',encryptedKey||'',new Date().toISOString()]);saveDB();if(req.body.pubKey){const ur=db.exec('SELECT pub_key FROM users WHERE username=?',[req.user]);if(!ur[0].values[0][0]){db.run('UPDATE users SET pub_key=? WHERE username=?',[pubKey,req.user]);saveDB()}}res.json({id,name,size:req.file.size})}catch(e){res.status(500).json({error:e.message})}})})
  app.get('/api/files/list',userAuth,(req,res)=>{
    const my=db.exec('SELECT * FROM files WHERE owner=? ORDER BY uploaded_at DESC',[req.user])
    const myFiles=(my[0]||{values:[]}).values.map(r=>({id:r[0],owner:req.user,name:r[2],originalName:r[3],size:r[4],sm3Hash:r[5],pubKey:r[6],signature:r[7]?JSON.parse(r[7]):null,encryptedKey:r[8],uploadedAt:r[9],isMine:true}))
    const sr=db.exec("SELECT f.*,s.username as shared_to FROM files f JOIN shares s ON f.id=s.file_id WHERE s.username=? ORDER BY f.uploaded_at DESC",[req.user])
    const sharedFiles=(sr[0]||{values:[]}).values.map(r=>({id:r[0],owner:r[1],name:r[2],originalName:r[3],size:r[4],sm3Hash:r[5],pubKey:r[6],signature:r[7]?JSON.parse(r[7]):null,encryptedKey:r[8],uploadedAt:r[9],isMine:false,sharedBy:r[1]}))
    // get authorized pubKeys for my files
    const authMap={}
    for(const f of myFiles){const ar=db.exec('SELECT username FROM shares WHERE file_id=?',[f.id]);authMap[f.id]=(ar[0]||{values:[]}).values.map(v=>({username:v[0]}))}
    res.json({my:myFiles.map(f=>({...f,authorizedUsers:authMap[f.id]||[]})),shared:sharedFiles.map(f=>({...f,authorizedUsers:[]}))})
  })
  app.get('/api/files/:id',userAuth,(req,res)=>{
    let r=db.exec('SELECT * FROM files WHERE id=? AND owner=?',[req.params.id,req.user])
    if(!r.length||!r[0].values.length){r=db.exec("SELECT f.*,s.username as shared_to FROM files f JOIN shares s ON f.id=s.file_id WHERE f.id=? AND s.username=?",[req.params.id,req.user])}
    if(!r.length||!r[0].values.length)return res.status(404).json({error:'not found'})
    const v=r[0].values[0];res.json({id:v[0],owner:v[1],name:v[2],originalName:v[3],size:v[4],sm3Hash:v[5],pubKey:v[6],signature:v[7]?JSON.parse(v[7]):null,encryptedKey:v[8],uploadedAt:v[9]})
  })
  app.get('/api/files/:id/download',userAuth,(req,res)=>{
    let r=db.exec('SELECT * FROM files WHERE id=? AND owner=?',[req.params.id,req.user])
    if(!r.length||!r[0].values.length){r=db.exec("SELECT f.* FROM files f JOIN shares s ON f.id=s.file_id WHERE f.id=? AND s.username=?",[req.params.id,req.user])}
    if(!r.length||!r[0].values.length)return res.status(404).json({error:'not found'})
    const fp=path.join(STORAGE_DIR(),req.params.id+'.enc');if(!fs.existsSync(fp))return res.status(404).json({error:'file lost'});res.setHeader('Content-Disposition','attachment; filename="'+encodeURIComponent(r[0].values[0][2])+'"');res.sendFile(fp)
  })
  app.post('/api/files/:id/share',userAuth,(req,res)=>{
    const{targetPubKey,grantSignature}=req.body
    if(!targetPubKey||!grantSignature)return res.status(400).json({error:'missing targetPubKey or grantSignature'})
    const fr=db.exec('SELECT * FROM files WHERE id=? AND owner=?',[req.params.id,req.user])
    if(!fr.length||!fr[0].values.length)return res.status(404).json({error:'not found'})
    // Look up target username from pubKey
    const ur=db.exec('SELECT username FROM users WHERE pub_key=?',[targetPubKey])
    if(!ur.length||!ur[0].values.length)return res.status(404).json({error:'target user not found, ask them to generate SM2 key first'})
    const targetUser=ur[0].values[0][0]
    const sr=db.exec('SELECT * FROM shares WHERE file_id=? AND username=?',[req.params.id,targetUser])
    if(sr.length&&sr[0].values.length)return res.status(400).json({error:'already shared'})
    let sigStr='';try{sigStr=typeof grantSignature==='string'?grantSignature:JSON.stringify(grantSignature)}catch{}
    db.run('INSERT INTO shares VALUES(?,?,?)',[req.params.id,targetUser,new Date().toISOString()])
    saveDB();res.json({ok:true})
  })
  app.delete('/api/files/:id',userAuth,(req,res)=>{
    const r=db.exec('SELECT * FROM files WHERE id=? AND owner=?',[req.params.id,req.user])
    if(!r.length||!r[0].values.length)return res.status(404).json({error:'not found'})
    const fp=path.join(STORAGE_DIR(),req.params.id+'.enc');if(fs.existsSync(fp))fs.unlinkSync(fp)
    db.run('DELETE FROM shares WHERE file_id=?',[req.params.id]);db.run('DELETE FROM files WHERE id=?',[req.params.id]);saveDB();res.json({ok:true})
  })

  app.get('/',(req,res)=>{res.json({service:'SMC Storage',version:'1.0.0',docs:'https://smc-storage.onrender.com/api/health'})})
  app.get('/api/health',(req,res)=>{
    const r=db.exec('SELECT COUNT(*) FROM files')
    const count=r[0]?r[0].values[0][0]:0
    res.json({ok:true,status:'ok',mode:'E2EE Multi-User SQLite',files:count})
  })

  // ===== Admin 缃戦〉鍚庡彴 =====
  app.get('/admin',(req,res)=>{res.type('html').send(ADMIN_HTML)})

  app.listen(PORT,'0.0.0.0',()=>console.log('[SMC SQLite] http://0.0.0.0:'+PORT))
}

module.exports={startServer}

startServer()

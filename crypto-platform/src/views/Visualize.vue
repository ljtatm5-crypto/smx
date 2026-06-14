<template>
  <div class="page">
    <h2>📐 国密算法原理可视化</h2>
    <p class="page-desc">动态展示 SM4/SM3/SM2 算法内部运算过程。输入数据，逐轮观察变化。</p>

    <div class="mode-tabs" style="margin-bottom:1.5rem">
      <button :class="{ active: algo === 'sm4' }" @click="algo = 'sm4'">SM4 · 分组密码</button>
      <button :class="{ active: algo === 'sm3' }" @click="algo = 'sm3'">SM3 · 哈希算法</button>
      <button :class="{ active: algo === 'sm2' }" @click="algo = 'sm2'">SM2 · 椭圆曲线</button>
    </div>

    <!-- ==================== SM4 ==================== -->
    <template v-if="algo === 'sm4'">
      <div class="tool-card" style="margin-bottom:1rem">
        <div class="input-row" style="gap:1rem">
          <div style="flex:1"><label style="font-size:0.8rem;color:var(--text2)">明文 (32 hex)</label><input v-model="sm4Plain" /></div>
          <div style="flex:1"><label style="font-size:0.8rem;color:var(--text2)">密钥 (32 hex)</label><input v-model="sm4Key" /></div>
          <button class="btn-sm" style="align-self:flex-end" @click="sm4Init">🔄</button>
        </div>
        <p style="font-size:0.75rem;color:var(--text2);margin-top:0.4rem">
          128 位 = 4 个 32 位寄存器 (X0,X1,X2,X3)。每轮：T(X1⊕X2⊕X3⊕rk) → 与 X0 异或 → 寄存器左移。32 轮后逆序输出。
        </p>
      </div>
      <div class="tool-card" style="margin-bottom:1rem;text-align:center;overflow-x:auto">
        <canvas ref="sm4Canvas" width="1200" height="500" style="width:100%;background:#0b1121;border-radius:8px"></canvas>
      </div>
      <div class="tool-card" style="text-align:center">
        <div class="input-row" style="justify-content:center;gap:0.5rem">
          <button class="btn-sm" @click="sm4Step(-1)">⏮</button>
          <button class="btn-sm" @click="sm4Step(1)">▶ 单步</button>
          <button class="btn-primary" style="width:auto;padding:0.5rem 1.5rem" @click="sm4Toggle">{{ sm4Playing ? '⏸ 暂停' : '▶ 自动播放' }}</button>
          <button class="btn-sm" @click="sm4Step(32)">⏭</button>
        </div>
        <div style="margin-top:0.5rem;font-size:0.8rem;color:var(--text2)">
          速度 <input type="range" min="1" max="10" v-model="sm4Speed" style="width:100px;vertical-align:middle" /> &nbsp;
          第 <strong style="color:var(--accent)">{{ sm4Round }}</strong>/32 轮
          <span v-if="sm4Round===32" style="color:#4ade80;margin-left:0.5rem">✅ 加密完成</span>
        </div>
      </div>
    </template>

    <!-- ==================== SM3 ==================== -->
    <template v-if="algo === 'sm3'">
      <div class="tool-card" style="margin-bottom:1rem">
        <div class="input-row" style="gap:1rem">
          <div style="flex:1"><label style="font-size:0.8rem;color:var(--text2)">输入消息</label><input v-model="sm3Msg" /></div>
          <button class="btn-sm" style="align-self:flex-end" @click="sm3Init">🔄</button>
        </div>
        <p style="font-size:0.75rem;color:var(--text2);margin-top:0.4rem">
          IV 初始值 → 消息扩展(132字) → 64轮压缩(A-H寄存器) → 输出256位哈希
        </p>
      </div>
      <div class="tool-card" style="margin-bottom:1rem;text-align:center;overflow-x:auto">
        <canvas ref="sm3Canvas" width="1200" height="500" style="width:100%;background:#0b1121;border-radius:8px"></canvas>
      </div>
      <div class="tool-card" style="text-align:center">
        <div class="input-row" style="justify-content:center;gap:0.5rem">
          <button class="btn-sm" @click="sm3Step(-1)">⏮</button>
          <button class="btn-sm" @click="sm3Step(1)">▶ 单步</button>
          <button class="btn-primary" style="width:auto;padding:0.5rem 1.5rem" @click="sm3Toggle">{{ sm3Playing ? '⏸ 暂停' : '▶ 自动播放' }}</button>
          <button class="btn-sm" @click="sm3Step(64)">⏭</button>
        </div>
        <div style="margin-top:0.5rem;font-size:0.8rem;color:var(--text2)">
          速度 <input type="range" min="1" max="10" v-model="sm3Speed" style="width:100px;vertical-align:middle" /> &nbsp;
          第 <strong style="color:var(--accent)">{{ sm3Round }}</strong>/64 轮
        </div>
      </div>
    </template>

    <!-- ==================== SM2 ==================== -->
    <template v-if="algo === 'sm2'">
      <div class="tool-card" style="margin-bottom:1rem">
        <p style="font-size:0.85rem;color:var(--text2)">
          椭圆曲线 y² = x³ + ax + b，SM2 推荐参数。演示点加法、倍乘运算的几何意义，以及签名过程中 kG 的计算。
        </p>
        <div style="font-size:0.75rem;color:var(--text2);margin-top:0.3rem">
          p = FFFFFEFFFF...FFFFFFFF (256位) &nbsp;|&nbsp; a = FFFFFEFF...FFFFFFFC &nbsp;|&nbsp; G = 生成元点
        </div>
      </div>
      <div class="tool-card" style="margin-bottom:1rem;text-align:center;overflow-x:auto">
        <canvas ref="sm2Canvas" width="1200" height="550" style="width:100%;background:#0b1121;border-radius:8px"></canvas>
      </div>
      <div class="tool-card" style="text-align:center">
        <div class="input-row" style="justify-content:center;gap:0.5rem;margin-bottom:0.5rem">
          <button class="btn-sm" @click="sm2Zoom(-20)">🔍−</button>
          <button class="btn-sm" @click="sm2Zoom(20)">🔍+</button>
          <button class="btn-sm" @click="sm2Toggle">{{ sm2Playing ? '⏸ 暂停' : '▶ 自动演示' }}</button>
          <button class="btn-sm" @click="sm2Reset">🔄 重置</button>
        </div>
        <div style="font-size:0.8rem;color:var(--text2)">
          k = <strong style="color:var(--accent)">{{ sm2K }}</strong> &nbsp;|&nbsp; 缩放 {{ Math.round(sm2Scale) }}%
          &nbsp;|&nbsp; 鼠标: <strong style="color:var(--accent)">({{ sm2Mouse.x.toFixed(2) }}, {{ sm2Mouse.y.toFixed(2) }})</strong>
          &nbsp;|&nbsp; 滚轮缩放 · 拖拽平移
        </div>
      </div>
    </template>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted, nextTick } from 'vue'

const algo = ref('sm4')

// ==================== SM4 ====================
const sm4Plain = ref('6d6573736167652064696765737473')  // "message digests" 的 ASCII hex
const sm4Key = ref('0123456789abcdeffedcba9876543210')
const sm4Round = ref(0); const sm4Playing = ref(false); const sm4Speed = ref(4)
const sm4Canvas = ref(null); let sm4Timer = null
const sm4States = ref([])

const SM4_SBOX = [0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48]
const SM4_FK = [0xa3b1bac6,0x56aa3350,0x677d9197,0xb27022dc]
const SM4_CK = [0x00070e15,0x1c232a31,0x383f464d,0x545b6269,0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,0x30373e45,0x4c535a61,0x686f767d,0x848b9299,0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,0x10171e25,0x2c333a41,0x484f565d,0x646b7279]

function sm4Init() { sm4Round.value=0;sm4Playing.value=false;clearInterval(sm4Timer);sm4Compute();sm4Draw() }
function sm4Compute() {
  const rotl=(x,n)=>((x<<n)|(x>>>32-n))>>>0
  const sbox=x=>SM4_SBOX[x&0xff]|(SM4_SBOX[(x>>>8)&0xff]<<8)|(SM4_SBOX[(x>>>16)&0xff]<<16)|(SM4_SBOX[(x>>>24)&0xff]<<24)
  const L=x=>x^rotl(x,2)^rotl(x,10)^rotl(x,18)^rotl(x,24)
  const Lp=x=>x^rotl(x,13)^rotl(x,23)
  const T=x=>L(sbox(x)); const Tp=x=>Lp(sbox(x))
  const ph=sm4Plain.value.replace(/\s/g,''), kh=sm4Key.value.replace(/\s/g,'')
  const mk=[],k=[],rk=[]
  for(let i=0;i<4;i++)mk[i]=(parseInt(ph.substr(i*8,2),16)<<24)|(parseInt(ph.substr(i*8+2,2),16)<<16)|(parseInt(ph.substr(i*8+4,2),16)<<8)|parseInt(ph.substr(i*8+6,2),16)
  for(let i=0;i<4;i++){const b=(parseInt(kh.substr(i*8,2),16)<<24)|(parseInt(kh.substr(i*8+2,2),16)<<16)|(parseInt(kh.substr(i*8+4,2),16)<<8)|parseInt(kh.substr(i*8+6,2),16);k[i]=b^SM4_FK[i]}
  for(let i=0;i<32;i++){rk[i]=k[i]^Tp(k[i+1]^k[i+2]^k[i+3]^SM4_CK[i]);k[i+4]=rk[i]}
  const x=[]; for(let i=0;i<4;i++)x[i]=mk[i]
  const rounds=[{x:[...x]}]
  for(let i=0;i<32;i++){x.push(x[i]^T(x[i+1]^x[i+2]^x[i+3]^rk[i]));rounds.push({x:[...x]})}
  sm4States.value=rounds
}

function sm4Draw() {
  const c=sm4Canvas.value;if(!c||!sm4States.value.length)return
  const ctx=c.getContext('2d'),W=c.width,H=c.height
  ctx.clearRect(0,0,W,H)
  ctx.fillStyle='#e8edf5';ctx.font='bold 15px "Microsoft YaHei"';ctx.fillText(`SM4 — 第 ${sm4Round.value} / 32 轮`,20,28)
  const s=sm4States.value[Math.min(sm4Round.value,32)]
  if(!s)return
  const colors=['#ef4444','#f59e0b','#38bdf8','#22c55e'], labels=['X0','X1','X2','X3']
  for(let i=0;i<4;i++){
    const idx=sm4Round.value+i, val=s.x[idx]||0, hex=val.toString(16).padStart(8,'0').toUpperCase()
    ctx.fillStyle=colors[i]+'18';ctx.fillRect(30,55+i*72,W-60,60)
    ctx.strokeStyle=colors[i];ctx.lineWidth=1.5;ctx.strokeRect(30,55+i*72,W-60,60)
    ctx.fillStyle=colors[i];ctx.font='bold 14px "Consolas"';ctx.fillText(labels[i]+' = '+hex,45,55+i*72+22)
    for(let b=0;b<32;b++){const v=(val>>>31-b)&1,bx=300+b*19,by=55+i*72+34;ctx.fillStyle=v?'#fbbf24':'#1a2744';ctx.fillRect(bx,by,16,13);ctx.fillStyle='#0b1121';ctx.font='8px "Consolas"';ctx.fillText(v,bx+5,by+10)}
  }
  // 箭头
  if(sm4Round.value<32){ctx.fillStyle='#38bdf8';ctx.font='14px sans-serif';ctx.fillText('→ 第'+sm4Round.value+'轮 T(X1⊕X2⊕X3⊕rk) ⊕ X0 →',W-320,H-15)}
  else{ctx.fillStyle='#4ade80';ctx.font='13px sans-serif';ctx.fillText('✅ 密文 = 逆序输出 (X35,X34,X33,X32)',W-380,H-15)}
}

function sm4Step(n){sm4Round.value=Math.max(0,Math.min(32,sm4Round.value+n));sm4Draw()}
function sm4Toggle(){sm4Playing.value=!sm4Playing.value;if(sm4Playing.value){sm4Timer=setInterval(()=>{if(sm4Round.value<32){sm4Round.value++;sm4Draw()}else{sm4Playing.value=false;clearInterval(sm4Timer)}},1200/sm4Speed.value)}else clearInterval(sm4Timer)}

// ==================== SM3 ====================
const sm3Msg=ref('abc');const sm3Round=ref(0);const sm3Playing=ref(false);const sm3Speed=ref(5)
const sm3Canvas=ref(null);let sm3Timer=null;const sm3States=ref([]);const sm3FinalHash=ref('')

function sm3Init(){sm3Round.value=0;sm3Playing.value=false;clearInterval(sm3Timer);sm3Compute();sm3Draw()}
function sm3Compute(){
  const SM3_IV=[0x7380166f,0x4914b2b9,0x172442d7,0xda8a0600,0xa96f30bc,0x163138aa,0xe38dee4d,0xb0fb0e4e]
  const rotl=(x,n)=>((x<<n)|(x>>>32-n))>>>0
  const p0=x=>x^rotl(x,9)^rotl(x,17);const p1=x=>x^rotl(x,15)^rotl(x,23)
  const ff0=(x,y,z)=>x^y^z;const ff1=(x,y,z)=>(x&y)|(x&z)|(y&z)
  const gg0=(x,y,z)=>x^y^z;const gg1=(x,y,z)=>(x&y)|(~x&z)
  const msg=new TextEncoder().encode(sm3Msg.value)
  const len=msg.length*8
  const pad=(448-(len+1)%512+512)%512,total=(len+1+pad+64)/8
  const buf=new Uint8Array(total);buf.set(msg);buf[msg.length]=0x80
  const dv=new DataView(buf.buffer);dv.setUint32(total-4,len&0xffffffff);dv.setUint32(total-8,Math.floor(len/0x100000000))
  const V=[...SM3_IV];const W=new Uint32Array(68),W1=new Uint32Array(64)
  const rounds=[]
  for(let blk=0;blk<total;blk+=64){
    for(let i=0;i<16;i++)W[i]=dv.getUint32(blk+i*4)
    for(let i=16;i<68;i++)W[i]=p1(W[i-16]^W[i-9]^rotl(W[i-3],15))^rotl(W[i-13],7)^W[i-6]
    for(let i=0;i<64;i++)W1[i]=W[i]^W[i+4]
    let A=V[0],B=V[1],C=V[2],D=V[3],E=V[4],F=V[5],G=V[6],H=V[7]
    for(let j=0;j<64;j++){
      const Tj=j<16?0x79cc4519:0x7a879d8a
      const SS1=rotl(rotl(A,12)+E+rotl(Tj,j%32),7),SS2=SS1^rotl(A,12)
      const TT1=j<16?ff0(A,B,C)+D+SS2+W1[j]:ff1(A,B,C)+D+SS2+W1[j]
      const TT2=j<16?gg0(E,F,G)+H+SS1+W[j]:gg1(E,F,G)+H+SS1+W[j]
      D=C;C=rotl(B,9);B=A;A=TT1;H=G;G=rotl(F,19);F=E;E=p0(TT2)
      rounds.push({A,B,C,D,E,F,G,H,Wj:W[j],W1j:W1[j]})
    }
    V[0]^=A;V[1]^=B;V[2]^=C;V[3]^=D;V[4]^=E;V[5]^=F;V[6]^=G;V[7]^=H
  }
  sm3States.value=rounds
  const hash=[];for(let i=0;i<8;i++)hash.push(V[i].toString(16).padStart(8,'0'))
  sm3FinalHash.value=hash.join('')
}

function sm3Draw(){
  const c=sm3Canvas.value;if(!c)return
  const ctx=c.getContext('2d'),W=c.width,H=c.height
  ctx.clearRect(0,0,W,H)
  ctx.fillStyle='#e8edf5';ctx.font='bold 15px "Microsoft YaHei"'
  ctx.fillText(`SM3 压缩函数 — 第 ${sm3Round.value} / 64 轮`,20,28)
  if(!sm3States.value.length)return
  const s=sm3States.value[Math.min(sm3Round.value,63)]||sm3States.value[63]
  if(!s)return
  const regs=['A','B','C','D','E','F','G','H']
  const vals=[s.A,s.B,s.C,s.D,s.E,s.F,s.G,s.H]
  const colors2=['#ef4444','#f59e0b','#38bdf8','#22c55e','#a855f7','#ec4899','#14b8a6','#f97316']
  for(let i=0;i<8;i++){
    const hex=vals[i].toString(16).padStart(8,'0').toUpperCase()
    ctx.fillStyle=colors2[i]+'22';ctx.fillRect(20,48+i*38,480,33)
    ctx.strokeStyle=colors2[i];ctx.strokeRect(20,48+i*38,480,33)
    ctx.fillStyle=colors2[i];ctx.font='bold 13px "Consolas"';ctx.fillText(regs[i],30,48+i*38+23)
    ctx.fillStyle='#fbbf24';ctx.fillText(hex,70,48+i*38+23)
  }
  if(sm3FinalHash.value&&sm3Round.value===64){ctx.fillStyle='#4ade80';ctx.font='12px "Consolas"';ctx.fillText('✅ SM3('+sm3Msg.value+') = '+sm3FinalHash.value.slice(0,32)+'...',20,360)}
}

function sm3Step(n){sm3Round.value=Math.max(0,Math.min(64,sm3Round.value+n));sm3Draw()}
function sm3Toggle(){sm3Playing.value=!sm3Playing.value;if(sm3Playing.value){sm3Timer=setInterval(()=>{if(sm3Round.value<64){sm3Round.value++;sm3Draw()}else{sm3Playing.value=false;clearInterval(sm3Timer)}},1000/sm3Speed.value)}else clearInterval(sm3Timer)}

// ==================== SM2 ====================
const sm2Canvas=ref(null);const sm2K=ref(1);const sm2Playing=ref(false);let sm2Timer=null
const sm2Scale=ref(80);const sm2Ox=ref(0);const sm2Oy=ref(0)
const sm2Mouse=ref({x:0,y:0})
let sm2Dragging=false,sm2LastX=0,sm2LastY=0

// 曲线 y² = x³ + x + 1, G = (0, 1)
const SM2_A2=1,SM2_B2=1
const SM2_G2={x:0,y:1}

function sm2Zoom(d){sm2Scale.value=Math.max(10,Math.min(500,sm2Scale.value+d));sm2Draw()}
function sm2Reset(){sm2K.value=1;sm2Playing.value=false;clearInterval(sm2Timer);sm2Scale.value=80;sm2Ox.value=0;sm2Oy.value=0;sm2Draw()}
function sm2Toggle(){sm2Playing.value=!sm2Playing.value;if(sm2Playing.value){sm2Timer=setInterval(()=>{if(sm2K.value<12){sm2K.value++;sm2Draw()}else{sm2Playing.value=false;clearInterval(sm2Timer)}},1000)}else clearInterval(sm2Timer)}

function ecY2(x,a,b){return x*x*x+a*x+b}
function ecAdd(P,Q,a){
  if(!P)return Q;if(!Q)return P
  let m
  if(Math.abs(P.x-Q.x)<1e-8&&Math.abs(P.y-Q.y)<1e-8){
    if(Math.abs(P.y)<1e-8)return null
    m=(3*P.x*P.x+a)/(2*P.y)
  }else{
    if(Math.abs(P.x-Q.x)<1e-8)return null
    m=(Q.y-P.y)/(Q.x-P.x)
  }
  const x3=m*m-P.x-Q.x
  const y3=m*(P.x-x3)-P.y
  return {x:x3,y:y3,m}
}

function sm2Draw(){
  const c=sm2Canvas.value;if(!c)return
  const ctx=c.getContext('2d'),W=c.width,H=c.height
  ctx.fillStyle='#0b1121';ctx.fillRect(0,0,W,H)

  const ox=W/2+sm2Ox.value,oy=H/2+sm2Oy.value,scale=sm2Scale.value
  const xMin=(-ox)/scale,xMax=(W-ox)/scale

  // 网格
  ctx.strokeStyle='#1a2744';ctx.lineWidth=0.5
  const gs=scale>=40?1:scale>=20?0.5:0.2
  for(let x=Math.floor(xMin);x<=xMax;x+=gs){
    const sx=ox+x*scale;ctx.beginPath();ctx.moveTo(sx,10);ctx.lineTo(sx,H-10);ctx.stroke()
  }
  for(let y=Math.floor(-oy/scale);y<=(H-oy)/scale;y+=gs){
    const sy=oy+y*scale;ctx.beginPath();ctx.moveTo(10,sy);ctx.lineTo(W-10,sy);ctx.stroke()
  }
  // 坐标轴
  ctx.strokeStyle='#475569';ctx.lineWidth=1
  if(ox>10&&ox<W-10){ctx.beginPath();ctx.moveTo(ox,10);ctx.lineTo(ox,H-10);ctx.stroke()}
  if(oy>10&&oy<H-10){ctx.beginPath();ctx.moveTo(10,oy);ctx.lineTo(W-10,oy);ctx.stroke()}

  // 标题
  ctx.fillStyle='#e8edf5';ctx.font='bold 16px "Microsoft YaHei"'
  ctx.fillText('SM2 椭圆曲线 · y² = x³ + x + 1 · 滚轮缩放 · 拖拽平移',20,28)

  // 曲线
  ctx.strokeStyle='#38bdf8';ctx.lineWidth=2.5
  ctx.beginPath();let f=true
  for(let sx=xMin;sx<=xMax;sx+=0.005){
    const y2=ecY2(sx,SM2_A2,SM2_B2)
    if(y2>=0){const sy=Math.sqrt(y2);const px=ox+sx*scale,py=oy-sy*scale;if(py>10&&py<H-10){if(f){ctx.moveTo(px,py);f=false}else ctx.lineTo(px,py)}}
  }
  ctx.stroke()
  ctx.beginPath();f=true
  for(let sx=xMin;sx<=xMax;sx+=0.005){
    const y2=ecY2(sx,SM2_A2,SM2_B2)
    if(y2>=0){const sy=Math.sqrt(y2);const px=ox+sx*scale,py=oy+sy*scale;if(py>10&&py<H-10){if(f){ctx.moveTo(px,py);f=false}else ctx.lineTo(px,py)}}
  }
  ctx.stroke()

  // G 点
  const gsx=ox+SM2_G2.x*scale,gsy=oy-SM2_G2.y*scale
  ctx.fillStyle='#22c55e';ctx.beginPath();ctx.arc(gsx,gsy,7,0,Math.PI*2);ctx.fill()
  ctx.fillStyle='#fff';ctx.font='bold 13px "Consolas"';ctx.fillText('G',gsx+12,gsy-6)

  // kG 路径
  let P=null;const path=[]
  for(let i=1;i<=sm2K.value;i++){P=ecAdd(P,SM2_G2,SM2_A2);if(!P)break;path.push({...P})}
  if(path.length>=2){
    const prev=path[path.length-2]
    ctx.strokeStyle='#fbbf2499';ctx.lineWidth=1.5;ctx.setLineDash([5,5])
    ctx.beginPath();ctx.moveTo(ox+prev.x*scale,oy-prev.y*scale);ctx.lineTo(gsx,gsy);ctx.stroke()
    ctx.setLineDash([])
  }
  for(let i=0;i<path.length;i++){
    const p=path[i],sx=ox+p.x*scale,sy=oy-p.y*scale
    ctx.fillStyle=i===path.length-1?'#fbbf24':'#fbbf2444'
    ctx.beginPath();ctx.arc(sx,sy,i===path.length-1?6:2.5,0,Math.PI*2);ctx.fill()
  }
  if(path.length>0){
    const last=path[path.length-1]
    ctx.fillStyle='#fbbf24';ctx.font='bold 13px "Consolas"'
    ctx.fillText(sm2K.value+'G',ox+last.x*scale+12,oy-last.y*scale-6)
  }
  // 十字线跟鼠标
  const mx=sm2Mouse.value.x,my=sm2Mouse.value.y
  ctx.strokeStyle='#ffffff22';ctx.lineWidth=0.8;ctx.setLineDash([3,3])
  ctx.beginPath();ctx.moveTo(ox+mx*scale,10);ctx.lineTo(ox+mx*scale,H-10);ctx.stroke()
  ctx.beginPath();ctx.moveTo(10,oy-my*scale);ctx.lineTo(W-10,oy-my*scale);ctx.stroke()
  ctx.setLineDash([])

  ctx.fillStyle='#8b9fc0';ctx.font='12px "Microsoft YaHei"'
  ctx.fillText(`k=${sm2K.value} → kG → r=(e+x₁)mod n → 签名(r,s)  |  缩放:${Math.round(scale)}%`,20,H-10)
}

// SM2 交互
onMounted(()=>{sm4Init();sm3Init();sm2Draw();setTimeout(()=>{
  const c=sm2Canvas.value;if(!c)return
  c.onwheel=e=>{e.preventDefault();const r=c.getBoundingClientRect();const sx=c.width/r.width,sy=c.height/r.height;const px=(e.clientX-r.left)*sx,py=(e.clientY-r.top)*sy;const f=Math.exp(-e.deltaY*0.004);sm2Ox.value+=((px-sm2Ox.value)*(1-f)+(py-sm2Oy.value)*0);sm2Oy.value+=((py-sm2Oy.value)*(1-f));sm2Scale.value=Math.max(5,Math.min(500,sm2Scale.value*f));sm2Draw()}
  c.onmousedown=e=>{if(e.button!==0)return;e.preventDefault();sm2Dragging=true;const r=c.getBoundingClientRect();const sx=c.width/r.width,sy=c.height/r.height;sm2LastX=(e.clientX-r.left)*sx;sm2LastY=(e.clientY-r.top)*sy;c.style.cursor='grabbing'}
  c.onmousemove=e=>{const r=c.getBoundingClientRect();const sx=c.width/r.width,sy=c.height/r.height;const px=(e.clientX-r.left)*sx,py=(e.clientY-r.top)*sy;const ox=c.width/2+sm2Ox.value,oy=c.height/2+sm2Oy.value,sc=sm2Scale.value;sm2Mouse.value={x:(px-ox)/sc,y:(oy-py)/sc};if(sm2Dragging){sm2Ox.value+=px-sm2LastX;sm2Oy.value+=py-sm2LastY;sm2LastX=px;sm2LastY=py;sm2Draw()}}
  c.onmouseup=()=>{sm2Dragging=false;c.style.cursor=''}
  c.onmouseleave=()=>{sm2Dragging=false;c.style.cursor=''}
},300)})
onUnmounted(()=>{clearInterval(sm4Timer);clearInterval(sm3Timer);clearInterval(sm2Timer)})
</script>

#!/usr/bin/env python3
import hashlib, hmac, socket, struct, sys, time
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

RESP_PRIV=bytes.fromhex('20'*32)
PSK=bytes(32)
CONSTRUCTION=b'Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s'
IDENT=b'WireGuard v1 zx2c4 Jason@zx2c4.com'

def b2(x): return hashlib.blake2s(x,digest_size=32).digest()
def mixhash(h,d): return b2(h+d)
def hm(k,d): return hmac.new(k,d,hashlib.blake2s).digest()
def kdf1(c,x):
    t0=hm(c,x); return hm(t0,b'\x01')
def kdf2(c,x):
    t0=hm(c,x); t1=hm(t0,b'\x01'); t2=hm(t0,t1+b'\x02'); return t1,t2
def kdf3(c,x):
    t0=hm(c,x); t1=hm(t0,b'\x01'); t2=hm(t0,t1+b'\x02'); t3=hm(t0,t2+b'\x03'); return t1,t2,t3

def main():
    port=int(sys.argv[1]) if len(sys.argv)>1 else 45887
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',port));s.settimeout(10)
    data,addr=s.recvfrom(4096)
    assert len(data)==148 and struct.unpack_from('<I',data,0)[0]==1
    init_idx=struct.unpack_from('<I',data,4)[0]; ei=data[8:40]
    resp_priv=X25519PrivateKey.from_private_bytes(RESP_PRIV); resp_pub=resp_priv.public_key().public_bytes_raw()
    chain=b2(CONSTRUCTION); h=mixhash(chain,IDENT); h=mixhash(h,resp_pub); chain=kdf1(chain,ei);h=mixhash(h,ei)
    es=resp_priv.exchange(X25519PublicKey.from_public_bytes(ei));chain,key=kdf2(chain,es)
    init_pub=ChaCha20Poly1305(key).decrypt(bytes(12),data[40:88],h);h=mixhash(h,data[40:88])
    ss=resp_priv.exchange(X25519PublicKey.from_public_bytes(init_pub));chain,key=kdf2(chain,ss)
    _ts=ChaCha20Poly1305(key).decrypt(bytes(12),data[88:116],h);h=mixhash(h,data[88:116])
    # independent MAC1 check
    mac1key=b2(b'mac1----'+resp_pub); assert hashlib.blake2s(data[:116],key=mac1key,digest_size=16).digest()==data[116:132]

    er_priv=X25519PrivateKey.from_private_bytes(bytes.fromhex('30'*32));er=er_priv.public_key().public_bytes_raw()
    chain=kdf1(chain,er);h=mixhash(h,er)
    chain=kdf1(chain,er_priv.exchange(X25519PublicKey.from_public_bytes(ei)))
    chain=kdf1(chain,er_priv.exchange(X25519PublicKey.from_public_bytes(init_pub)))
    chain,tau,key=kdf3(chain,PSK);h=mixhash(h,tau)
    empty=ChaCha20Poly1305(key).encrypt(bytes(12),b'',h);h=mixhash(h,empty)
    resp_idx=0x12345678
    out=bytearray(92);struct.pack_into('<III',out,0,2,resp_idx,init_idx);out[12:44]=er;out[44:60]=empty
    rmac=b2(b'mac1----'+init_pub);out[60:76]=hashlib.blake2s(out[:60],key=rmac,digest_size=16).digest()
    s.sendto(out,addr)
    recv_key,send_key=kdf2(chain,b'')
    tr,addr=s.recvfrom(65535);assert struct.unpack_from('<I',tr,0)[0]==4 and struct.unpack_from('<I',tr,4)[0]==resp_idx
    ctr=struct.unpack_from('<Q',tr,8)[0];nonce=bytes(4)+struct.pack('<Q',ctr);plain=ChaCha20Poly1305(recv_key).decrypt(nonce,tr[16:],b'')
    # echo it back as a valid responder transport message
    nonce2=bytes(12);sealed=ChaCha20Poly1305(send_key).encrypt(nonce2,plain,b'');reply=struct.pack('<IIQ',4,init_idx,0)+sealed;s.sendto(reply,addr)
    print('PY_WIREGUARD_INTEROP_OK',flush=True)

if __name__=='__main__': main()

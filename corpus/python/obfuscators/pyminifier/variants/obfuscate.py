nK=int
nE=str
na=float
nU=ValueError
nC=OverflowError
nF=object
nI=TypeError
nA=KeyError
nu=IndexError
nD=Exception
nX=None
nH=RuntimeError
nd=bool
nO=True
nL=False
ne=enumerate
nS=sum
nM=max
nP=sorted
nJ=list
nY=filter
nj=range
nq=property
nG=classmethod
ni=staticmethod
nb=ImportError
nw=len
nN=isinstance
ng=bytes
np=hasattr
nh=print
import asyncio
nW=asyncio.get_event_loop
ns=asyncio.run
import contextlib
nV=contextlib.contextmanager
nf=contextlib.suppress
import functools
ny=functools.lru_cache
nz=functools.wraps
import json
import secrets
nR=secrets.token_hex
from typing import(Any,Awaitable,Callable,ClassVar,Dict,Generic,Iterator,List,NamedTuple,Optional,Sequence,Set,Tuple,TypeVar,)
__PY_BAND__:k[nK,nK]=(3,6)
T=TypeVar("T")
R=TypeVar("R")
n:nK=3
v:na=0.5
T:nK=1_000_000
def kQ(j:nE,count:nK,ratio:na)->nE:
 Q:nE=f"{name!r}: {count:04d} @ {ratio:.2%}"
 r:nE=f"name-len={len(name)}"
 return f"{head} | {tail}"
def kr(parts:y[nE])->nE:
 o:nE=f"count={len(parts)}"
 x:nE=", ".join(parts)
 return o+" | "+f"items=[{joined}]"
def ko()->nK:
 s:nK=1_000_000_000
 W:nK=0xFF_FF_FF
 f:nK=0b1010_1010
 return s+W+f
def kx(kw:nE)->nK:
 try:
  return nK(kw)
 except nU as exc:
  return-1
def ks(G:Sequence[nK])->nK:
 V:nK=0
 try:
  for it in G:
   V+=it
 except nC:
  V=-1
 else:
  V+=100
 finally:
  V=V
 return V
def kW(d:nF)->nE:
 try:
  return nE(nK(d))
 except nU:
  return "not-a-number"
 except nI:
  return "wrong-type"
 except(nA,nu):
  return "lookup-failed"
 except nD:
  return "unknown"
def kf(cause:nD)->nX:
 raise nH("wrapped failure")from cause
def kV(lock:L)->nK:
 with lock:
  return 1
def kz(store:a[nE,nK])->nX:
 with nf(nA,nU):
  del store["maybe-missing"]
def ky(G:y[nK],target:nK)->nd:
 for it in G:
  if it==target:
   return nO
 else:
  return nL
def kR(n:nK)->nK:
 i:nK=0
 while i<n:
  if i==5:
   break
  i+=1
 else:
  return-1
 return i
def kK(pairs:y[k[nK,nK]])->nK:
 V:nK=0
 for a,b in pairs:
  V+=a*b
 return V
def kE(flag:nd,a:nK,b:nK)->nK:
 return a if flag else b
def ka(a:nK,b:nK,c:nK)->nd:
 return 0<=a<b<=c<100
def kU(matrix:y[y[nK]])->a[nE,L]:
 z:y[nK]=[cell for row in matrix for cell in row if cell>0]
 R:K[nK]={cell for row in matrix for cell in row}
 E:a[nK,y[nK]]={i:row for i,row in ne(matrix)if row}
 U:nK=nS(cell*2 for row in matrix for cell in row)
 return{"flat":z,"uniq":R,"index":E,"gen_sum":U}
def kC(o:y[nK],suffix:y[nK])->y[nK]:
 return[*o,0,*suffix]
def kF(args:y[nK])->nK:
 return nS([*args,1])+nM(args)
def kI(e:y[nK])->k[nK,y[nK],nK]:
 C,*F,I=e
 return C,F,I
def kA(a:a[nE,nK],b:a[nE,nK])->a[nE,nK]:
 return{**a,**b,"extra":1}
def ku(G:y[k[nE,nK]])->y[k[nE,nK]]:
 A:y[k[nE,nK]]=nP(G,key=lambda kv:(kv[1],kv[0]))
 return nJ(nY(lambda kv:kv[1]>0,A))
def kD(o:nE)->N[[N[...,R]],N[...,R]]:
 def kX(fn:N[...,R])->N[...,R]:
  @nz(fn)
  def kH(*args:L,**kwargs:L)->R:
   return fn(*args,**kwargs)
  return kH
 return kX
@kD("trace")
def kd(x:nK,y:nK=10)->nK:
 return x+y
@ny(maxsize=128)
def kO(n:nK)->nK:
 return n*n if n<2 else kO(n-1)+kO(n-2)
def kL()->N[[nK],nK]:
 D:nK=0
 def ke(X:nK)->nK:
  nonlocal D
  D+=X
  return D
 return ke
H:nK=0
def kS()->nK:
 global H
 H+=1
 return H
def kM(limit:nK)->Iterator[nK]:
 for i in nj(limit):
  if i%3==0:
   yield i
def kP()->nE:
 return nR(8)
async def kJ(client:L)->nE:
 d:ng=await client.authenticate()
 O:L=await client.open(d)
 e:ng=await O.kc()
 return e.decode()
async def kY(source:L)->L:
 async for S in source:
  if S%2==0:
   yield S*10
async def kj(source:L)->y[nK]:
 return[S async for S in source if S>0]
class g(NamedTuple):
 x:nK
 y:nK=0
class p(Generic[T]):
 def __init__(M,S:T)->nX:
  M.item:T=S
 def kq(M)->T:
  return M.item
class h:
 P:J[nK]=3
 Y:J[na]=30.0
 j:J[nE]="default"
class t:
 def __init__(M,r:nK,g:nK,b:nK)->nX:
  M.r:nK=r
  M.g:nK=g
  M.b:nK=b
 @nq
 def kG(M)->na:
  return(M.r+M.g+M.b)/3.0
 @nG
 def ki(cls)->"Color":
  return cls(0,0,0)
 @ni
 def kb(a:"Color",b:"Color")->"Color":
  return t((a.r+b.r)//2,(a.g+b.g)//2,(a.b+b.b)//2)
 def __repr__(M)->nE:
  return f"Color({self.r}, {self.g}, {self.b})"
class kv:
 def __init__(M)->nX:
  M._value:nK=0
 @nq
 def kw(M)->nK:
  return M._value
 @kw.setter
 def kw(M,q:nK)->nX:
  M._value=nM(0,q)
def kN()->L:
 try:
  import orjson as serializer
 except nb:
  import json as serializer
 return serializer
def kg(action:nE,payload:a[nE,L])->a[nE,L]:
 if action=="list":
  try:
   G:y[nE]=[nE(x).strip()for x in payload.get("items",[])if x]
  except nI:
   return{"ok":nL,"error":"not-iterable"}
  return{"ok":nO,"count":nw(G),"items":G}
 if action=="batch":
  V:nK=nS(v for v in payload.values()if nN(v,nK))
  return{"ok":nO,"total":V}
 return{"ok":nL,"error":"unknown"}
def kp()->nX:
 assert kQ("alpha",7,0.5)=="'alpha': 0007 @ 50.00% | name-len=5"
 assert "items=" in kr(["a","b"])
 assert ko()>0
 assert kx("123")==123
 assert kx("nope")==-1
 assert ks([1,2,3])==106
 assert kW("xyz")=="not-a-number"
 @nV
 def kh()->Iterator[nX]:
  yield nX
 assert kV(kh())==1
 kz({"present":1})
 assert ky([1,2,3],2)is nO
 assert ky([1,2,3],99)is nL
 assert kR(10)==5
 assert kK([(1,2),(3,4)])==14
 assert kE(nO,1,2)==1
 assert ka(1,2,50)is nO
 i:a[nE,L]=kU([[1,2],[3,-1,4]])
 assert nw(i["flat"])==4
 assert kC([1,2],[3,4])==[1,2,0,3,4]
 assert kF([1,2,3])==(1+2+3+1)+3
 C,b,I=kI([1,2,3,4,5])
 assert C==1 and b==[2,3,4]and I==5
 assert kA({"a":1},{"b":2})=={"a":1,"b":2,"extra":1}
 assert ku([("a",2),("b",-1),("c",3)])==[("a",2),("c",3)]
 assert kd(1,2)==3
 assert kO(5)>0
 w:N[[nK],nK]=kL()
 assert w(1)==1 and w(2)==3
 assert kS()>=1
 assert nJ(kM(10))==[0,3,6,9]
 assert nw(kP())==16
 p:g=g(1)
 assert p.x==1 and p.y==0
 c:p[nK]=p(42)
 assert c.kq()==42
 assert h.retries==3
 async def km()->nX:
  class nx:
   async def kB(M)->ng:
    return b"tok"
   async def kl(M,_t:ng)->L:
    return M
   async def kc(M)->ng:
    return b"payload"
  m:nE=await kJ(nx())
  assert m=="payload"
  async def kt()->L:
   for v in[0,1,2,3]:
    yield v
  B=kY(kt())
  l:y[nK]=[]
  async for v in B:
   l.append(v)
  assert l==[0,20]
  async def nk()->L:
   for v in[-1,0,1,2]:
    yield v
  c:y[nK]=await kj(nk())
  assert c==[1,2]
 if np(asyncio,"run"):
  ns(km())
 else:
  nW().run_until_complete(km())
 assert t(10,20,30).brightness==20.0
 kn:kv=kv()
 kn.kw=-5
 assert kn.kw==0
 kn.kw=100
 assert kn.kw==100
 assert kN()is not nX
 kT:a[nE,L]=kg("list",{"items":["a","b",""]})
 assert kT["ok"]is nO and kT["count"]==2
 nh("edge_cases_3_6: exercise ok")
if __name__=="__main__":
 kp()
# Created by pyminifier (https://github.com/liftoff/pyminifier)

VC=int
Vl=str
VU=float
VD=ValueError
Vv=OverflowError
VI=object
VA=TypeError
Vp=KeyError
Vq=IndexError
Vo=Exception
VG=None
VF=RuntimeError
Vj=bool
Va=True
VW=False
VO=enumerate
VQ=sum
VJ=max
Vw=sorted
Vi=list
VB=filter
VT=range
Vd=property
VR=classmethod
Vg=staticmethod
VP=ImportError
Vn=len
Vz=isinstance
Vy=bytes
Vk=hasattr
VX=print
import asyncio
Vr=asyncio.get_event_loop
Vu=asyncio.run
import contextlib
Ve=contextlib.contextmanager
VS=contextlib.suppress
import functools
VM=functools.lru_cache
VY=functools.wraps
import json
import secrets
Vf=secrets.token_hex
from typing import(Any,Awaitable,Callable,ClassVar,Dict,Generic,Iterator,List,NamedTuple,Optional,Sequence,Set,Tuple,TypeVar,)
__PY_BAND__:N[VC,VC]=(3,6)
T=TypeVar("T")
R=TypeVar("R")
V:VC=3
t:VU=0.5
b:VC=1_000_000
def NL(T:Vl,count:VC,ratio:VU)->Vl:
 L:Vl=f"{name!r}: {count:04d} @ {ratio:.2%}"
 m:Vl=f"name-len={len(name)}"
 return f"{head} | {tail}"
def Nm(parts:M[Vl])->Vl:
 h:Vl=f"count={len(parts)}"
 c:Vl=", ".join(parts)
 return h+" | "+f"items=[{joined}]"
def Nh()->VC:
 u:VC=1_000_000_000
 r:VC=0xFF_FF_FF
 S:VC=0b1010_1010
 return u+r+S
def Nc(Nn:Vl)->VC:
 try:
  return VC(Nn)
 except VD as exc:
  return-1
def Nu(R:Sequence[VC])->VC:
 e:VC=0
 try:
  for it in R:
   e+=it
 except Vv:
  e=-1
 else:
  e+=100
 finally:
  e=e
 return e
def Nr(j:VI)->Vl:
 try:
  return Vl(VC(j))
 except VD:
  return "not-a-number"
 except VA:
  return "wrong-type"
 except(Vp,Vq):
  return "lookup-failed"
 except Vo:
  return "unknown"
def NS(cause:Vo)->VG:
 raise VF("wrapped failure")from cause
def Ne(lock:W)->VC:
 with lock:
  return 1
def NY(store:U[Vl,VC])->VG:
 with VS(Vp,VD):
  del store["maybe-missing"]
def NM(R:M[VC],target:VC)->Vj:
 for it in R:
  if it==target:
   return Va
 else:
  return VW
def Nf(n:VC)->VC:
 i:VC=0
 while i<n:
  if i==5:
   break
  i+=1
 else:
  return-1
 return i
def NC(pairs:M[N[VC,VC]])->VC:
 e:VC=0
 for a,b in pairs:
  e+=a*b
 return e
def Nl(flag:Vj,a:VC,b:VC)->VC:
 return a if flag else b
def NU(a:VC,b:VC,c:VC)->Vj:
 return 0<=a<b<=c<100
def ND(matrix:M[M[VC]])->U[Vl,W]:
 Y:M[VC]=[cell for row in matrix for cell in row if cell>0]
 f:C[VC]={cell for row in matrix for cell in row}
 l:U[VC,M[VC]]={i:row for i,row in VO(matrix)if row}
 D:VC=VQ(cell*2 for row in matrix for cell in row)
 return{"flat":Y,"uniq":f,"index":l,"gen_sum":D}
def Nv(h:M[VC],suffix:M[VC])->M[VC]:
 return[*h,0,*suffix]
def NI(args:M[VC])->VC:
 return VQ([*args,1])+VJ(args)
def NA(O:M[VC])->N[VC,M[VC],VC]:
 v,*I,A=O
 return v,I,A
def Np(a:U[Vl,VC],b:U[Vl,VC])->U[Vl,VC]:
 return{**a,**b,"extra":1}
def Nq(R:M[N[Vl,VC]])->M[N[Vl,VC]]:
 p:M[N[Vl,VC]]=Vw(R,key=lambda kv:(kv[1],kv[0]))
 return Vi(VB(lambda kv:kv[1]>0,p))
def No(h:Vl)->z[[z[...,R]],z[...,R]]:
 def NG(fn:z[...,R])->z[...,R]:
  @VY(fn)
  def NF(*args:W,**kwargs:W)->R:
   return fn(*args,**kwargs)
  return NF
 return NG
@No("trace")
def Nj(x:VC,y:VC=10)->VC:
 return x+y
@VM(maxsize=128)
def Na(n:VC)->VC:
 return n*n if n<2 else Na(n-1)+Na(n-2)
def NW()->z[[VC],VC]:
 o:VC=0
 def NO(G:VC)->VC:
  nonlocal o
  o+=G
  return o
 return NO
F:VC=0
def NQ()->VC:
 global F
 F+=1
 return F
def NJ(limit:VC)->Iterator[VC]:
 for i in VT(limit):
  if i%3==0:
   yield i
def Nw()->Vl:
 return Vf(8)
async def Ni(client:W)->Vl:
 j:Vy=await client.authenticate()
 a:W=await client.open(j)
 O:Vy=await a.NK()
 return O.decode()
async def NB(source:W)->W:
 async for Q in source:
  if Q%2==0:
   yield Q*10
async def NT(source:W)->M[VC]:
 return[Q async for Q in source if Q>0]
class y(NamedTuple):
 x:VC
 y:VC=0
class k(Generic[T]):
 def __init__(J,Q:T)->VG:
  J.item:T=Q
 def Nd(J)->T:
  return J.item
class X:
 w:i[VC]=3
 B:i[VU]=30.0
 T:i[Vl]="default"
class H:
 def __init__(J,r:VC,g:VC,b:VC)->VG:
  J.r:VC=r
  J.g:VC=g
  J.b:VC=b
 @Vd
 def NR(J)->VU:
  return(J.r+J.g+J.b)/3.0
 @VR
 def Ng(cls)->"Color":
  return cls(0,0,0)
 @Vg
 def NP(a:"Color",b:"Color")->"Color":
  return H((a.r+b.r)//2,(a.g+b.g)//2,(a.b+b.b)//2)
 def __repr__(J)->Vl:
  return f"Color({self.r}, {self.g}, {self.b})"
class Nt:
 def __init__(J)->VG:
  J._value:VC=0
 @Vd
 def Nn(J)->VC:
  return J._value
 @Nn.setter
 def Nn(J,d:VC)->VG:
  J._value=VJ(0,d)
def Nz()->W:
 try:
  import orjson as serializer
 except VP:
  import json as serializer
 return serializer
def Ny(action:Vl,payload:U[Vl,W])->U[Vl,W]:
 if action=="list":
  try:
   R:M[Vl]=[Vl(x).strip()for x in payload.get("items",[])if x]
  except VA:
   return{"ok":VW,"error":"not-iterable"}
  return{"ok":Va,"count":Vn(R),"items":R}
 if action=="batch":
  e:VC=VQ(v for v in payload.values()if Vz(v,VC))
  return{"ok":Va,"total":e}
 return{"ok":VW,"error":"unknown"}
def Nk()->VG:
 assert NL("alpha",7,0.5)=="'alpha': 0007 @ 50.00% | name-len=5"
 assert "items=" in Nm(["a","b"])
 assert Nh()>0
 assert Nc("123")==123
 assert Nc("nope")==-1
 assert Nu([1,2,3])==106
 assert Nr("xyz")=="not-a-number"
 @Ve
 def NX()->Iterator[VG]:
  yield VG
 assert Ne(NX())==1
 NY({"present":1})
 assert NM([1,2,3],2)is Va
 assert NM([1,2,3],99)is VW
 assert Nf(10)==5
 assert NC([(1,2),(3,4)])==14
 assert Nl(Va,1,2)==1
 assert NU(1,2,50)is Va
 g:U[Vl,W]=ND([[1,2],[3,-1,4]])
 assert Vn(g["flat"])==4
 assert Nv([1,2],[3,4])==[1,2,0,3,4]
 assert NI([1,2,3])==(1+2+3+1)+3
 v,P,A=NA([1,2,3,4,5])
 assert v==1 and P==[2,3,4]and A==5
 assert Np({"a":1},{"b":2})=={"a":1,"b":2,"extra":1}
 assert Nq([("a",2),("b",-1),("c",3)])==[("a",2),("c",3)]
 assert Nj(1,2)==3
 assert Na(5)>0
 n:z[[VC],VC]=NW()
 assert n(1)==1 and n(2)==3
 assert NQ()>=1
 assert Vi(NJ(10))==[0,3,6,9]
 assert Vn(Nw())==16
 p:y=y(1)
 assert p.x==1 and p.y==0
 c:k[VC]=k(42)
 assert c.Nd()==42
 assert X.retries==3
 async def NE()->VG:
  class Vc:
   async def Ns(J)->Vy:
    return b"tok"
   async def Nx(J,_t:Vy)->W:
    return J
   async def NK(J)->Vy:
    return b"payload"
  E:Vl=await Ni(Vc())
  assert E=="payload"
  async def NH()->W:
   for v in[0,1,2,3]:
    yield v
  s=NB(NH())
  x:M[VC]=[]
  async for v in s:
   x.append(v)
  assert x==[0,20]
  async def VN()->W:
   for v in[-1,0,1,2]:
    yield v
  K:M[VC]=await NT(VN())
  assert K==[1,2]
 if Vk(asyncio,"run"):
  Vu(NE())
 else:
  Vr().run_until_complete(NE())
 assert H(10,20,30).brightness==20.0
 NV:Nt=Nt()
 NV.Nn=-5
 assert NV.Nn==0
 NV.Nn=100
 assert NV.Nn==100
 assert Nz()is not VG
 Nb:U[Vl,W]=Ny("list",{"items":["a","b",""]})
 assert Nb["ok"]is Va and Nb["count"]==2
 VX("edge_cases_3_6: exercise ok")
if __name__=="__main__":
 Nk()
# Created by pyminifier (https://github.com/liftoff/pyminifier)

SG=int
SL=str
SI=float
SP=ValueError
SB=OverflowError
SE=object
Sm=TypeError
Si=KeyError
SC=IndexError
SD=Exception
Su=None
Sx=RuntimeError
SV=bool
SN=True
Sf=False
SR=enumerate
Sd=sum
SY=max
SA=sorted
Ss=list
Sg=filter
Sh=range
Sz=property
SH=classmethod
SF=staticmethod
Sw=ImportError
SU=len
SO=isinstance
Sp=bytes
St=hasattr
SQ=print
import asyncio
Sl=asyncio.get_event_loop
Sb=asyncio.run
import contextlib
SX=contextlib.contextmanager
SM=contextlib.suppress
import functools
Sa=functools.lru_cache
Sy=functools.wraps
import json
import secrets
So=secrets.token_hex
from typing import(Any,Awaitable,Callable,ClassVar,Dict,Generic,Iterator,List,NamedTuple,Optional,Sequence,Set,Tuple,TypeVar,)
__PY_BAND__:k[SG,SG]=(3,6)
T=TypeVar("T")
R=TypeVar("R")
S:SG=3
J:SI=0.5
K:SG=1_000_000
def kW(h:SL,count:SG,ratio:SI)->SL:
 W:SL=f"{name!r}: {count:04d} @ {ratio:.2%}"
 r:SL=f"name-len={len(name)}"
 return f"{head} | {tail}"
def kr(parts:a[SL])->SL:
 c:SL=f"count={len(parts)}"
 v:SL=", ".join(parts)
 return c+" | "+f"items=[{joined}]"
def kc()->SG:
 b:SG=1_000_000_000
 l:SG=0xFF_FF_FF
 M:SG=0b1010_1010
 return b+l+M
def kv(kU:SL)->SG:
 try:
  return SG(kU)
 except SP as exc:
  return-1
def kb(H:Sequence[SG])->SG:
 X:SG=0
 try:
  for it in H:
   X+=it
 except SB:
  X=-1
 else:
  X+=100
 finally:
  X=X
 return X
def kl(V:SE)->SL:
 try:
  return SL(SG(V))
 except SP:
  return "not-a-number"
 except Sm:
  return "wrong-type"
 except(Si,SC):
  return "lookup-failed"
 except SD:
  return "unknown"
def kM(cause:SD)->Su:
 raise Sx("wrapped failure")from cause
def kX(lock:f)->SG:
 with lock:
  return 1
def ky(store:I[SL,SG])->Su:
 with SM(Si,SP):
  del store["maybe-missing"]
def ka(H:a[SG],target:SG)->SV:
 for it in H:
  if it==target:
   return SN
 else:
  return Sf
def ko(n:SG)->SG:
 i:SG=0
 while i<n:
  if i==5:
   break
  i+=1
 else:
  return-1
 return i
def kG(pairs:a[k[SG,SG]])->SG:
 X:SG=0
 for a,b in pairs:
  X+=a*b
 return X
def kL(flag:SV,a:SG,b:SG)->SG:
 return a if flag else b
def kI(a:SG,b:SG,c:SG)->SV:
 return 0<=a<b<=c<100
def kP(matrix:a[a[SG]])->I[SL,f]:
 y:a[SG]=[cell for row in matrix for cell in row if cell>0]
 o:G[SG]={cell for row in matrix for cell in row}
 L:I[SG,a[SG]]={i:row for i,row in SR(matrix)if row}
 P:SG=Sd(cell*2 for row in matrix for cell in row)
 return{"flat":y,"uniq":o,"index":L,"gen_sum":P}
def kB(c:a[SG],suffix:a[SG])->a[SG]:
 return[*c,0,*suffix]
def kE(args:a[SG])->SG:
 return Sd([*args,1])+SY(args)
def km(R:a[SG])->k[SG,a[SG],SG]:
 B,*E,m=R
 return B,E,m
def ki(a:I[SL,SG],b:I[SL,SG])->I[SL,SG]:
 return{**a,**b,"extra":1}
def kC(H:a[k[SL,SG]])->a[k[SL,SG]]:
 i:a[k[SL,SG]]=SA(H,key=lambda kv:(kv[1],kv[0]))
 return Ss(Sg(lambda kv:kv[1]>0,i))
def kD(c:SL)->O[[O[...,R]],O[...,R]]:
 def ku(fn:O[...,R])->O[...,R]:
  @Sy(fn)
  def kx(*args:f,**kwargs:f)->R:
   return fn(*args,**kwargs)
  return kx
 return ku
@kD("trace")
def kV(x:SG,y:SG=10)->SG:
 return x+y
@Sa(maxsize=128)
def kN(n:SG)->SG:
 return n*n if n<2 else kN(n-1)+kN(n-2)
def kf()->O[[SG],SG]:
 D:SG=0
 def kR(u:SG)->SG:
  nonlocal D
  D+=u
  return D
 return kR
x:SG=0
def kd()->SG:
 global x
 x+=1
 return x
def kY(limit:SG)->Iterator[SG]:
 for i in Sh(limit):
  if i%3==0:
   yield i
def kA()->SL:
 return So(8)
async def ks(client:f)->SL:
 V:Sp=await client.authenticate()
 N:f=await client.open(V)
 R:Sp=await N.kn()
 return R.decode()
async def kg(source:f)->f:
 async for d in source:
  if d%2==0:
   yield d*10
async def kh(source:f)->a[SG]:
 return[d async for d in source if d>0]
class p(NamedTuple):
 x:SG
 y:SG=0
class t(Generic[T]):
 def __init__(Y,d:T)->Su:
  Y.item:T=d
 def kz(Y)->T:
  return Y.item
class Q:
 A:s[SG]=3
 g:s[SI]=30.0
 h:s[SL]="default"
class j:
 def __init__(Y,r:SG,g:SG,b:SG)->Su:
  Y.r:SG=r
  Y.g:SG=g
  Y.b:SG=b
 @Sz
 def kH(Y)->SI:
  return(Y.r+Y.g+Y.b)/3.0
 @SH
 def kF(cls)->"Color":
  return cls(0,0,0)
 @SF
 def kw(a:"Color",b:"Color")->"Color":
  return j((a.r+b.r)//2,(a.g+b.g)//2,(a.b+b.b)//2)
 def __repr__(Y)->SL:
  return f"Color({self.r}, {self.g}, {self.b})"
class kJ:
 def __init__(Y)->Su:
  Y._value:SG=0
 @Sz
 def kU(Y)->SG:
  return Y._value
 @kU.setter
 def kU(Y,z:SG)->Su:
  Y._value=SY(0,z)
def kO()->f:
 try:
  import orjson as serializer
 except Sw:
  import json as serializer
 return serializer
def kp(action:SL,payload:I[SL,f])->I[SL,f]:
 if action=="list":
  try:
   H:a[SL]=[SL(x).strip()for x in payload.get("items",[])if x]
  except Sm:
   return{"ok":Sf,"error":"not-iterable"}
  return{"ok":SN,"count":SU(H),"items":H}
 if action=="batch":
  X:SG=Sd(v for v in payload.values()if SO(v,SG))
  return{"ok":SN,"total":X}
 return{"ok":Sf,"error":"unknown"}
def kt()->Su:
 assert kW("alpha",7,0.5)=="'alpha': 0007 @ 50.00% | name-len=5"
 assert "items=" in kr(["a","b"])
 assert kc()>0
 assert kv("123")==123
 assert kv("nope")==-1
 assert kb([1,2,3])==106
 assert kl("xyz")=="not-a-number"
 @SX
 def kQ()->Iterator[Su]:
  yield Su
 assert kX(kQ())==1
 ky({"present":1})
 assert ka([1,2,3],2)is SN
 assert ka([1,2,3],99)is Sf
 assert ko(10)==5
 assert kG([(1,2),(3,4)])==14
 assert kL(SN,1,2)==1
 assert kI(1,2,50)is SN
 F:I[SL,f]=kP([[1,2],[3,-1,4]])
 assert SU(F["flat"])==4
 assert kB([1,2],[3,4])==[1,2,0,3,4]
 assert kE([1,2,3])==(1+2+3+1)+3
 B,w,m=km([1,2,3,4,5])
 assert B==1 and w==[2,3,4]and m==5
 assert ki({"a":1},{"b":2})=={"a":1,"b":2,"extra":1}
 assert kC([("a",2),("b",-1),("c",3)])==[("a",2),("c",3)]
 assert kV(1,2)==3
 assert kN(5)>0
 U:O[[SG],SG]=kf()
 assert U(1)==1 and U(2)==3
 assert kd()>=1
 assert Ss(kY(10))==[0,3,6,9]
 assert SU(kA())==16
 p:p=p(1)
 assert p.x==1 and p.y==0
 c:t[SG]=t(42)
 assert c.kz()==42
 assert Q.retries==3
 async def ke()->Su:
  class Sv:
   async def kq(Y)->Sp:
    return b"tok"
   async def kT(Y,_t:Sp)->f:
    return Y
   async def kn(Y)->Sp:
    return b"payload"
  e:SL=await ks(Sv())
  assert e=="payload"
  async def kj()->f:
   for v in[0,1,2,3]:
    yield v
  q=kg(kj())
  T:a[SG]=[]
  async for v in q:
   T.append(v)
  assert T==[0,20]
  async def Sk()->f:
   for v in[-1,0,1,2]:
    yield v
  n:a[SG]=await kh(Sk())
  assert n==[1,2]
 if St(asyncio,"run"):
  Sb(ke())
 else:
  Sl().run_until_complete(ke())
 assert j(10,20,30).brightness==20.0
 kS:kJ=kJ()
 kS.kU=-5
 assert kS.kU==0
 kS.kU=100
 assert kS.kU==100
 assert kO()is not Su
 kK:I[SL,f]=kp("list",{"items":["a","b",""]})
 assert kK["ok"]is SN and kK["count"]==2
 SQ("edge_cases_3_6: exercise ok")
if __name__=="__main__":
 kt()
# Created by pyminifier (https://github.com/liftoff/pyminifier)

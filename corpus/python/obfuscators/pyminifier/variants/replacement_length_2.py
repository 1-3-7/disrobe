dI=int
dj=str
dy=float
dU=ValueError
dX=OverflowError
dH=object
dR=TypeError
dp=KeyError
di=IndexError
dv=Exception
dL=None
dm=RuntimeError
de=bool
dF=True
dC=False
ds=enumerate
dB=sum
dN=max
dQ=sorted
dl=list
dx=filter
dh=range
dG=property
da=classmethod
du=staticmethod
dK=ImportError
dO=len
dn=isinstance
dz=bytes
dM=hasattr
dq=print
import asyncio
dJ=asyncio.get_event_loop
db=asyncio.run
import contextlib
dk=contextlib.contextmanager
dS=contextlib.suppress
import functools
dg=functools.lru_cache
dE=functools.wraps
import json
import secrets
dD=secrets.token_hex
from typing import(Any,Awaitable,Callable,ClassVar,Dict,Generic,Iterator,List,NamedTuple,Optional,Sequence,Set,Tuple,TypeVar,)
__PY_BAND__:Aw[dI,dI]=(3,6)
T=TypeVar("T")
R=TypeVar("R")
Ad:dI=3
At:dy=0.5
AV:dI=1_000_000
def wP(Ah:dj,count:dI,ratio:dy)->dj:
 AP:dj=f"{name!r}: {count:04d} @ {ratio:.2%}"
 AT:dj=f"name-len={len(name)}"
 return f"{head} | {tail}"
def wT(parts:Ag[dj])->dj:
 Ar:dj=f"count={len(parts)}"
 Af:dj=", ".join(parts)
 return Ar+" | "+f"items=[{joined}]"
def wr()->dI:
 Ab:dI=1_000_000_000
 AJ:dI=0xFF_FF_FF
 AS:dI=0b1010_1010
 return Ab+AJ+AS
def wf(wO:dj)->dI:
 try:
  return dI(wO)
 except dU as exc:
  return-1
def wb(Aa:Sequence[dI])->dI:
 Ak:dI=0
 try:
  for it in Aa:
   Ak+=it
 except dX:
  Ak=-1
 else:
  Ak+=100
 finally:
  Ak=Ak
 return Ak
def wJ(Ae:dH)->dj:
 try:
  return dj(dI(Ae))
 except dU:
  return "not-a-number"
 except dR:
  return "wrong-type"
 except(dp,di):
  return "lookup-failed"
 except dv:
  return "unknown"
def wS(cause:dv)->dL:
 raise dm("wrapped failure")from cause
def wk(lock:AC)->dI:
 with lock:
  return 1
def wE(store:Ay[dj,dI])->dL:
 with dS(dp,dU):
  del store["maybe-missing"]
def wg(Aa:Ag[dI],target:dI)->de:
 for it in Aa:
  if it==target:
   return dF
 else:
  return dC
def wD(n:dI)->dI:
 i:dI=0
 while i<n:
  if i==5:
   break
  i+=1
 else:
  return-1
 return i
def wI(pairs:Ag[Aw[dI,dI]])->dI:
 Ak:dI=0
 for a,b in pairs:
  Ak+=a*b
 return Ak
def wj(flag:de,a:dI,b:dI)->dI:
 return a if flag else b
def wy(a:dI,b:dI,c:dI)->de:
 return 0<=a<b<=c<100
def wU(matrix:Ag[Ag[dI]])->Ay[dj,AC]:
 AE:Ag[dI]=[cell for row in matrix for cell in row if cell>0]
 AD:AI[dI]={cell for row in matrix for cell in row}
 Aj:Ay[dI,Ag[dI]]={i:row for i,row in ds(matrix)if row}
 AU:dI=dB(cell*2 for row in matrix for cell in row)
 return{"flat":AE,"uniq":AD,"index":Aj,"gen_sum":AU}
def wX(Ar:Ag[dI],suffix:Ag[dI])->Ag[dI]:
 return[*Ar,0,*suffix]
def wH(args:Ag[dI])->dI:
 return dB([*args,1])+dN(args)
def wR(As:Ag[dI])->Aw[dI,Ag[dI],dI]:
 AX,*AH,AR=As
 return AX,AH,AR
def wp(a:Ay[dj,dI],b:Ay[dj,dI])->Ay[dj,dI]:
 return{**a,**b,"extra":1}
def wi(Aa:Ag[Aw[dj,dI]])->Ag[Aw[dj,dI]]:
 Ap:Ag[Aw[dj,dI]]=dQ(Aa,key=lambda kv:(kv[1],kv[0]))
 return dl(dx(lambda kv:kv[1]>0,Ap))
def wv(Ar:dj)->An[[An[...,R]],An[...,R]]:
 def wL(fn:An[...,R])->An[...,R]:
  @dE(fn)
  def wm(*args:AC,**kwargs:AC)->R:
   return fn(*args,**kwargs)
  return wm
 return wL
@wv("trace")
def we(x:dI,y:dI=10)->dI:
 return x+y
@dg(maxsize=128)
def wF(n:dI)->dI:
 return n*n if n<2 else wF(n-1)+wF(n-2)
def wC()->An[[dI],dI]:
 Av:dI=0
 def ws(AL:dI)->dI:
  nonlocal Av
  Av+=AL
  return Av
 return ws
Am:dI=0
def wB()->dI:
 global Am
 Am+=1
 return Am
def wN(limit:dI)->Iterator[dI]:
 for i in dh(limit):
  if i%3==0:
   yield i
def wQ()->dj:
 return dD(8)
async def wl(client:AC)->dj:
 Ae:dz=await client.authenticate()
 AF:AC=await client.open(Ae)
 As:dz=await AF.wc()
 return As.decode()
async def wx(source:AC)->AC:
 async for AB in source:
  if AB%2==0:
   yield AB*10
async def wh(source:AC)->Ag[dI]:
 return[AB async for AB in source if AB>0]
class Az(NamedTuple):
 x:dI
 y:dI=0
class AM(Generic[T]):
 def __init__(AN,AB:T)->dL:
  AN.item:T=AB
 def wG(AN)->T:
  return AN.item
class Aq:
 AQ:Al[dI]=3
 Ax:Al[dy]=30.0
 Ah:Al[dj]="default"
class wA:
 def __init__(AN,r:dI,g:dI,b:dI)->dL:
  AN.r:dI=r
  AN.g:dI=g
  AN.b:dI=b
 @dG
 def wa(AN)->dy:
  return(AN.r+AN.g+AN.b)/3.0
 @da
 def wu(cls)->"Color":
  return cls(0,0,0)
 @du
 def wK(a:"Color",b:"Color")->"Color":
  return wA((a.r+b.r)//2,(a.g+b.g)//2,(a.b+b.b)//2)
 def __repr__(AN)->dj:
  return f"Color({self.r}, {self.g}, {self.b})"
class wt:
 def __init__(AN)->dL:
  AN._value:dI=0
 @dG
 def wO(AN)->dI:
  return AN._value
 @wO.setter
 def wO(AN,AG:dI)->dL:
  AN._value=dN(0,AG)
def wn()->AC:
 try:
  import orjson as serializer
 except dK:
  import json as serializer
 return serializer
def wz(action:dj,payload:Ay[dj,AC])->Ay[dj,AC]:
 if action=="list":
  try:
   Aa:Ag[dj]=[dj(x).strip()for x in payload.get("items",[])if x]
  except dR:
   return{"ok":dC,"error":"not-iterable"}
  return{"ok":dF,"count":dO(Aa),"items":Aa}
 if action=="batch":
  Ak:dI=dB(v for v in payload.values()if dn(v,dI))
  return{"ok":dF,"total":Ak}
 return{"ok":dC,"error":"unknown"}
def wM()->dL:
 assert wP("alpha",7,0.5)=="'alpha': 0007 @ 50.00% | name-len=5"
 assert "items=" in wT(["a","b"])
 assert wr()>0
 assert wf("123")==123
 assert wf("nope")==-1
 assert wb([1,2,3])==106
 assert wJ("xyz")=="not-a-number"
 @dk
 def wq()->Iterator[dL]:
  yield dL
 assert wk(wq())==1
 wE({"present":1})
 assert wg([1,2,3],2)is dF
 assert wg([1,2,3],99)is dC
 assert wD(10)==5
 assert wI([(1,2),(3,4)])==14
 assert wj(dF,1,2)==1
 assert wy(1,2,50)is dF
 Au:Ay[dj,AC]=wU([[1,2],[3,-1,4]])
 assert dO(Au["flat"])==4
 assert wX([1,2],[3,4])==[1,2,0,3,4]
 assert wH([1,2,3])==(1+2+3+1)+3
 AX,AK,AR=wR([1,2,3,4,5])
 assert AX==1 and AK==[2,3,4]and AR==5
 assert wp({"a":1},{"b":2})=={"a":1,"b":2,"extra":1}
 assert wi([("a",2),("b",-1),("c",3)])==[("a",2),("c",3)]
 assert we(1,2)==3
 assert wF(5)>0
 AO:An[[dI],dI]=wC()
 assert AO(1)==1 and AO(2)==3
 assert wB()>=1
 assert dl(wN(10))==[0,3,6,9]
 assert dO(wQ())==16
 p:Az=Az(1)
 assert p.x==1 and p.y==0
 c:AM[dI]=AM(42)
 assert c.get()==42
 assert Aq.retries==3
 async def wo()->dL:
  class df:
   async def wW(AN)->dz:
    return b"tok"
   async def wY(AN,_t:dz)->AC:
    return AN
   async def wc(AN)->dz:
    return b"payload"
  Ao:dj=await wl(df())
  assert Ao=="payload"
  async def dA()->AC:
   for v in[0,1,2,3]:
    yield v
  AW=wx(dA())
  AY:Ag[dI]=[]
  async for v in AW:
   AY.append(v)
  assert AY==[0,20]
  async def dw()->AC:
   for v in[-1,0,1,2]:
    yield v
  Ac:Ag[dI]=await wh(dw())
  assert Ac==[1,2]
 if dM(asyncio,"run"):
  db(wo())
 else:
  dJ().run_until_complete(wo())
 assert wA(10,20,30).brightness==20.0
 wd:wt=wt()
 wd.wO=-5
 assert wd.wO==0
 wd.wO=100
 assert wd.wO==100
 assert wn()is not dL
 wV:Ay[dj,AC]=wz("list",{"items":["a","b",""]})
 assert wV["ok"]is dF and wV["count"]==2
 dq("edge_cases_3_6: exercise ok")
if __name__=="__main__":
 wM()
# Created by pyminifier (https://github.com/liftoff/pyminifier)

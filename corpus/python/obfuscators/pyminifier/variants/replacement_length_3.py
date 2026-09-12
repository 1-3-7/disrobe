Jvo=int
Jvs=str
Jvw=float
Jvf=ValueError
Jvl=OverflowError
JvF=object
JvX=TypeError
JvU=KeyError
JvE=IndexError
Jvh=Exception
Jvt=None
JvR=RuntimeError
JvL=bool
Jvq=True
JvY=False
Jvc=enumerate
Jvx=sum
JvS=max
Jvy=sorted
Jvr=list
JvK=filter
Jvj=range
JvI=property
JvW=classmethod
Jvk=staticmethod
JvD=ImportError
JvP=len
JvM=isinstance
Jvz=bytes
Jvn=hasattr
Jvg=print
import asyncio
Jvu=asyncio.get_event_loop
Jvd=asyncio.run
import contextlib
Jva=contextlib.contextmanager
JvH=contextlib.suppress
import functools
JvG=functools.lru_cache
Jvm=functools.wraps
import json
import secrets
Jve=secrets.token_hex
from typing import(Any,Awaitable,Callable,ClassVar,Dict,Generic,Iterator,List,NamedTuple,Optional,Sequence,Set,Tuple,TypeVar,)
__PY_BAND__:JCb[Jvo,Jvo]=(3,6)
T=TypeVar("T")
R=TypeVar("R")
JCv:Jvo=3
JCV:Jvw=0.5
JCN:Jvo=1_000_000
def JbT(JCr:Jvs,count:Jvo,ratio:Jvw)->Jvs:
 JCp:Jvs=f"{name!r}: {count:04d} @ {ratio:.2%}"
 JCT:Jvs=f"name-len={len(name)}"
 return f"{head} | {tail}"
def Jbi(parts:JCa[Jvs])->Jvs:
 JCi:Jvs=f"count={len(parts)}"
 JCA:Jvs=", ".join(parts)
 return JCi+" | "+f"items=[{joined}]"
def JbA()->Jvo:
 JCB:Jvo=1_000_000_000
 JCO:Jvo=0xFF_FF_FF
 JCd:Jvo=0b1010_1010
 return JCB+JCO+JCd
def JbB(JbD:Jvs)->Jvo:
 try:
  return Jvo(JbD)
 except Jvf as exc:
  return-1
def JbO(JCj:Sequence[Jvo])->Jvo:
 JCu:Jvo=0
 try:
  for it in JCj:
   JCu+=it
 except Jvl:
  JCu=-1
 else:
  JCu+=100
 finally:
  JCu=JCu
 return JCu
def Jbd(JCt:JvF)->Jvs:
 try:
  return Jvs(Jvo(JCt))
 except Jvf:
  return "not-a-number"
 except JvX:
  return "wrong-type"
 except(JvU,JvE):
  return "lookup-failed"
 except Jvh:
  return "unknown"
def Jbu(cause:Jvh)->Jvt:
 raise JvR("wrapped failure")from cause
def JbH(lock:JCL)->Jvo:
 with lock:
  return 1
def Jba(store:JCo[Jvs,Jvo])->Jvt:
 with JvH(JvU,Jvf):
  del store["maybe-missing"]
def Jbm(JCj:JCa[Jvo],target:Jvo)->JvL:
 for it in JCj:
  if it==target:
   return Jvq
 else:
  return JvY
def JbG(n:Jvo)->Jvo:
 i:Jvo=0
 while i<n:
  if i==5:
   break
  i+=1
 else:
  return-1
 return i
def Jbe(pairs:JCa[JCb[Jvo,Jvo]])->Jvo:
 JCu:Jvo=0
 for a,b in pairs:
  JCu+=a*b
 return JCu
def Jbo(flag:JvL,a:Jvo,b:Jvo)->Jvo:
 return a if flag else b
def Jbs(a:Jvo,b:Jvo,c:Jvo)->JvL:
 return 0<=a<b<=c<100
def Jbw(matrix:JCa[JCa[Jvo]])->JCo[Jvs,JCL]:
 JCH:JCa[Jvo]=[cell for row in matrix for cell in row if cell>0]
 JCm:JCG[Jvo]={cell for row in matrix for cell in row}
 JCe:JCo[Jvo,JCa[Jvo]]={i:row for i,row in Jvc(matrix)if row}
 JCs:Jvo=Jvx(cell*2 for row in matrix for cell in row)
 return{"flat":JCH,"uniq":JCm,"index":JCe,"gen_sum":JCs}
def Jbf(JCi:JCa[Jvo],suffix:JCa[Jvo])->JCa[Jvo]:
 return[*JCi,0,*suffix]
def Jbl(args:JCa[Jvo])->Jvo:
 return Jvx([*args,1])+JvS(args)
def JbF(JCq:JCa[Jvo])->JCb[Jvo,JCa[Jvo],Jvo]:
 JCw,*JCf,JCl=JCq
 return JCw,JCf,JCl
def JbX(a:JCo[Jvs,Jvo],b:JCo[Jvs,Jvo])->JCo[Jvs,Jvo]:
 return{**a,**b,"extra":1}
def JbU(JCj:JCa[JCb[Jvs,Jvo]])->JCa[JCb[Jvs,Jvo]]:
 JCF:JCa[JCb[Jvs,Jvo]]=Jvy(JCj,key=lambda kv:(kv[1],kv[0]))
 return Jvr(JvK(lambda kv:kv[1]>0,JCF))
def JbE(JCi:Jvs)->JCD[[JCD[...,R]],JCD[...,R]]:
 def Jbh(fn:JCD[...,R])->JCD[...,R]:
  @Jvm(fn)
  def Jbt(*args:JCL,**kwargs:JCL)->R:
   return fn(*args,**kwargs)
  return Jbt
 return Jbh
@JbE("trace")
def JbR(x:Jvo,y:Jvo=10)->Jvo:
 return x+y
@JvG(maxsize=128)
def JbL(n:Jvo)->Jvo:
 return n*n if n<2 else JbL(n-1)+JbL(n-2)
def Jbq()->JCD[[Jvo],Jvo]:
 JCU:Jvo=0
 def JbY(JCE:Jvo)->Jvo:
  nonlocal JCU
  JCU+=JCE
  return JCU
 return JbY
JCh:Jvo=0
def Jbc()->Jvo:
 global JCh
 JCh+=1
 return JCh
def Jbx(limit:Jvo)->Iterator[Jvo]:
 for i in Jvj(limit):
  if i%3==0:
   yield i
def JbS()->Jvs:
 return Jve(8)
async def Jby(client:JCL)->Jvs:
 JCt:Jvz=await client.authenticate()
 JCR:JCL=await client.open(JCt)
 JCq:Jvz=await JCR.Jvb()
 return JCq.decode()
async def Jbr(source:JCL)->JCL:
 async for JCY in source:
  if JCY%2==0:
   yield JCY*10
async def JbK(source:JCL)->JCa[Jvo]:
 return[JCY async for JCY in source if JCY>0]
class JCP(NamedTuple):
 x:Jvo
 y:Jvo=0
class JCM(Generic[T]):
 def __init__(JCc,JCY:T)->Jvt:
  JCc.item:T=JCY
 def Jbj(JCc)->T:
  return JCc.item
class JCz:
 JCx:JCS[Jvo]=3
 JCy:JCS[Jvw]=30.0
 JCr:JCS[Jvs]="default"
class Jbv:
 def __init__(JCc,r:Jvo,g:Jvo,b:Jvo)->Jvt:
  JCc.r:Jvo=r
  JCc.g:Jvo=g
  JCc.b:Jvo=b
 @JvI
 def JbI(JCc)->Jvw:
  return(JCc.r+JCc.g+JCc.b)/3.0
 @JvW
 def JbW(cls)->"Color":
  return cls(0,0,0)
 @Jvk
 def Jbk(a:"Color",b:"Color")->"Color":
  return Jbv((a.r+b.r)//2,(a.g+b.g)//2,(a.b+b.b)//2)
 def __repr__(JCc)->Jvs:
  return f"Color({self.r}, {self.g}, {self.b})"
class JbN:
 def __init__(JCc)->Jvt:
  JCc._value:Jvo=0
 @JvI
 def JbD(JCc)->Jvo:
  return JCc._value
 @JbD.setter
 def JbD(JCc,JCK:Jvo)->Jvt:
  JCc._value=JvS(0,JCK)
def JbP()->JCL:
 try:
  import orjson as serializer
 except JvD:
  import json as serializer
 return serializer
def JbM(action:Jvs,payload:JCo[Jvs,JCL])->JCo[Jvs,JCL]:
 if action=="list":
  try:
   JCj:JCa[Jvs]=[Jvs(x).strip()for x in payload.get("items",[])if x]
  except JvX:
   return{"ok":JvY,"error":"not-iterable"}
  return{"ok":Jvq,"count":JvP(JCj),"items":JCj}
 if action=="batch":
  JCu:Jvo=Jvx(v for v in payload.values()if JvM(v,Jvo))
  return{"ok":Jvq,"total":JCu}
 return{"ok":JvY,"error":"unknown"}
def Jbz()->Jvt:
 assert JbT("alpha",7,0.5)=="'alpha': 0007 @ 50.00% | name-len=5"
 assert "items=" in Jbi(["a","b"])
 assert JbA()>0
 assert JbB("123")==123
 assert JbB("nope")==-1
 assert JbO([1,2,3])==106
 assert Jbd("xyz")=="not-a-number"
 @Jva
 def Jbn()->Iterator[Jvt]:
  yield Jvt
 assert JbH(Jbn())==1
 Jba({"present":1})
 assert Jbm([1,2,3],2)is Jvq
 assert Jbm([1,2,3],99)is JvY
 assert JbG(10)==5
 assert Jbe([(1,2),(3,4)])==14
 assert Jbo(Jvq,1,2)==1
 assert Jbs(1,2,50)is Jvq
 JCI:JCo[Jvs,JCL]=Jbw([[1,2],[3,-1,4]])
 assert JvP(JCI["flat"])==4
 assert Jbf([1,2],[3,4])==[1,2,0,3,4]
 assert Jbl([1,2,3])==(1+2+3+1)+3
 JCw,JCW,JCl=JbF([1,2,3,4,5])
 assert JCw==1 and JCW==[2,3,4]and JCl==5
 assert JbX({"a":1},{"b":2})=={"a":1,"b":2,"extra":1}
 assert JbU([("a",2),("b",-1),("c",3)])==[("a",2),("c",3)]
 assert JbR(1,2)==3
 assert JbL(5)>0
 JCk:JCD[[Jvo],Jvo]=Jbq()
 assert JCk(1)==1 and JCk(2)==3
 assert Jbc()>=1
 assert Jvr(Jbx(10))==[0,3,6,9]
 assert JvP(JbS())==16
 p:JCP=JCP(1)
 assert p.x==1 and p.y==0
 c:JCM[Jvo]=JCM(42)
 assert c.get()==42
 assert JCz.retries==3
 async def Jbg()->Jvt:
  class JvO:
   async def JbQ(JCc)->Jvz:
    return b"tok"
   async def JvC(JCc,_t:Jvz)->JCL:
    return JCc
   async def Jvb(JCc)->Jvz:
    return b"payload"
  JCn:Jvs=await Jby(JvO())
  assert JCn=="payload"
  async def JvV()->JCL:
   for v in[0,1,2,3]:
    yield v
  JCg=Jbr(JvV())
  JCQ:JCa[Jvo]=[]
  async for v in JCg:
   JCQ.append(v)
  assert JCQ==[0,20]
  async def JvN()->JCL:
   for v in[-1,0,1,2]:
    yield v
  JbC:JCa[Jvo]=await JbK(JvN())
  assert JbC==[1,2]
 if Jvn(asyncio,"run"):
  Jvd(Jbg())
 else:
  Jvu().run_until_complete(Jbg())
 assert Jbv(10,20,30).brightness==20.0
 JbV:JbN=JbN()
 JbV.JbD=-5
 assert JbV.JbD==0
 JbV.JbD=100
 assert JbV.JbD==100
 assert JbP()is not Jvt
 Jbp:JCo[Jvs,JCL]=JbM("list",{"items":["a","b",""]})
 assert Jbp["ok"]is Jvq and Jbp["count"]==2
 Jvg("edge_cases_3_6: exercise ok")
if __name__=="__main__":
 Jbz()
# Created by pyminifier (https://github.com/liftoff/pyminifier)

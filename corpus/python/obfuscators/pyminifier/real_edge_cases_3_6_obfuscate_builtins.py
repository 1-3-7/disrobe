wu=int
wk=str
wV=float
wp=ValueError
wm=OverflowError
wM=object
wt=TypeError
wg=KeyError
wO=IndexError
wB=Exception
wX=None
wW=RuntimeError
wK=bool
wF=True
wc=False
wY=enumerate
wT=sum
wi=max
wq=sorted
wJ=list
wN=filter
wQ=range
ws=property
wP=classmethod
wo=staticmethod
wz=ImportError
wj=len
wh=isinstance
wr=bytes
wH=hasattr
wy=print
import asyncio
wR=asyncio.get_event_loop
wU=asyncio.run
import contextlib
wf=contextlib.contextmanager
wG=contextlib.suppress
import functools
wD=functools.lru_cache
wn=functools.wraps
import json
import secrets
wI=secrets.token_hex
from typing import(Any,Awaitable,Callable,ClassVar,Dict,Generic,Iterator,List,NamedTuple,Optional,Sequence,Set,Tuple,TypeVar,)
__PY_BAND__:E[wu,wu]=(3,6)
T=TypeVar("T")
R=TypeVar("R")
w:wu=3
L:wV=0.5
v:wu=1_000_000
def El(Q:wk,count:wu,ratio:wV)->wk:
 l:wk=f"{name!r}: {count:04d} @ {ratio:.2%}"
 b:wk=f"name-len={len(name)}"
 return f"{head} | {tail}"
def Eb(parts:D[wk])->wk:
 e:wk=f"count={len(parts)}"
 S:wk=", ".join(parts)
 return e+" | "+f"items=[{joined}]"
def Ee()->wu:
 U:wu=1_000_000_000
 R:wu=0xFF_FF_FF
 G:wu=0b1010_1010
 return U+R+G
def ES(Ej:wk)->wu:
 try:
  return wu(Ej)
 except wp as exc:
  return-1
def EU(P:Sequence[wu])->wu:
 f:wu=0
 try:
  for it in P:
   f+=it
 except wm:
  f=-1
 else:
  f+=100
 finally:
  f=f
 return f
def ER(K:wM)->wk:
 try:
  return wk(wu(K))
 except wp:
  return "not-a-number"
 except wt:
  return "wrong-type"
 except(wg,wO):
  return "lookup-failed"
 except wB:
  return "unknown"
def EG(cause:wB)->wX:
 raise wW("wrapped failure")from cause
def Ef(lock:c)->wu:
 with lock:
  return 1
def En(store:V[wk,wu])->wX:
 with wG(wg,wp):
  del store["maybe-missing"]
def ED(P:D[wu],target:wu)->wK:
 for it in P:
  if it==target:
   return wF
 else:
  return wc
def EI(n:wu)->wu:
 i:wu=0
 while i<n:
  if i==5:
   break
  i+=1
 else:
  return-1
 return i
def Eu(pairs:D[E[wu,wu]])->wu:
 f:wu=0
 for a,b in pairs:
  f+=a*b
 return f
def Ek(flag:wK,a:wu,b:wu)->wu:
 return a if flag else b
def EV(a:wu,b:wu,c:wu)->wK:
 return 0<=a<b<=c<100
def Ep(matrix:D[D[wu]])->V[wk,c]:
 n:D[wu]=[cell for row in matrix for cell in row if cell>0]
 I:u[wu]={cell for row in matrix for cell in row}
 k:V[wu,D[wu]]={i:row for i,row in wY(matrix)if row}
 p:wu=wT(cell*2 for row in matrix for cell in row)
 return{"flat":n,"uniq":I,"index":k,"gen_sum":p}
def Em(e:D[wu],suffix:D[wu])->D[wu]:
 return[*e,0,*suffix]
def EM(args:D[wu])->wu:
 return wT([*args,1])+wi(args)
def Et(Y:D[wu])->E[wu,D[wu],wu]:
 m,*M,t=Y
 return m,M,t
def Eg(a:V[wk,wu],b:V[wk,wu])->V[wk,wu]:
 return{**a,**b,"extra":1}
def EO(P:D[E[wk,wu]])->D[E[wk,wu]]:
 g:D[E[wk,wu]]=wq(P,key=lambda kv:(kv[1],kv[0]))
 return wJ(wN(lambda kv:kv[1]>0,g))
def EB(e:wk)->h[[h[...,R]],h[...,R]]:
 def EX(fn:h[...,R])->h[...,R]:
  @wn(fn)
  def EW(*args:c,**kwargs:c)->R:
   return fn(*args,**kwargs)
  return EW
 return EX
@EB("trace")
def EK(x:wu,y:wu=10)->wu:
 return x+y
@wD(maxsize=128)
def EF(n:wu)->wu:
 return n*n if n<2 else EF(n-1)+EF(n-2)
def Ec()->h[[wu],wu]:
 B:wu=0
 def EY(X:wu)->wu:
  nonlocal B
  B+=X
  return B
 return EY
W:wu=0
def ET()->wu:
 global W
 W+=1
 return W
def Ei(limit:wu)->Iterator[wu]:
 for i in wQ(limit):
  if i%3==0:
   yield i
def Eq()->wk:
 return wI(8)
async def EJ(client:c)->wk:
 K:wr=await client.authenticate()
 F:c=await client.open(K)
 Y:wr=await F.Ex()
 return Y.decode()
async def EN(source:c)->c:
 async for T in source:
  if T%2==0:
   yield T*10
async def EQ(source:c)->D[wu]:
 return[T async for T in source if T>0]
class r(NamedTuple):
 x:wu
 y:wu=0
class H(Generic[T]):
 def __init__(i,T:T)->wX:
  i.item:T=T
 def Es(i)->T:
  return i.item
class y:
 q:J[wu]=3
 N:J[wV]=30.0
 Q:J[wk]="default"
class A:
 def __init__(i,r:wu,g:wu,b:wu)->wX:
  i.r:wu=r
  i.g:wu=g
  i.b:wu=b
 @ws
 def EP(i)->wV:
  return(i.r+i.g+i.b)/3.0
 @wP
 def Eo(cls)->"Color":
  return cls(0,0,0)
 @wo
 def Ez(a:"Color",b:"Color")->"Color":
  return A((a.r+b.r)//2,(a.g+b.g)//2,(a.b+b.b)//2)
 def __repr__(i)->wk:
  return f"Color({self.r}, {self.g}, {self.b})"
class EL:
 def __init__(i)->wX:
  i._value:wu=0
 @ws
 def Ej(i)->wu:
  return i._value
 @Ej.setter
 def Ej(i,s:wu)->wX:
  i._value=wi(0,s)
def Eh()->c:
 try:
  import orjson as serializer
 except wz:
  import json as serializer
 return serializer
def Er(action:wk,payload:V[wk,c])->V[wk,c]:
 if action=="list":
  try:
   P:D[wk]=[wk(x).strip()for x in payload.get("items",[])if x]
  except wt:
   return{"ok":wc,"error":"not-iterable"}
  return{"ok":wF,"count":wj(P),"items":P}
 if action=="batch":
  f:wu=wT(v for v in payload.values()if wh(v,wu))
  return{"ok":wF,"total":f}
 return{"ok":wc,"error":"unknown"}
def EH()->wX:
 assert El("alpha",7,0.5)=="'alpha': 0007 @ 50.00% | name-len=5"
 assert "items=" in Eb(["a","b"])
 assert Ee()>0
 assert ES("123")==123
 assert ES("nope")==-1
 assert EU([1,2,3])==106
 assert ER("xyz")=="not-a-number"
 @wf
 def Ey()->Iterator[wX]:
  yield wX
 assert Ef(Ey())==1
 En({"present":1})
 assert ED([1,2,3],2)is wF
 assert ED([1,2,3],99)is wc
 assert EI(10)==5
 assert Eu([(1,2),(3,4)])==14
 assert Ek(wF,1,2)==1
 assert EV(1,2,50)is wF
 o:V[wk,c]=Ep([[1,2],[3,-1,4]])
 assert wj(o["flat"])==4
 assert Em([1,2],[3,4])==[1,2,0,3,4]
 assert EM([1,2,3])==(1+2+3+1)+3
 m,z,t=Et([1,2,3,4,5])
 assert m==1 and z==[2,3,4]and t==5
 assert Eg({"a":1},{"b":2})=={"a":1,"b":2,"extra":1}
 assert EO([("a",2),("b",-1),("c",3)])==[("a",2),("c",3)]
 assert EK(1,2)==3
 assert EF(5)>0
 j:h[[wu],wu]=Ec()
 assert j(1)==1 and j(2)==3
 assert ET()>=1
 assert wJ(Ei(10))==[0,3,6,9]
 assert wj(Eq())==16
 p:r=r(1)
 assert p.x==1 and p.y==0
 c:H[wu]=H(42)
 assert c.Es()==42
 assert y.retries==3
 async def EC()->wX:
  class wS:
   async def Ea(i)->wr:
    return b"tok"
   async def Ed(i,_t:wr)->c:
    return i
   async def Ex(i)->wr:
    return b"payload"
  C:wk=await EJ(wS())
  assert C=="payload"
  async def EA()->c:
   for v in[0,1,2,3]:
    yield v
  a=EN(EA())
  d:D[wu]=[]
  async for v in a:
   d.append(v)
  assert d==[0,20]
  async def wE()->c:
   for v in[-1,0,1,2]:
    yield v
  x:D[wu]=await EQ(wE())
  assert x==[1,2]
 if wH(asyncio,"run"):
  wU(EC())
 else:
  wR().run_until_complete(EC())
 assert A(10,20,30).brightness==20.0
 Ew:EL=EL()
 Ew.Ej=-5
 assert Ew.Ej==0
 Ew.Ej=100
 assert Ew.Ej==100
 assert Eh()is not wX
 Ev:V[wk,c]=Er("list",{"items":["a","b",""]})
 assert Ev["ok"]is wF and Ev["count"]==2
 wy("edge_cases_3_6: exercise ok")
if __name__=="__main__":
 EH()
# Created by pyminifier (https://github.com/liftoff/pyminifier)

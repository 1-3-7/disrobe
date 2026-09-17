import asyncio
import contextlib
import functools
import json
import secrets
from typing import(Any,Awaitable,Callable,ClassVar,Dict,Generic,Iterator,List,NamedTuple,Optional,Sequence,Set,Tuple,TypeVar,)
__PY_BAND__:Tuple[int,int]=(3,6)
T=TypeVar("T")
R=TypeVar("R")
MAX_RETRIES:int=3
BACKOFF_BASE:float=0.5
ONE_MILLION:int=1_000_000
def X(name:str,count:int,ratio:float)->str:
 head:str=f"{name!r}: {count:04d} @ {ratio:.2%}"
 tail:str=f"name-len={len(name)}"
 return f"{head} | {tail}"
def a(parts:List[str])->str:
 prefix:str=f"count={len(parts)}"
 joined:str=", ".join(parts)
 return prefix+" | "+f"items=[{joined}]"
def O()->int:
 big:int=1_000_000_000
 hex_lit:int=0xFF_FF_FF
 bin_lit:int=0b1010_1010
 return big+hex_lit+bin_lit
def b(Q:str)->int:
 try:
  return int(Q)
 except ValueError as exc:
  return-1
def T(items:Sequence[int])->int:
 total:int=0
 try:
  for it in items:
   total+=it
 except OverflowError:
  total=-1
 else:
  total+=100
 finally:
  total=total
 return total
def g(token:object)->str:
 try:
  return str(int(token))
 except ValueError:
  return "not-a-number"
 except TypeError:
  return "wrong-type"
 except(KeyError,IndexError):
  return "lookup-failed"
 except Exception:
  return "unknown"
def C(cause:Exception)->None:
 raise RuntimeError("wrapped failure")from cause
def H(lock:Any)->int:
 with lock:
  return 1
def w(store:Dict[str,int])->None:
 with contextlib.suppress(KeyError,ValueError):
  del store["maybe-missing"]
def c(items:List[int],target:int)->bool:
 for it in items:
  if it==target:
   return True
 else:
  return False
def p(n:int)->int:
 i:int=0
 while i<n:
  if i==5:
   break
  i+=1
 else:
  return-1
 return i
def I(pairs:List[Tuple[int,int]])->int:
 total:int=0
 for a,b in pairs:
  total+=a*b
 return total
def D(flag:bool,a:int,b:int)->int:
 return a if flag else b
def x(a:int,b:int,c:int)->bool:
 return 0<=a<b<=c<100
def N(matrix:List[List[int]])->Dict[str,Any]:
 flat:List[int]=[cell for row in matrix for cell in row if cell>0]
 uniq:Set[int]={cell for row in matrix for cell in row}
 index:Dict[int,List[int]]={i:row for i,row in enumerate(matrix)if row}
 gen_sum:int=sum(cell*2 for row in matrix for cell in row)
 return{"flat":flat,"uniq":uniq,"index":index,"gen_sum":gen_sum}
def o(prefix:List[int],suffix:List[int])->List[int]:
 return[*prefix,0,*suffix]
def B(args:List[int])->int:
 return sum([*args,1])+max(args)
def u(data:List[int])->Tuple[int,List[int],int]:
 first,*middle,last=data
 return first,middle,last
def Y(a:Dict[str,int],b:Dict[str,int])->Dict[str,int]:
 return{**a,**b,"extra":1}
def A(items:List[Tuple[str,int]])->List[Tuple[str,int]]:
 ordered:List[Tuple[str,int]]=sorted(items,key=lambda kv:(kv[1],kv[0]))
 return list(filter(lambda kv:kv[1]>0,ordered))
def i(prefix:str)->Callable[[Callable[...,R]],Callable[...,R]]:
 def e(fn:Callable[...,R])->Callable[...,R]:
  @functools.wraps(fn)
  def r(*args:Any,**kwargs:Any)->R:
   return fn(*args,**kwargs)
  return r
 return e
@i("trace")
def m(x:int,y:int=10)->int:
 return x+y
@functools.lru_cache(maxsize=128)
def f(n:int)->int:
 return n*n if n<2 else f(n-1)+f(n-2)
def S()->Callable[[int],int]:
 accumulator:int=0
 def M(delta:int)->int:
  nonlocal accumulator
  accumulator+=delta
  return accumulator
 return M
_GLOBAL_COUNTER:int=0
def l()->int:
 global _GLOBAL_COUNTER
 _GLOBAL_COUNTER+=1
 return _GLOBAL_COUNTER
def G(limit:int)->Iterator[int]:
 for i in range(limit):
  if i%3==0:
   yield i
def K()->str:
 return secrets.token_hex(8)
async def y(client:Any)->str:
 token:bytes=await client.authenticate()
 session:Any=await client.open(token)
 data:bytes=await session.read()
 return data.decode()
async def z(source:Any)->Any:
 async for item in source:
  if item%2==0:
   yield item*10
async def W(source:Any)->List[int]:
 return[item async for item in source if item>0]
class Coordinate(NamedTuple):
 x:int
 y:int=0
class Comparable(Generic[T]):
 def __init__(self,item:T)->None:
  self.item:T=item
 def h(self)->T:
  return self.item
class TypedConfig:
 retries:ClassVar[int]=3
 timeout:ClassVar[float]=30.0
 name:ClassVar[str]="default"
class Color:
 def __init__(self,r:int,g:int,b:int)->None:
  self.r:int=r
  self.g:int=g
  self.b:int=b
 @property
 def v(self)->float:
  return(self.r+self.g+self.b)/3.0
 @classmethod
 def j(cls)->"Color":
  return cls(0,0,0)
 @staticmethod
 def J(a:"Color",b:"Color")->"Color":
  return Color((a.r+b.r)//2,(a.g+b.g)//2,(a.b+b.b)//2)
 def __repr__(self)->str:
  return f"Color({self.r}, {self.g}, {self.b})"
class Counter:
 def __init__(self)->None:
  self._value:int=0
 @property
 def Q(self)->int:
  return self._value
 @Q.setter
 def Q(self,new:int)->None:
  self._value=max(0,new)
def R()->Any:
 try:
  import orjson as serializer
 except ImportError:
  import json as serializer
 return serializer
def V(action:str,payload:Dict[str,Any])->Dict[str,Any]:
 if action=="list":
  try:
   items:List[str]=[str(x).strip()for x in payload.get("items",[])if x]
  except TypeError:
   return{"ok":False,"error":"not-iterable"}
  return{"ok":True,"count":len(items),"items":items}
 if action=="batch":
  total:int=sum(v for v in payload.values()if isinstance(v,int))
  return{"ok":True,"total":total}
 return{"ok":False,"error":"unknown"}
def d()->None:
 assert X("alpha",7,0.5)=="'alpha': 0007 @ 50.00% | name-len=5"
 assert "items=" in a(["a","b"])
 assert O()>0
 assert b("123")==123
 assert b("nope")==-1
 assert T([1,2,3])==106
 assert g("xyz")=="not-a-number"
 @contextlib.contextmanager
 def L()->Iterator[None]:
  yield None
 assert H(L())==1
 w({"present":1})
 assert c([1,2,3],2)is True
 assert c([1,2,3],99)is False
 assert p(10)==5
 assert I([(1,2),(3,4)])==14
 assert D(True,1,2)==1
 assert x(1,2,50)is True
 result:Dict[str,Any]=N([[1,2],[3,-1,4]])
 assert len(result["flat"])==4
 assert o([1,2],[3,4])==[1,2,0,3,4]
 assert B([1,2,3])==(1+2+3+1)+3
 first,mid,last=u([1,2,3,4,5])
 assert first==1 and mid==[2,3,4]and last==5
 assert Y({"a":1},{"b":2})=={"a":1,"b":2,"extra":1}
 assert A([("a",2),("b",-1),("c",3)])==[("a",2),("c",3)]
 assert m(1,2)==3
 assert f(5)>0
 adder:Callable[[int],int]=S()
 assert adder(1)==1 and adder(2)==3
 assert l()>=1
 assert list(G(10))==[0,3,6,9]
 assert len(K())==16
 p:Coordinate=Coordinate(1)
 assert p.x==1 and p.y==0
 c:Comparable[int]=Comparable(42)
 assert c.get()==42
 assert TypedConfig.retries==3
 async def P()->None:
  class FakeClient:
   async def E(self)->bytes:
    return b"tok"
   async def k(self,_t:bytes)->Any:
    return self
   async def t(self)->bytes:
    return b"payload"
  text:str=await y(FakeClient())
  assert text=="payload"
  async def U()->Any:
   for v in[0,1,2,3]:
    yield v
  agen=z(U())
  collected:List[int]=[]
  async for v in agen:
   collected.append(v)
  assert collected==[0,20]
  async def s()->Any:
   for v in[-1,0,1,2]:
    yield v
  vals:List[int]=await W(s())
  assert vals==[1,2]
 if hasattr(asyncio,"run"):
  asyncio.run(P())
 else:
  asyncio.get_event_loop().run_until_complete(P())
 assert Color(10,20,30).brightness==20.0
 cnt:Counter=Counter()
 cnt.value=-5
 assert cnt.value==0
 cnt.value=100
 assert cnt.value==100
 assert R()is not None
 routed:Dict[str,Any]=V("list",{"items":["a","b",""]})
 assert routed["ok"]is True and routed["count"]==2
 print("edge_cases_3_6: exercise ok")
if __name__=="__main__":
 d()
# Created by pyminifier (https://github.com/liftoff/pyminifier)

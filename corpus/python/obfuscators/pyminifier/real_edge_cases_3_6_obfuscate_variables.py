import asyncio
import contextlib
import functools
import json
import secrets
from typing import(Any,Awaitable,Callable,ClassVar,Dict,Generic,Iterator,List,NamedTuple,Optional,Sequence,Set,Tuple,TypeVar,)
__PY_BAND__:q[int,int]=(3,6)
T=TypeVar("T")
R=TypeVar("R")
G:int=3
m:float=0.5
C:int=1_000_000
def fstring_basic(A:str,count:int,ratio:float)->str:
 g:str=f"{name!r}: {count:04d} @ {ratio:.2%}"
 n:str=f"name-len={len(name)}"
 return f"{head} | {tail}"
def fstring_simple_concat(parts:P[str])->str:
 p:str=f"count={len(parts)}"
 o:str=", ".join(parts)
 return p+" | "+f"items=[{joined}]"
def underscore_numeric_literals()->int:
 a:int=1_000_000_000
 B:int=0xFF_FF_FF
 j:int=0b1010_1010
 return a+B+j
def try_except_basic(value:str)->int:
 try:
  return int(value)
 except ValueError as exc:
  return-1
def try_except_else_finally(D:Sequence[int])->int:
 s:int=0
 try:
  for it in D:
   s+=it
 except OverflowError:
  s=-1
 else:
  s+=100
 finally:
  s=s
 return s
def multiple_except_clauses(S:object)->str:
 try:
  return str(int(S))
 except ValueError:
  return "not-a-number"
 except TypeError:
  return "wrong-type"
 except(KeyError,IndexError):
  return "lookup-failed"
 except Exception:
  return "unknown"
def raise_from_chain(cause:Exception)->None:
 raise RuntimeError("wrapped failure")from cause
def with_simple(lock:T)->int:
 with lock:
  return 1
def with_suppress(store:h[str,int])->None:
 with contextlib.suppress(KeyError,ValueError):
  del store["maybe-missing"]
def for_else(D:P[int],target:int)->bool:
 for it in D:
  if it==target:
   return True
 else:
  return False
def while_else(n:int)->int:
 i:int=0
 while i<n:
  if i==5:
   break
  i+=1
 else:
  return-1
 return i
def for_with_unpacking(pairs:P[q[int,int]])->int:
 s:int=0
 for a,b in pairs:
  s+=a*b
 return s
def ternary_simple(flag:bool,a:int,b:int)->int:
 return a if flag else b
def chained_comparison(a:int,b:int,c:int)->bool:
 return 0<=a<b<=c<100
def comprehensions(matrix:P[P[int]])->h[str,T]:
 e:P[int]=[cell for row in matrix for cell in row if cell>0]
 v:R[int]={cell for row in matrix for cell in row}
 K:h[int,P[int]]={i:row for i,row in enumerate(matrix)if row}
 r:int=sum(cell*2 for row in matrix for cell in row)
 return{"flat":e,"uniq":v,"index":K,"gen_sum":r}
def starred_in_literals(p:P[int],suffix:P[int])->P[int]:
 return[*p,0,*suffix]
def starred_in_call(args:P[int])->int:
 return sum([*args,1])+max(args)
def starred_assignment(t:P[int])->q[int,P[int],int]:
 Q,*L,x=t
 return Q,L,x
def dict_merge_via_unpack(a:h[str,int],b:h[str,int])->h[str,int]:
 return{**a,**b,"extra":1}
def lambda_usage(D:P[q[str,int]])->P[q[str,int]]:
 d:P[q[str,int]]=sorted(D,key=lambda kv:(kv[1],kv[0]))
 return list(filter(lambda kv:kv[1]>0,d))
def decorator_factory(p:str)->Y[[Y[...,R]],Y[...,R]]:
 def decorate(fn:Y[...,R])->Y[...,R]:
  @functools.wraps(fn)
  def wrapper(*args:T,**kwargs:T)->R:
   return fn(*args,**kwargs)
  return wrapper
 return decorate
@decorator_factory("trace")
def decorated_function(x:int,y:int=10)->int:
 return x+y
@functools.lru_cache(maxsize=128)
def memoized(n:int)->int:
 return n*n if n<2 else memoized(n-1)+memoized(n-2)
def closure_with_nonlocal()->Y[[int],int]:
 i:int=0
 def add(O:int)->int:
  nonlocal i
  i+=O
  return i
 return add
k:int=0
def mutate_global()->int:
 global k
 k+=1
 return k
def generator_function(limit:int)->Iterator[int]:
 for i in range(limit):
  if i%3==0:
   yield i
def secrets_token_demo()->str:
 return secrets.token_hex(8)
async def await_chain(client:T)->str:
 S:bytes=await client.authenticate()
 X:T=await client.open(S)
 t:bytes=await X.read()
 return t.decode()
async def async_generator(source:T)->T:
 async for W in source:
  if W%2==0:
   yield W*10
async def async_comprehension(source:T)->P[int]:
 return[W async for W in source if W>0]
class u(NamedTuple):
 x:int
 y:int=0
class N(Generic[T]):
 def __init__(w,W:T)->None:
  w.item:T=W
 def get(w)->T:
  return w.item
class l:
 H:E[int]=3
 U:E[float]=30.0
 A:E[str]="default"
class c:
 def __init__(w,r:int,g:int,b:int)->None:
  w.r:int=r
  w.g:int=g
  w.b:int=b
 @property
 def brightness(w)->float:
  return(w.r+w.g+w.b)/3.0
 @classmethod
 def black(cls)->"Color":
  return cls(0,0,0)
 @staticmethod
 def mix(a:"Color",b:"Color")->"Color":
  return c((a.r+b.r)//2,(a.g+b.g)//2,(a.b+b.b)//2)
 def __repr__(w)->str:
  return f"Color({self.r}, {self.g}, {self.b})"
class qm:
 def __init__(w)->None:
  w._value:int=0
 @property
 def value(w)->int:
  return w._value
 @value.setter
 def value(w,M:int)->None:
  w._value=max(0,M)
def conditional_import_fallback()->T:
 try:
  import orjson as serializer
 except ImportError:
  import json as serializer
 return serializer
def parse_and_route(action:str,payload:h[str,T])->h[str,T]:
 if action=="list":
  try:
   D:P[str]=[str(x).strip()for x in payload.get("items",[])if x]
  except TypeError:
   return{"ok":False,"error":"not-iterable"}
  return{"ok":True,"count":len(D),"items":D}
 if action=="batch":
  s:int=sum(v for v in payload.values()if isinstance(v,int))
  return{"ok":True,"total":s}
 return{"ok":False,"error":"unknown"}
def exercise()->None:
 assert fstring_basic("alpha",7,0.5)=="'alpha': 0007 @ 50.00% | name-len=5"
 assert "items=" in fstring_simple_concat(["a","b"])
 assert underscore_numeric_literals()>0
 assert try_except_basic("123")==123
 assert try_except_basic("nope")==-1
 assert try_except_else_finally([1,2,3])==106
 assert multiple_except_clauses("xyz")=="not-a-number"
 @contextlib.contextmanager
 def _lock()->Iterator[None]:
  yield None
 assert with_simple(_lock())==1
 with_suppress({"present":1})
 assert for_else([1,2,3],2)is True
 assert for_else([1,2,3],99)is False
 assert while_else(10)==5
 assert for_with_unpacking([(1,2),(3,4)])==14
 assert ternary_simple(True,1,2)==1
 assert chained_comparison(1,2,50)is True
 I:h[str,T]=comprehensions([[1,2],[3,-1,4]])
 assert len(I["flat"])==4
 assert starred_in_literals([1,2],[3,4])==[1,2,0,3,4]
 assert starred_in_call([1,2,3])==(1+2+3+1)+3
 Q,y,x=starred_assignment([1,2,3,4,5])
 assert Q==1 and y==[2,3,4]and x==5
 assert dict_merge_via_unpack({"a":1},{"b":2})=={"a":1,"b":2,"extra":1}
 assert lambda_usage([("a",2),("b",-1),("c",3)])==[("a",2),("c",3)]
 assert decorated_function(1,2)==3
 assert memoized(5)>0
 f:Y[[int],int]=closure_with_nonlocal()
 assert f(1)==1 and f(2)==3
 assert mutate_global()>=1
 assert list(generator_function(10))==[0,3,6,9]
 assert len(secrets_token_demo())==16
 p:u=u(1)
 assert p.x==1 and p.y==0
 c:N[int]=N(42)
 assert c.get()==42
 assert l.retries==3
 async def _drive()->None:
  class FakeClient:
   async def authenticate(w)->bytes:
    return b"tok"
   async def open(w,_t:bytes)->T:
    return w
   async def read(w)->bytes:
    return b"payload"
  J:str=await await_chain(FakeClient())
  assert J=="payload"
  async def src()->T:
   for v in[0,1,2,3]:
    yield v
  F=async_generator(src())
  V:P[int]=[]
  async for v in F:
   V.append(v)
  assert V==[0,20]
  async def src2()->T:
   for v in[-1,0,1,2]:
    yield v
  z:P[int]=await async_comprehension(src2())
  assert z==[1,2]
 if hasattr(asyncio,"run"):
  asyncio.run(_drive())
 else:
  asyncio.get_event_loop().run_until_complete(_drive())
 assert c(10,20,30).brightness==20.0
 qG:qm=qm()
 qG.value=-5
 assert qG.value==0
 qG.value=100
 assert qG.value==100
 assert conditional_import_fallback()is not None
 qC:h[str,T]=parse_and_route("list",{"items":["a","b",""]})
 assert qC["ok"]is True and qC["count"]==2
 print("edge_cases_3_6: exercise ok")
if __name__=="__main__":
 exercise()
# Created by pyminifier (https://github.com/liftoff/pyminifier)

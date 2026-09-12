import asyncio
import contextlib
import functools
import json
import secrets
from typing import(Any,Awaitable,Callable,ClassVar,Dict,Generic,Iterator,List,NamedTuple,Optional,Sequence,Set,Tuple,TypeVar,)
__PY_BAND__:x[int,int]=(3,6)
T=TypeVar("T")
R=TypeVar("R")
f:int=3
z:float=0.5
B:int=1_000_000
def fstring_basic(K:str,count:int,ratio:float)->str:
 D:str=f"{name!r}: {count:04d} @ {ratio:.2%}"
 C:str=f"name-len={len(name)}"
 return f"{head} | {tail}"
def fstring_simple_concat(parts:L[str])->str:
 V:str=f"count={len(parts)}"
 S:str=", ".join(parts)
 return V+" | "+f"items=[{joined}]"
def underscore_numeric_literals()->int:
 l:int=1_000_000_000
 W:int=0xFF_FF_FF
 k:int=0b1010_1010
 return l+W+k
def try_except_basic(value:str)->int:
 try:
  return int(value)
 except ValueError as exc:
  return-1
def try_except_else_finally(h:Sequence[int])->int:
 i:int=0
 try:
  for it in h:
   i+=it
 except OverflowError:
  i=-1
 else:
  i+=100
 finally:
  i=i
 return i
def multiple_except_clauses(b:object)->str:
 try:
  return str(int(b))
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
def with_simple(lock:G)->int:
 with lock:
  return 1
def with_suppress(store:o[str,int])->None:
 with contextlib.suppress(KeyError,ValueError):
  del store["maybe-missing"]
def for_else(h:L[int],target:int)->bool:
 for it in h:
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
def for_with_unpacking(pairs:L[x[int,int]])->int:
 i:int=0
 for a,b in pairs:
  i+=a*b
 return i
def ternary_simple(flag:bool,a:int,b:int)->int:
 return a if flag else b
def chained_comparison(a:int,b:int,c:int)->bool:
 return 0<=a<b<=c<100
def comprehensions(matrix:L[L[int]])->o[str,G]:
 R:L[int]=[cell for row in matrix for cell in row if cell>0]
 s:Q[int]={cell for row in matrix for cell in row}
 T:o[int,L[int]]={i:row for i,row in enumerate(matrix)if row}
 m:int=sum(cell*2 for row in matrix for cell in row)
 return{"flat":R,"uniq":s,"index":T,"gen_sum":m}
def starred_in_literals(V:L[int],suffix:L[int])->L[int]:
 return[*V,0,*suffix]
def starred_in_call(args:L[int])->int:
 return sum([*args,1])+max(args)
def starred_assignment(j:L[int])->x[int,L[int],int]:
 F,*H,g=j
 return F,H,g
def dict_merge_via_unpack(a:o[str,int],b:o[str,int])->o[str,int]:
 return{**a,**b,"extra":1}
def lambda_usage(h:L[x[str,int]])->L[x[str,int]]:
 q:L[x[str,int]]=sorted(h,key=lambda kv:(kv[1],kv[0]))
 return list(filter(lambda kv:kv[1]>0,q))
def decorator_factory(V:str)->w[[w[...,R]],w[...,R]]:
 def decorate(fn:w[...,R])->w[...,R]:
  @functools.wraps(fn)
  def wrapper(*args:G,**kwargs:G)->R:
   return fn(*args,**kwargs)
  return wrapper
 return decorate
@decorator_factory("trace")
def decorated_function(x:int,y:int=10)->int:
 return x+y
@functools.lru_cache(maxsize=128)
def memoized(n:int)->int:
 return n*n if n<2 else memoized(n-1)+memoized(n-2)
def closure_with_nonlocal()->w[[int],int]:
 c:int=0
 def add(M:int)->int:
  nonlocal c
  c+=M
  return c
 return add
p:int=0
def mutate_global()->int:
 global p
 p+=1
 return p
def generator_function(limit:int)->Iterator[int]:
 for i in range(limit):
  if i%3==0:
   yield i
def secrets_token_demo()->str:
 return secrets.token_hex(8)
async def await_chain(client:G)->str:
 b:bytes=await client.authenticate()
 d:G=await client.open(b)
 j:bytes=await d.read()
 return j.decode()
async def async_generator(source:G)->G:
 async for u in source:
  if u%2==0:
   yield u*10
async def async_comprehension(source:G)->L[int]:
 return[u async for u in source if u>0]
class O(NamedTuple):
 x:int
 y:int=0
class J(Generic[T]):
 def __init__(E,u:T)->None:
  E.item:T=u
 def get(E)->T:
  return E.item
class X:
 v:t[int]=3
 n:t[float]=30.0
 K:t[str]="default"
class U:
 def __init__(E,r:int,g:int,b:int)->None:
  E.r:int=r
  E.g:int=g
  E.b:int=b
 @property
 def brightness(E)->float:
  return(E.r+E.g+E.b)/3.0
 @classmethod
 def black(cls)->"Color":
  return cls(0,0,0)
 @staticmethod
 def mix(a:"Color",b:"Color")->"Color":
  return U((a.r+b.r)//2,(a.g+b.g)//2,(a.b+b.b)//2)
 def __repr__(E)->str:
  return f"Color({self.r}, {self.g}, {self.b})"
class xz:
 def __init__(E)->None:
  E._value:int=0
 @property
 def value(E)->int:
  return E._value
 @value.setter
 def value(E,I:int)->None:
  E._value=max(0,I)
def conditional_import_fallback()->G:
 try:
  import orjson as serializer
 except ImportError:
  import json as serializer
 return serializer
def parse_and_route(action:str,payload:o[str,G])->o[str,G]:
 if action=="list":
  try:
   h:L[str]=[str(x).strip()for x in payload.get("items",[])if x]
  except TypeError:
   return{"ok":False,"error":"not-iterable"}
  return{"ok":True,"count":len(h),"items":h}
 if action=="batch":
  i:int=sum(v for v in payload.values()if isinstance(v,int))
  return{"ok":True,"total":i}
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
 r:o[str,G]=comprehensions([[1,2],[3,-1,4]])
 assert len(r["flat"])==4
 assert starred_in_literals([1,2],[3,4])==[1,2,0,3,4]
 assert starred_in_call([1,2,3])==(1+2+3+1)+3
 F,y,g=starred_assignment([1,2,3,4,5])
 assert F==1 and y==[2,3,4]and g==5
 assert dict_merge_via_unpack({"a":1},{"b":2})=={"a":1,"b":2,"extra":1}
 assert lambda_usage([("a",2),("b",-1),("c",3)])==[("a",2),("c",3)]
 assert decorated_function(1,2)==3
 assert memoized(5)>0
 e:w[[int],int]=closure_with_nonlocal()
 assert e(1)==1 and e(2)==3
 assert mutate_global()>=1
 assert list(generator_function(10))==[0,3,6,9]
 assert len(secrets_token_demo())==16
 p:O=O(1)
 assert p.x==1 and p.y==0
 c:J[int]=J(42)
 assert c.get()==42
 assert X.retries==3
 async def _drive()->None:
  class FakeClient:
   async def authenticate(E)->bytes:
    return b"tok"
   async def open(E,_t:bytes)->G:
    return E
   async def read(E)->bytes:
    return b"payload"
  A:str=await await_chain(FakeClient())
  assert A=="payload"
  async def src()->G:
   for v in[0,1,2,3]:
    yield v
  a=async_generator(src())
  Y:L[int]=[]
  async for v in a:
   Y.append(v)
  assert Y==[0,20]
  async def src2()->G:
   for v in[-1,0,1,2]:
    yield v
  P:L[int]=await async_comprehension(src2())
  assert P==[1,2]
 if hasattr(asyncio,"run"):
  asyncio.run(_drive())
 else:
  asyncio.get_event_loop().run_until_complete(_drive())
 assert U(10,20,30).brightness==20.0
 xf:xz=xz()
 xf.value=-5
 assert xf.value==0
 xf.value=100
 assert xf.value==100
 assert conditional_import_fallback()is not None
 xB:o[str,G]=parse_and_route("list",{"items":["a","b",""]})
 assert xB["ok"]is True and xB["count"]==2
 print("edge_cases_3_6: exercise ok")
if __name__=="__main__":
 exercise()
# Created by pyminifier (https://github.com/liftoff/pyminifier)

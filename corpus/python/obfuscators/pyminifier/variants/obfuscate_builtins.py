B=int
b=str
U=float
p=ValueError
F=OverflowError
y=object
I=TypeError
P=KeyError
v=IndexError
E=Exception
A=None
N=RuntimeError
n=bool
f=True
L=False
q=enumerate
C=sum
S=max
e=sorted
G=list
W=filter
J=range
a=property
z=classmethod
i=staticmethod
w=ImportError
m=len
O=isinstance
V=bytes
X=open
k=hasattr
T=print
import asyncio
import contextlib
import functools
import json
import secrets
from typing import(Any,Awaitable,Callable,ClassVar,Dict,Generic,Iterator,List,NamedTuple,Optional,Sequence,Set,Tuple,TypeVar,)
__PY_BAND__:Tuple[B,B]=(3,6)
T=TypeVar("T")
R=TypeVar("R")
MAX_RETRIES:B=3
BACKOFF_BASE:U=0.5
ONE_MILLION:B=1_000_000
def fstring_basic(name:b,count:B,ratio:U)->b:
 head:b=f"{name!r}: {count:04d} @ {ratio:.2%}"
 tail:b=f"name-len={len(name)}"
 return f"{head} | {tail}"
def fstring_simple_concat(parts:List[b])->b:
 prefix:b=f"count={len(parts)}"
 joined:b=", ".join(parts)
 return prefix+" | "+f"items=[{joined}]"
def underscore_numeric_literals()->B:
 big:B=1_000_000_000
 hex_lit:B=0xFF_FF_FF
 bin_lit:B=0b1010_1010
 return big+hex_lit+bin_lit
def try_except_basic(value:b)->B:
 try:
  return B(value)
 except p as exc:
  return-1
def try_except_else_finally(items:Sequence[B])->B:
 total:B=0
 try:
  for it in items:
   total+=it
 except F:
  total=-1
 else:
  total+=100
 finally:
  total=total
 return total
def multiple_except_clauses(token:y)->b:
 try:
  return b(B(token))
 except p:
  return "not-a-number"
 except I:
  return "wrong-type"
 except(P,v):
  return "lookup-failed"
 except E:
  return "unknown"
def raise_from_chain(cause:E)->A:
 raise N("wrapped failure")from cause
def with_simple(lock:Any)->B:
 with lock:
  return 1
def with_suppress(store:Dict[b,B])->A:
 with contextlib.suppress(P,p):
  del store["maybe-missing"]
def for_else(items:List[B],target:B)->n:
 for it in items:
  if it==target:
   return f
 else:
  return L
def while_else(n:B)->B:
 i:B=0
 while i<n:
  if i==5:
   break
  i+=1
 else:
  return-1
 return i
def for_with_unpacking(pairs:List[Tuple[B,B]])->B:
 total:B=0
 for a,b in pairs:
  total+=a*b
 return total
def ternary_simple(flag:n,a:B,b:B)->B:
 return a if flag else b
def chained_comparison(a:B,b:B,c:B)->n:
 return 0<=a<b<=c<100
def comprehensions(matrix:List[List[B]])->Dict[b,Any]:
 flat:List[B]=[cell for row in matrix for cell in row if cell>0]
 uniq:Set[B]={cell for row in matrix for cell in row}
 index:Dict[B,List[B]]={i:row for i,row in q(matrix)if row}
 gen_sum:B=C(cell*2 for row in matrix for cell in row)
 return{"flat":flat,"uniq":uniq,"index":index,"gen_sum":gen_sum}
def starred_in_literals(prefix:List[B],suffix:List[B])->List[B]:
 return[*prefix,0,*suffix]
def starred_in_call(args:List[B])->B:
 return C([*args,1])+S(args)
def starred_assignment(data:List[B])->Tuple[B,List[B],B]:
 first,*middle,last=data
 return first,middle,last
def dict_merge_via_unpack(a:Dict[b,B],b:Dict[b,B])->Dict[b,B]:
 return{**a,**b,"extra":1}
def lambda_usage(items:List[Tuple[b,B]])->List[Tuple[b,B]]:
 ordered:List[Tuple[b,B]]=e(items,key=lambda kv:(kv[1],kv[0]))
 return G(W(lambda kv:kv[1]>0,ordered))
def decorator_factory(prefix:b)->Callable[[Callable[...,R]],Callable[...,R]]:
 def decorate(fn:Callable[...,R])->Callable[...,R]:
  @functools.wraps(fn)
  def wrapper(*args:Any,**kwargs:Any)->R:
   return fn(*args,**kwargs)
  return wrapper
 return decorate
@decorator_factory("trace")
def decorated_function(x:B,y:B=10)->B:
 return x+y
@functools.lru_cache(maxsize=128)
def memoized(n:B)->B:
 return n*n if n<2 else memoized(n-1)+memoized(n-2)
def closure_with_nonlocal()->Callable[[B],B]:
 accumulator:B=0
 def add(delta:B)->B:
  nonlocal accumulator
  accumulator+=delta
  return accumulator
 return add
_GLOBAL_COUNTER:B=0
def mutate_global()->B:
 global _GLOBAL_COUNTER
 _GLOBAL_COUNTER+=1
 return _GLOBAL_COUNTER
def generator_function(limit:B)->Iterator[B]:
 for i in J(limit):
  if i%3==0:
   yield i
def secrets_token_demo()->b:
 return secrets.token_hex(8)
async def await_chain(client:Any)->b:
 token:V=await client.authenticate()
 session:Any=await client.X(token)
 data:V=await session.read()
 return data.decode()
async def async_generator(source:Any)->Any:
 async for item in source:
  if item%2==0:
   yield item*10
async def async_comprehension(source:Any)->List[B]:
 return[item async for item in source if item>0]
class Coordinate(NamedTuple):
 x:B
 y:B=0
class Comparable(Generic[T]):
 def __init__(self,item:T)->A:
  self.item:T=item
 def get(self)->T:
  return self.item
class TypedConfig:
 retries:ClassVar[B]=3
 timeout:ClassVar[U]=30.0
 name:ClassVar[b]="default"
class Color:
 def __init__(self,r:B,g:B,b:B)->A:
  self.r:B=r
  self.g:B=g
  self.b:B=b
 @a
 def brightness(self)->U:
  return(self.r+self.g+self.b)/3.0
 @z
 def black(cls)->"Color":
  return cls(0,0,0)
 @i
 def mix(a:"Color",b:"Color")->"Color":
  return Color((a.r+b.r)//2,(a.g+b.g)//2,(a.b+b.b)//2)
 def __repr__(self)->b:
  return f"Color({self.r}, {self.g}, {self.b})"
class Counter:
 def __init__(self)->A:
  self._value:B=0
 @a
 def value(self)->B:
  return self._value
 @value.setter
 def value(self,new:B)->A:
  self._value=S(0,new)
def conditional_import_fallback()->Any:
 try:
  import orjson as serializer
 except w:
  import json as serializer
 return serializer
def parse_and_route(action:b,payload:Dict[b,Any])->Dict[b,Any]:
 if action=="list":
  try:
   items:List[b]=[b(x).strip()for x in payload.get("items",[])if x]
  except I:
   return{"ok":L,"error":"not-iterable"}
  return{"ok":f,"count":m(items),"items":items}
 if action=="batch":
  total:B=C(v for v in payload.values()if O(v,B))
  return{"ok":f,"total":total}
 return{"ok":L,"error":"unknown"}
def exercise()->A:
 assert fstring_basic("alpha",7,0.5)=="'alpha': 0007 @ 50.00% | name-len=5"
 assert "items=" in fstring_simple_concat(["a","b"])
 assert underscore_numeric_literals()>0
 assert try_except_basic("123")==123
 assert try_except_basic("nope")==-1
 assert try_except_else_finally([1,2,3])==106
 assert multiple_except_clauses("xyz")=="not-a-number"
 @contextlib.contextmanager
 def _lock()->Iterator[A]:
  yield A
 assert with_simple(_lock())==1
 with_suppress({"present":1})
 assert for_else([1,2,3],2)is f
 assert for_else([1,2,3],99)is L
 assert while_else(10)==5
 assert for_with_unpacking([(1,2),(3,4)])==14
 assert ternary_simple(f,1,2)==1
 assert chained_comparison(1,2,50)is f
 result:Dict[b,Any]=comprehensions([[1,2],[3,-1,4]])
 assert m(result["flat"])==4
 assert starred_in_literals([1,2],[3,4])==[1,2,0,3,4]
 assert starred_in_call([1,2,3])==(1+2+3+1)+3
 first,mid,last=starred_assignment([1,2,3,4,5])
 assert first==1 and mid==[2,3,4]and last==5
 assert dict_merge_via_unpack({"a":1},{"b":2})=={"a":1,"b":2,"extra":1}
 assert lambda_usage([("a",2),("b",-1),("c",3)])==[("a",2),("c",3)]
 assert decorated_function(1,2)==3
 assert memoized(5)>0
 adder:Callable[[B],B]=closure_with_nonlocal()
 assert adder(1)==1 and adder(2)==3
 assert mutate_global()>=1
 assert G(generator_function(10))==[0,3,6,9]
 assert m(secrets_token_demo())==16
 p:Coordinate=Coordinate(1)
 assert p.x==1 and p.y==0
 c:Comparable[B]=Comparable(42)
 assert c.get()==42
 assert TypedConfig.retries==3
 async def _drive()->A:
  class FakeClient:
   async def authenticate(self)->V:
    return b"tok"
   async def X(self,_t:V)->Any:
    return self
   async def read(self)->V:
    return b"payload"
  text:b=await await_chain(FakeClient())
  assert text=="payload"
  async def src()->Any:
   for v in[0,1,2,3]:
    yield v
  agen=async_generator(src())
  collected:List[B]=[]
  async for v in agen:
   collected.append(v)
  assert collected==[0,20]
  async def src2()->Any:
   for v in[-1,0,1,2]:
    yield v
  vals:List[B]=await async_comprehension(src2())
  assert vals==[1,2]
 if k(asyncio,"run"):
  asyncio.run(_drive())
 else:
  asyncio.get_event_loop().run_until_complete(_drive())
 assert Color(10,20,30).brightness==20.0
 cnt:Counter=Counter()
 cnt.value=-5
 assert cnt.value==0
 cnt.value=100
 assert cnt.value==100
 assert conditional_import_fallback()is not A
 routed:Dict[b,Any]=parse_and_route("list",{"items":["a","b",""]})
 assert routed["ok"]is f and routed["count"]==2
 T("edge_cases_3_6: exercise ok")
if __name__=="__main__":
 exercise()
# Created by pyminifier (https://github.com/liftoff/pyminifier)

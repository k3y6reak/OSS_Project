# 3_Advanced topics

## Working with Data and Conventions

종종 분석중인 프로그램에서 구조화된 데이터에 엑세스 하길 원하는 경우가 있습니다. angr은 이러한 부분을 해소하기 위한 몇 가지 기능이 있습니다.

### Working with types

angr에는 type을 나타내는 시스템이 있습니다. 이러한 SimTypes는 `angr.types`에 있습니다. 이 클래스중 하나의 인스턴스는 type을 나타냅니다. 대부분의 type은 `SimState`로 대체하지 않으면 불완전합니다. 크기는 실행중인 아키텍쳐에 따라 다릅니다. `ty.with_state`를 사용하여 이 작업을 수행할 수 있으며, 지정된 상태로 자신의 복사본을 반환합니다.

angr는 또한 `pycparser` 주위에 경량 래퍼를 가지고 있는데, 이것은 C 파서입니다. 이렇게 하면 객체의 타입에 대한 인스턴스를 가져오는데 도움이 됩니다.

```python
>>> import angr

# note that SimType objects have their __repr__ defined to return their c type name,
# so this function actually returned a SimType instance.
>>> angr.types.parse_type('int')
int

>>> angr.types.parse_type('char **')
char**

>>> angr.types.parse_type('struct aa {int x; long y;}')
struct aa

>>> angr.types.parse_type('struct aa {int x; long y;}').fields
OrderedDict([('x', int), ('y', long)])
```

또한 C definition을 파싱하여 변수/함수 선언 또는 새로 정의된 타입을 dictionary로 반환할 수 있습니다.

```python
>>> angr.types.parse_defns("int x; typedef struct llist { char* str; struct llist *next; } list_node; list_node *y;")
{'x': int, 'y': struct llist*}

>>> defs = angr.types.parse_types("int x; typedef struct llist { char* str; struct llist *next; } list_node; list_node *y;")
>>> defs
{'list_node': struct llist}

# if you want to get both of these dicts at once, use parse_file, which returns both in a tuple.

>>> defs['list_node'].fields
OrderedDict([('str', char*), ('next', struct llist*)])

>>> defs['list_node'].fields['next'].pts_to.fields
OrderedDict([('str', char*), ('next', struct llist*)])

# If you want to get a function type and you don't want to construct it manually,
# you have to use parse_defns, not parse_type
>>> angr.types.parse_defns("int x(int y, double z);")
{'x': (int, double) -> int}
```

마지막으로 나중에 사용할 수 있도록 구조체의 정의를 등록할 수 있습니다.

```python
>>> angr.types.define_struct('struct abcd { int x; int y; }')
>>> angr.types.register_types(angr.types.parse_types('typedef long time_t;'))
>>> angr.types.parse_defns('struct abcd a; time_t b;')
{'a': struct abcd, 'b': long}
```

이러한 타입 객체는 그 자체로는 유용하지 않지만 angr의 다른 부분으로 전달되어 데이터 타입을 지정할 수 있습니다.

### Accessing typed data from memory

이제 angr의 타입 시스템이 어떻게 작동하는지 알았으니 `state.mem` 인터페이스의 모든 기능을 사용할 수 있습니다. `types` 모듈에 등록된 모든 유형을 사용하여 메모리에서 데이터를 추출할 수 있습니다.

```python
>>> import angr
>>> b = angr.Project('examples/fauxware/fauxware')
>>> s = b.factory.entry_state()
>>> s.mem[0x601048]
<<untyped> <unresolvable> at 0x601048>

>>> s.mem[0x601048].long
<long (64 bits) <BV64 0x4008d0> at 0x601048>

>>> s.mem[0x601048].long.resolved
<BV64 0x4008d0>

>>> s.mem[0x601048].long.concrete
0x4008d0

>>> s.mem[0x601048].abcd
<struct abcd {
  .x = <int (32 bits) <BV32 0x4008d0> at 0x601048>,
  .y = <int (32 bits) <BV32 0x0> at 0x60104c>
} at 0x601048>

>>> s.mem[0x601048].long.resolved
<BV64 0x4008d0>

>>> s.mem[0x601048].long.concrete
4196560L

>>> s.mem[0x601048].deref
<<untyped> <unresolvable> at 0x4008d0>

>>> s.mem[0x601048].deref.string
<string_t <BV64 0x534f534e45414b59> at 0x4008d0>

>>> s.mem[0x601048].deref.string.resolved
<BV64 0x534f534e45414b59>

>>> s.mem[0x601048].deref.string.concrete
'SOSNEAKY'
```

인터페이스는 다음과 같이 동작합니다.

* 먼저 [array index notation]을 사용하여 로드하려는 주소를 지정하세요.
* 그 주소에 포인터가 있다면, `deref` 속성에 접근하여 메모리에 있는 주소에 `SimMemView`를 반환할 수 있습니다.
* 그 다음 해당 이름의 속성에 액세스하여 데이터 타입을 지정합니다. 지원되는 타입 목록을 확인하려면 `state.mem.types`를 확인하세요.
* 그리고  타입을 조정할 수 있습니다. 모든 타입은 선호하는 모든 상세 검색을 지원합니다. 현재 지원되는 유일한 기능은 멤버 이름으로 구조체의 멤버에 액세스할 수 있으며, 해당 요소에 액세스하기 위해 문자열이나 배열에 인덱스 할 수 있다는 것입니다.
* 지정한 주소가 처음에 해당 타입의 배열을 가리키는 경우 `.array(n)`을 사용하여 데이터를 n개의 요소로 구성된 배열로 둘 수 있습니다.
* 마지막으로 `.resolved` 또는 `.concrete`로 구조화된 데이터를 추출하세요. `.resolved`는 비트 벡터 값을 반환하고, `.concrete`는 데이터를 가장 잘 나타내는 정수, 문자열, 배열 등의 값을 반환합니다.
* 또는 생성한 속성 체인에 할당하여 메모리에 값을 저장할 수 있습니다. 파이썬이 작동하는 방식때문에 `x = s.mem [...]. prop; x = val`은 작동하지 않기 때문에 `s.mem [...]. prop=val`이라고 작성해야합니다.

`define_struct` 또는 `register_types`를 사용하여 구조체를 정의하면 여기서 타입으로 액세스 할 수 있습니다.

```python
>>> s.mem[b.entry].abcd
<struct abcd {
  .x = <int (32 bits) <BV32 0x8949ed31> at 0x400580>,
  .y = <int (32 bits) <BV32 0x89485ed1> at 0x400584>
} at 0x400580>
```
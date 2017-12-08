## 상태 - 메모리, 레지스터 등

angr의 작동 방식을 이해하기 위해서 `SimState`객체를 사용했습니다.

### 리뷰 : 메모리와 레지스터 쓰기 및 읽기

문서를 순서대로 읽었다면 메모리와 레지스터에 접근하는 방법을 이미 봤을 겁니다. `state.regs`는 레지스터의 이름, 속성, 읽기, 쓰기가 가능하고 `state.mem`은 메모리에 읽고 쓰는 것을 제공합니다.

레지스터와 메모리에 저장하기 위해서 bitvector 형식의 AST를 이해해야 합니다.

```python
>>> import angr
>>> proj = angr.Project('/bin/true')
>>> state = proj.factory.entry_state()

# copy rsp to rbp
>>> state.regs.rbp = state.regs.rsp

# store rdx to memory at 0x1000
>>> state.mem[0x1000].uint64_t = state.regs.rdx

# dereference rbp
>>> state.regs.rbp = state.mem[state.regs.rbp].uint64_t.resolved

# add rax, qword ptr [rsp + 8]
>>> state.regs.rax += state.mem[state.regs.rsp + 8].uint64_t.resolved
```

### 기본 실행

앞서 Simulation Manager를 통해서 기본 실행 방법을 봤습니다. 다음 장에서 Simulation Manager의 모든 기능에 대해서 설명하겠지만 `state.setp()`을 이용해 간단한 실행 방법을 보도록 하겠습니다. 이 함수는 한 단계씩 `Simsuccessors`에 의해 호출된 symbolic 실행과 리턴을 합니다.

Angr의 symbolic execution은 컴파일 된 개별 명령어의 작업을 수행하고 SimState을 변경하기 위해 수행하는 것입니다. `if(x > 4)`와 같은 코드에 도달했을 때, 만약 x가 bitvector일 경우 무슨 일이 일어날까요? angr가 분석하는 어딘가에서 `x>4`를 비교할 것이고 수행할 것입니다. 그 결과는 `<Bool x_32_1 > 4>`가 됩니다.

그렇다면 해당 비교에서 값이 "참"일지 "거짓" 중 어떤 값을 가져야 할까요? 답은 두 가지 모두를 갖는 것입니다. 참인 경우에 시뮬레이션을 하고 거짓인 경우 시뮬레이션하는 것을 각각 생성합니다.

이를 증명하기 위해서 [가짜 펌웨어](https://docs.angr.io/examples/fauxware/fauxware)를 예로 들어보겠습니다. 이 바이너리의 [소스코드](https://docs.angr.io/examples/fauxware/fauxware.c)를 살펴보면 펌웨어의 인증 메커니즘이 어떤 누구라도 관리자로 "SOSNEAKY"라는 비밀번호로 접근할 수 있습니다. 

```python
>>> proj = angr.Project('examples/fauxware/fauxware')
>>> state = proj.factory.entry_state()
>>> while True:
...     succ = state.step()
...     if len(succ.successors) == 2:
...         break
...     state = succ.successors[0]

>>> state1, state2 = succ.successors
>>> state1
<SimState @ 0x400629>
>>> state2
<SimState @ 0x400699
```

`strcmp`는 애뮬레이트하기 까다로운 함수이며 제약 조건이 매우 복잡합니다.

애뮬레이트 된 프로그램은 표준 입력에서 데이터를 가져오며 angr는 기본적으로 symbolic data 스트림으로 취급됩니다. 제약 조건을 해결하고 수행할 수 있는 가능한 입력을 얻으려면 stdin의 실제 내용을 참조해야 합니다. `state.posix.files[0].all_bytes()`는 stdin에서 읽은 모든 내용을 bitvector를 검색하는데 사용합니다.

```python
>>> input_data = state1.posix.files[0].all_bytes()

>>> state1.solver.eval(input_data, cast_to=str)
'\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00\x00\x00'

>>> state2.solver.eval(input_data, cast_to=str)
'\x00\x00\x00\x00\x00\x00\x00\x00\x00S\x00\x80N\x00\x00 \x00\x00\x00\x00'
```

`state1`을 따라 가려면 "SOSNEAKY"를 암호로 입력해야 하고 `state2`로 가려면 다른 값을 입력해야 합니다. z3가 해당 조건에 맞는 문자열 중 하나를 찾아낸 것입니다.


### 상태 조절

상태를 사용하기 위해서 `project.factory.entry_state()`를 사용했습니다. 이거슨 factory에서 사용할 수 있는 상태 중 하나입니다.

 - `.black_state()` : 공백 상태를 만듭니다.
 - `.entry_state()` : 바이너리의 초기 주소에서 실행 준비가 된 상태를 만듭니다.
 - `.full_init_state()` : 공유 라이브러리 생성자 또는 미리 초기화하는 프로그램 처럼 바이너리에 접근하기 전 실행하는 초기화 프로그램을 통해 실행할 준비가 된 상태를 만듭니다.
 - `.call_state()` : 지정된 함수를 실행할 준비가 된 상태를 만듭니다.

위 생성자를 통해서 여러 인수를 통해 사용자가 정의할 수 있습니다.

 - 모든 생성자는 `addr`로 시작할 주소를 설정할 수 있습니다.
 - `args`를 이용해 환경 변수 `env`에 `entry_state`와 `full_init_date`를 사용할 수 있습니다. 이 구조는 문자열이나 bitvector 입니다. `args`는 항상 비어있으며 찾고자 한다면 하나 이상이 있어야 합니다.
 - `entry_state`와 `full_init_state`에 `argc`로 bitvector를 넣을 수 있습니다. argc로 전달한 값이 args 수 보다 클 수 없습니다.
 - call state를 사용하려면 `.call_state(addr, arg1, arg2, ...)`을 호출할 수 있습니다. `addr`은 호출할 함수의 주소이며 `argN`은 N번째 함수의 인수입니다. 메모리를 할당하고 객체에 대한 포인터를 전달하려면 포인터를 PointerWrapper를 이용해야 합니다.
 - 함수의 호출 규약을 지정하려면 `cc` 인자와 같은 `SimCCinstance`를 이용해야 합니다.

### 메모리용 Low level 인터페이스

`state.mem`은 형식이 정해진 데이터를 로드하는데 편리하지만 raw 로드나 저장을 할 경우 복잡합니다. `state.memory`에서 `.load(addr, size)`와 `.store(addr, val)` 함수를 이용해 직접 할 수 있습니다.

```python
>>> s = proj.factory.blank_state()
>>> s.memory.store(0x4000, s.solver.BVV(0x0123456789abcdef0123456789abcdef, 128))
>>> s.memory.load(0x4004, 6) # load-size is in bytes
<BV48 0x89abcdef0123>
```

데이터는 로드 된 후에 Big-Endian 방식으로 저장됩니다. `state.memroy`의 목적은 저장된 데이터를 로드하는 것이기 때문입니다. 방식을 변경하려는 경우 `endness`로 정할 수 있습니다.

```python
>>> import archinfo
>>> s.memory.load(0x4000, 4, endness=archinfo.Endness.LE)
<BV32 0x67453201>
```


### 상태 플러그인

SimState는 실제로 플러그인에 저장됩니다. 플러그인 속성은 `memory`, `registers`, `mem`, `regs`, `solber` 등등이 있습니다. 이러한 방식은 모듈화 뿐만 아니라 쉽게 기능을 사용할 수 있습니다.

예를들어 `memory` 플러그인은 메모리 공간을 시뮬레이션 하지만 분석은 추상 메모리 프러그인을 사용하도록 선택할 수 있습니다. 

#### Global 플러그인

`state.globals`는 간단한 플러그인이며, Python의 dictionary를 구현하여 임의의 데이터를 상태에 저장할 수 있게 합니다.

#### History 플러그인

`state.history`는 실행 중에 경로에 대한 기록 데이터를 저장하는 중요한 플러그인 입니다. 여러개의 노드가 연결되어 있고 각각 하나의 실행 횟수를 말합니다. `state.history.parent.paret`로 확인할 수 있습니다.

히스토리를 작업하기 편하도록 반복자를 제공합니다. `history.recent_NAME`에 값이 저장되고 `history.NAME`으로 사용할 수 있습니다. 예를들어 `for addr in state.history.bbl_addrs: print hex(addr)`은 바이너리가 실행되면서 가장 최근에 실행된 주소를 출력합니다. `state.history.parent.reccent_bbl_addrs`는 이전 단계를 말합니다. 

 - `history.descriptions` : 실행 횟수의 상태를 문자열로 나타냅니다.
 - `history.bbl_addrs` : state에의해 실행되는 기본 블록 주소입니다.
 - `history.jumpkinds` : VEX 문자열과 같이 제어 흐름을 나타냅니다.
 - `history.guards` : 상태의 각 지점의 조건 목록을 나타냅니다.
 - `history.events` : 프로그램이 메시지를 띄우거나 종료하는 것과 같이 이벤트가 발생하는 목록을 말합니다.
 - `history.actions` : 기본적으로 비어있는 것이지만 `angr.options.refs` 옵션을 추가하면 프로그램에서 수행한 메모리, 레지스터, 임시 값에 접근한 기록을 표시합니다.

#### CallStack 플러그인

angr는 애뮬레이트된 프로그램의 스택을 추적합니다. history와 마찬가지로 callstack도 연결된 노드이지만 반복자는 제공되지 않습니다. `state.callstack`을 이용하여 직접 반복하여 얻을 수 있습니다.

 - `callstack.func_addr` : 현재 실행중인 함수의 주소
 - `callstack.call_site_addr` : 현재 함수를 호출한 블록 주소
 - `callstack_stack_ptr` : 현재 함수의 첫 스택 포인터 값
 - `callstack.ret_addr` : 함수가 리턴할 경우 리턴할 위치

#### posix 플러그인

진행 중

### 파일 시스템 작업

진행 중: SimFile이 무엇인지.

파일 시스템을 효과적으로 사용하는 많은 상태 초기화 루틴 옵션이 있습니다. `fs`, `concrete_fs`, `chroot` 옵션이 있습니다.

`fs` 옵션은 SimFile 객체에 파일 이름을 전달할 수 있습니다. 이렇게 사용하면 파일 내용에 구체적인 크기 제한을 설정하는 등의 작업을 수행할 수 있습니다.

`concrete_fs` 옵션을 `True`로 설정하면 디스크에 있는 파일을 보호합니다. 예를들어, `concrete_fs`을 `false`로 실행되면  시뮬레이션 중 프로그램이 'banner.txt' 열려고 시도하면 SimFile이 만들어지고 파일이 있는 것 처럼 시뮬레이션을 계속 합니다. `concrete_fs`가 `True`이면 새로운 SimFile을 만들고 실행되는 결과의 영향을 최소화합니다. 만약 'banner.txt'가 존재하지 않는다면 SimFile은 시뮬레이션 중에 오류가 출력됩니다. 또한 경로가 '/dev/'로 시작하는 파일을 열려고 한다면 `conrete_fs`가 `true`로 설정되어도 열리지 않습니다.

`chroot` 옵션은 경로를 지정할 수 있습니다. 분석중인 프로그램이 절대 경로를 이용해 파일을 참조할 때 편리할 수 있습니다. 예를 들어 /etc/passwd를 열려고 시도하는 경우 /etc/passwd가 $CMD/etc/passwd에서 읽힐 수 있도록 작업 디렉토리를 설정할 수 있습니다.

```python
>>> files = {'/dev/stdin': angr.storage.file.SimFile("/dev/stdin", "r", size=30)}
>>> s = proj.factory.entry_state(fs=files, concrete_fs=True, chroot="angr-chroot/")
```
위 예제는 최대 30바이트를 stdin에서 읽도록 제한하는 상태를 만듭니다.


### 복사 및 병합

state는 엄청 빠른 복사를 지원합니다.

```python
>>> proj = angr.Project('/bin/true')
>>> s = proj.factory.blank_state()
>>> s1 = s.copy()
>>> s2 = s.copy()

>>> s1.mem[0x1000].uint32_t = 0x41414141
>>> s2.mem[0x1000].uint32_t = 0x42424242

```

state를 병합할 수 있습니다.

```python
# merge will return a tuple. the first element is the merged state
# the second element is a symbolic variable describing a state flag
# the third element is a boolean describing whether any merging was done
>>> (s_merged, m, anything_merged) = s1.merge(s2)

# this is now an expression that can resolve to "AAAA" *or* "BBBB"
>>> aaaa_or_bbbb = s_merged.mem[0x1000].uint32_t

```

진행 중: 병합의 한계
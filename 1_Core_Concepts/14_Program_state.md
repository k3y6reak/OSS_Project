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


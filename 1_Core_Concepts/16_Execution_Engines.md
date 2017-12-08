## 시뮬레이션 및 연구

angr는 `SimEngine` 클래스를 사용하여 입력 상태에 미치는 영향을 애뮬레이션 합니다.
아래 목록은 기본 엔진 목록입니다.

 - 이전 단계에서 불연속 상태일 때 실패 엔진이 작동합니다.
 - 이전 단계에서 syscall 내에서 끝날 때 syscall 엔진이 작동합니다.
 - 현재 주소가 후킹됐을 때 hook 엔진이 작동합니다.
 - `UNICORN` 상태가 활성화 되거나 심볼릭 데이터가 존재하지 않는 경우 unicorn 엔진이 작동합니다.
 - 마지막 대체로 VEX 엔진이 작동됩니다.

### SimSuccessors

실제로 모든 엔진을 시도하는 코드는 `project.factory.successors(state, **kwargs)` 입니다.
`state.step()`과 `simulation_manager.step()`가 핵심입니다. SimSuccessors 객체를 반환하며 이전 문서에서 간략히 설명했습니다. SimSuccessors의 목적은 successor 상태의 간단한 분류를 수행하고 변수 속성을 저장하는 것입니다.

| 속성 | 보호 조건 | 명령 포인터 | 설명 
| --- | --- |
| `successors` | True(심볼릭일 수 있지만 True로 제한함.) | 심볼릭일 수 있습니다.(256개의 솔루션이 있고 `unconstrained_successors`를 참고하세요.) | 일반적으로 만족스러운 successor 상태는 엔진에 의해 처리됩니다. 이 상태의 명령 포인터는 심볼릭일 것입니다. (입력에 따른 계산된 점프.) 실제로 몇 가지 잠재적인 실행을 나타낼지 모릅니다. |
| `unsat_successors` | False(심볼릭일 수 있지만 False로 제한함.) |  심볼릭일 수 있습니다. | 만족하지 못한 successors. 이 successrs는 보호 조건이 오직 false 입니다. (점프가 이루어지지 않거나 기본 브랜치로 점프하는 것.) |
| `flat_successors` | True(심볼릭일 수 있지만 True로 제한함.) | 구체적인 값 | 위에서 언급한 것 처럼, `successors` 목록은 symbolic 명령 포인터를 갖습니다. 상태가 흘러갈 때 `simEngineVEX.process` 처럼 복잡합니다. 이를 완화하기 위해서 symbolic 명령 포인터를 사용하여 다음 상태를 만다면 가능한 구체적인 모든 솔루션(256개 까지) 계산하고 솔루션의 상태를 복사합니다. 이 프로세스를 'flattening'이라 부릅니다. `flat_successors `는 상태이며 각각 다른 명령 포인터를 갖습니다. 예를들어, `successors`의 상태가 `x+5`인 명령어 포인터라면 `X`가 `X > 0x800000`이고 `X < 0x800010`일 때 16개의 다른 `flat_successors` 상태로 만듭니다. `0x800006`, `0x800007`처럼 `0x800015`까지. |
| `unconstrained_successors` | True(심볼릭일 수 있지만 True로 제한함.) | 256개 이상의 가능한 솔루션이 나타난 경우 명령 포인터는 덮어 쓰여집니다.(스택 오버플로우 같은.) |
| unsat | `save_unsat` 옵션이 SimulationManager에 전달되면 만족할 수 없는 상태가 만들어집니다. |
| `all_successors` | 아무거나 | 심볼릭일 수 있음. | `succesors` + `unsat_successors` + `unconstrained_successors`|

### Breapoints

진행 중: 다시 내용 작성.

angr는 breakpoint를 지원합니다.

```python
>>> import angr
>>> b = angr.Project('examples/fauxware/fauxware')

# get our state
>>> s = b.factory.entry_state()

# add a breakpoint. This breakpoint will drop into ipdb right before a memory write happens.
>>> s.inspect.b('mem_write')

# on the other hand, we can have a breakpoint trigger right *after* a memory write happens. 
# we can also have a callback function run instead of opening ipdb.
>>> def debug_func(state):
...     print "State %s is about to do a memory write!"

>>> s.inspect.b('mem_write', when=angr.BP_AFTER, action=debug_func)

# or, you can have it drop you in an embedded IPython!
>>> s.inspect.b('mem_write', when=angr.BP_AFTER, action=angr.BP_IPYTHON)
```

메모리 쓰기 이외에 많은 break 구문이 존재합니다. BP_BEFORE 또는 BP_AFTER로 breakpoiont를 설정할 수 있습니다.

| 이벤트 | 의미 |
| ---| ---|
| mem_read | 메모리 읽기 |
| mem_write | 메모리 쓰기 |
| reg_read | 레지스터 읽기 |
| reg_write | 레지스터 쓰기 |
| tmp_read | temp 읽기 |
| tmp_write | temp 쓰기 |
| expr | 산술 연산 또는 상수의 결과 |
| statement | IR 상태 해석 |
| instruction | 새로운 명령어 해석 |
| irsb | 새로운 블록 해석 |
| consraints | 새로운 제약이 상태에 추가 |
| exit | 실행으로부터 successor가 발생 |
| symbolic_variable | 새로운 심볼릭 변수 생성 |
| call | call 명렁어 실행 |
| address_concretization | 심볼릭 메모리 접근 |

이벤트 들은 다른 속성을 나타냅니다.

| 이벤트 | 속성 이름 | 가능한 속성 | 속성 의미 |
| --- | --- | ---| --- |
| mem_read | mem_read_address | BP_BEFORE 또는 BP_AFTER | 메모리에서 읽음 |
| mem_read | mem_read_length | BP_BEFORE 또는 BP_AFTER | 메모리 읽기의 길이 |
| mem_read | mem_read_expr | BP_AFTER | 읽는 주소 표현 |
| mem_write | mem_write_address | BP_BEFORE 또는 BP_AFTER | 메모리 쓰기 |
| mem_write | mem_write_length | BP_BEFORE 또는 BP_AFTER | 메모리 쓰기 길이 |
| mem_write | mem_write_expr | BP_BEFORE 또는 BP_AFTER | 쓰는 주소 표현 
| reg_read | reg_read_offset | BP_BEFORE 또는 BP_AFTER | 레지스터에서 읽음 |
| reg_read | reg_read_length | BP_BEFORE 또는 BP_AFTER | 레지스터 읽기의 길이 |
| reg_read | reg_read_expr | BP_AFTER | 레지스터 표현 |
| reg_write | reg_write_offset | BP_BEFORE 또는 BP_AFTER | 레지스터에 쓰기 |
| reg_write | reg_write_length | BP_BEFORE 또는 BP_AFTER | 레지스터 쓰기 길이 |
| reg_write | reg_write_expr | BP_BEFORE 또는 BP_AFTER | 쓰는 주소 표현 |
| tmp_read | tmp_read_num | BP_BEFORE 또는 BP_AFTER | temp 읽는 수 |
| tmp_read | tmp_read_expr | BP_AFTER | temp 표현 |
| tmp_write | tmp_write_num | BP_BEFORE 또는 BP_AFTER | temp 쓰는 수 |
| tmp_write | tmp_write_length | BP_AFTER | temp 쓰기 표현 |
| expr | expr | BP_AFTER | 표현 수 |
| statement | statement | BP_BFORE 또는 BP_AFTER | ID 상태의 인덱스 |
| call | function_address | BP_BEFORE or BP_AFTER | 호출된 함수의 이름 |
| exit | exit_target | BP_BEFORE or BP_AFTER | SimExit의 표현 |
| exit | exit_guard | BP_BEFORE or BP_AFTER | SimExit의 보호 표현 |
| exit | jumpkind | BP_BEFORE or BP_AFTER | SimExit의 종류 표현 |
| symbolic_variable | symbolic_name | BP_BEFORE or BP_AFTER | 만들어진 심볼릭 변수 이름. solver 엔진이 이름을 수정할 수 있음. 마지막 심볼릭 표현을 위한 symbolic_expr 확인 |
| symbolic_variable | symbolic_size | BP_BEFORE or BP_AFTER | 만들어진 심볼릭 변수의 크기 |
| symbolic_variable | symbolic_expr | BP_AFTER | 심볼릭 변수의 표현 |
| address_concretization | address_concretization_strategy | BP_BEFORE or BP_AFTER | SimConcretizationStrategy는 주소를 해결합니다. breakpoint에 의해 수정될 수 있습니다. breakpoint 핸들러가 None이면 생략됩니다. |
| address_concretization | address_concretization_action | BP_BEFORE or BP_AFTER | 메모리 활동에 사용된 SimAction |
| address_concretization | address_concretization_memory | BP_BEFORE or BP_AFTER | 메모리에서 가져오는 SimMemory 객체 |
| address_concretization | address_concretization_expr | BP_BEFORE or BP_AFTER | AST는 메모리 인덱스를 표현합니다. breakpoint는 주소를 해결하는데 영향을 줍니다. | 
| address_concretization | address_concretization_add_constraints | BP_BEFORE or BP_AFTER | 강제하거나 안하는 경우 읽을 때 추가할 수 있습니다. |
| address_concretization | address_concretization_result | BP_AFTER | 메모리 주소를 정수형을로 표현합니다. breakpoint는 다른 결과에 덮어쓸 수 있습니다. |

위 속성은 breakpoint 콜백 중에 `state.inspect`으로 적절한 값에 접근할 수 있습니다. 이 값을 변경하여 수정할 수 있습니다.

```python
>>> def track_reads(state):
...     print 'Read', state.inspect.mem_read_expr, 'from', state.inspect.mem_read_address
...
>>> s.inspect.b('mem_read', when=angr.BP_AFTER, action=track_reads)
```

추가적으로 각각의 `inspect.b` 키워드 인수로 사용하여 breakpoint를 조건에 맞춰 사용할 수 있습니다.

```python
# This will break before a memory write if 0x1000 is a possible value of its target expression
>>> s.inspect.b('mem_write', mem_write_address=0x1000)

# This will break before a memory write if 0x1000 is the *only* value of its target expression
>>> s.inspect.b('mem_write', mem_write_address=0x1000, mem_write_address_unique=True)

# This will break after instruction 0x8000, but only 0x1000 is a possible value of the last expression that was read from memory
>>> s.inspect.b('instruction', when=angr.BP_AFTER, instruction=0x8000, mem_read_expr=0x1000)
```

사실, 조건으로 함수를 지정할 수 있습니다.

```python
# this is a complex condition that could do anything! In this case, it makes sure that RAX is 0x41414141 and
# that the basic block starting at 0x8004 was executed sometime in this path's history
>>> def cond(state):
...     return state.eval(state.regs.rax, cast_to=str) == 'AAAA' and 0x8004 in state.inspect.backtrace

>>> s.inspect.b('mem_write', condition=cond)
```
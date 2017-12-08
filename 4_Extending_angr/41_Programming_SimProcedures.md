## 후킹과 SimProcedures 상세 설명

angr의 후킹은 엄청 강력합니다. 상상하는 어떤 방법으로든 프로그램을 수정할 수 있습니다. 후킹을 프로그래밍하는 것은 정확하지 않을 수 있는데 이번 장은 SimProcedures를 프로그래밍하는데 도움이 될 것입니다.

### 시작

어떤 프로그램에서 버그를 제거하는 예제입니다.

```python
>>> from angr import Project, SimProcedure
>>> project = Project('examples/fauxware/fauxware')

>>> class BugFree(SimProcedure):
...    def run(self, argc, argv):
...        print 'Program running with argc=%s and argv=%s' % (argc, argv)
...        return 0

# this assumes we have symbols for the binary
>>> project.hook_symbol('main', BugFree)

# Run a quick execution!
>>> simgr = project.factory.simulation_manager()
>>> simgr.run()  # step until no more active states
Program running with argc=<SAO <BV64 0x0>> and argv=<SAO <BV64 0x7fffffffffeffa0>>
<SimulationManager with 1 deadended>
```

프로그램 실행시 main 함수에 도달하면 실제 main 함수를 실행하는 대신에 procedure가 실행됩니다. 그리고 메시지와 리턴 값을 출력합니다.

함수에 진입할 때 인자 값은 `run()`을 이용하여 정의할 수 있습니다. SimProcedure는 인자 값을 [호출 규약](https://docs.angr.io/docs/structured_data.html#working-with-calling-conventions)에 의해서 자동으로 뽑아내 함수를 실행합니다. 마찬가지로, 반환 값도 호출 규약에 따라 반환 됩니다. 아키텍처에 의존하고 연결된 레지스터나 스택의 pop 결과로 이동합니다.

### context 구현

`Project` 클래스의 dict는 `SimProcedure`의 `project._sim_procedures`에 매핑됩니다. [실행 파이프라인](https://docs.angr.io/docs/pipeline.html)이 dict 안에 존재하는 후킹된 주소라면 `project._sim_procedures[address].execute(state)`를 실행합니다. 호출 규약에 따라 인자 값을 가져오고 안정성을 유지하기 위해 복사를 하고 `run()` 함수를 실행합니다. SimProcedure를 실행하는 프로세스는 반드시 SimProcedure에서 상태를 변경해야하기 때문에 각 단계마다 별도의 인스턴스가 필요하므로 실행될 때마다 SimProcedure의 새 인스턴스를 만드는 것이 중요합니다.


#### kwargs

계층 구조는 단일 SimProcedure를 여러개의 후킹에서 사용할 수 있습니다. 같은 `SimProcedure`를 후킹하고 싶을 때 `run()`의 args를 추가하면 됩니다.


### 데이터 타입

위 예제를 보면 `run()` 함수의 인자 값을 추력하면 바뀐 `<<SAO <BV64 0xSTUFF>>` 클래스가 출력된 것을 볼 수 있습니다. 이것은 `SimActionObject`입니다.
SimProcedure에서 정확이 어떤 것을 해야할지 추적하고 정적분석에 도움을 줍니다.

또한 프로시저에서 Pyhon int `0`을 반환 된 것을 볼 수 있습니다. 자동으로 word 크기의 bitvector로 확장됩니다. native 수, bitvector, SimActionObejct가 반환됩니다.

부동 소수점을 처리하는 프로시저를 작성하려면 호출 규약을 수동으로 지정해야 합니다. cc에서 후킹을 제공합니다. : [`cc=project.factory.cc_from_arg_kinds((True, True), ret_fp=True)`](http://angr.io/api-doc/angr.html#angr.factory.AngrObjectFactory.cc_from_arg_kinds) 및 `project.hook(address, ProcedureClass(cc=mycc))`

### 제어흐름

SimProcedure를 종료하려면 `run()`에서 반환하면 됩니다. `self.ret(value)`를 호출하는 약어입니다. `self.ret()`는 함수에서 특정 작업을 수행하는 방법을 알고있는 함수입니다.

 - `ret(expr)` : 함수에서 반환
 - `jump(addr)` : 해당 주소로 점프
 - `exit(code)` : 프로그램 종료
 - `call(addr, args, continue_at)` : 함수 호출
 - `inline_call(procedure, *args)` : SimProcedure를 호출하고 결과를 반환.

#### 조건부 이탈

SimProcedure에서 조건 분기를 추가하려면 현재 실행 단계에서 SimSuccessor 객체로 직접 작업해야 합니다.

이를 위한 인터페이스는 [`self.successors.add_successor(state, addr, guard, jumpkind)`](http://angr.io/api-doc/angr.html#angr.engines.successors.SimSuccessors.add_successor)입니다.

매개변수가 의미가 있어야 합니다. 통과한 상태는 복사되지 않으며 많은 작업을 할 경우 미리 사본을 만들어야 합니다.


#### SimProcedure 연속

이전 함수를 호출하고 SimProcedure가 실행을 다시 하려면 `self.call(addr, args, continue_at)`를 사용하면 됩니다. `addr`은 호출하고자하는 주소이며, `args`는 인자값의 튜플입니다. `continue_at`은 다른 함수의 SimProcedure 클래스의 이름입니다. 호출 규약으로 `cc`를 전달하여 호출 상대와 통신해야 합니다.

이렇게 하면 현재 단계에서 종료하고 다음 단계에서 다시 시작합니다. 함수가 복귀되면 특정 주소로 돌아가야 합니다. 이 주소는 SImProcedure 런타임에 의해 지정됩니다. 주소는 지정된 함수 호출로 돌아가기 위해 angr의 externs 세그먼트에 할당 합니다. 그 후, `run()` 대신 지정된 `continue_at` 함수를 실행하기 위해 복사가 완료된 인스턴스에 후킹됩니다. 

서브 시스템을 사용하려면 SimProcedure 클래스에 연결해야 하는 2개의 메타데이터가 있습니다.

 - 클래스 변수 `IS_FUNCTION = True`로 설정합니다.
 - 클래스 변수 `local_vars`를 문자열 튜플로 설정합니다. 각 문자열은 반환 된 경우 저장할 값을 갖는 SimProcedure에서 인스턴스 변수의 이름입니다. 지역 변수는 인스턴스를 변경하지 않는 한 어떠한 형태라도 상관없습니다.

데이터를 저장하기 위해 어떤 종류의 보조 기억 장치가 있는지 짐작하고 있을 겁니다. 상태 플러그인 `state.callstack`은 현재의 호출 프레임에 위치 정보를 저장하는데 SimProcedure 런타임에 의해 사용되는 `.procedure_data`라는 항목이 있습니다. angr는 `state.callstack`의 로컬 데이터 저장소를 위해 스택 포인터를 추적합니다. 스택 프레임의 메모리에 저장해야 하는 것이지만 데이터 직렬화 및 메모리 할당이 어렵습니다.

예로 angr가 Linux 프로그램 `full_init_state`를 위해 모든 공유 라이브러리 초기화를 실행하기 위해 내부적으로 사용하는 SimProcedure를 보도록 하겠습니다.

```python
class LinuxLoader(angr.SimProcedure):
    NO_RET = True
    IS_FUNCTION = True
    local_vars = ('initializers',)

    def run(self):
        self.initializers = self.project.loader.initializers
        self.run_initializer()

    def run_initializer(self):
        if len(self.initializers) == 0:
            self.project._simos.set_entry_register_values(self.state)
            self.jump(self.project.entry)
        else:
            addr = self.initializers[0]
            self.initializers = self.initializers[1:]
            self.call(addr, (self.state.posix.argc, self.state.posix.argv, self.state.posix.environ), 'run_initializer')
```

이것은 SimProcedure 연속의 사용법입니다. 먼저 프로젝트가 프로시저 인스턴스에서 사용가능한지 살펴봐야 합니다. 안전성을 위해서 일반적으로 프로젝트를 읽기 전용 또는 추가 전용 데이터 구조로 사용합니다. 여기에서 로더에서 동적 이니셜 라이저 목록을 검색하면 됩니다. 목록이 비어있지 않으면 목록에서 하나의 함수 포인터를 가져옵니다. 그리고 그것을 호출하고 `run)initializer` 함수로 돌아갑니다.

### 전역 변수

간단히 말하면 전역 변수를 `state.globals`에 저장할 수 있습니다. SimProcedure 연속의 로컬 변수와 동일한 규칙이 적용됩니다. 정확히 모른다면 전역 변수로 사용되는 항목을 변경하지 않도록 해야합니다.


### 정적 분석 도움

이미 클래스 변수 `IS_FUNCTION`을 봤습니다. SimProcedure 연속을 사용할 수 있습니다. 설정 가능한 클래스 변수가 있지만 이 함수는 직접적인 것은 없습니다. 함수의 속성을 표시하고 정적 분석이 무엇을 하는지만 알 수 있습니다.

 - `NO_RET` : 제어 흐름이 함수에서 돌아오지 않는 경우 이를 true로 설정합니다.
 - `ADDS_EXITS` : 반환 이외의 제어 흐름을 실행하려면 true로 설정합니다.
 - `IS_SYSCALL` : syscall인지 확인합니다.

또한 `ADDS_EXITS`를 설정한 경우 `static_exits()` 함수를 정의 할 수 있습니다. 이 함수는 실행시 IRSB 목록인 단일 매개 변수를 취하고 그 경우 함수가 생성하는 것으로 보입니다. 반환 값은 (address(int) jumpkind(str)) 튜플로 예상 됩니다.


### 유저 후킹

SimProcedure를 설명하고 사용하는 과정은 함수 전체에 연결하는 것을 전제로 하고 있습니다. 코드 섹션을 연결하는 프로세스를 간소화하기 유저 후킹이 있습니다.

```python
>>> @project.hook(0x1234, length=5)
... def set_rax(state):
...     state.regs.rax = 1
```

SimProcedure의 서브 클래스 전체가 아닌 하나의 함수를 사용하는 것입니다. 인자 값을 가져오는 것은 실행되지 않고 복잡한 제어 흐름은 발생하지 않습니다.

제어 흐름은 length 인자 값에서 제어됩니다. 이 예제에서는 함수의 실행이 완료되면 후킹된 주소에 다섯 바이트 후에 다음 단계가 시작됩니다. length 인자가 생략되어 있거나 0으로 설정된 경우, 후킹을 다시 하지 않고 바이너리 코드의 실행이 후킹된 주소에서 다시 시작합니다. `Ijk_NoHook` 점프는 이것을 가능하게 합니다.

만약 유저 후킹에서 나오는 제어 흐름을 효율적으로 관리하고 싶은 경우 다음 상태의 목록을 반환할 수 있습니다. 다음 상태는 `state.regs.ip`, `state.scratch.guard`, `state.scratch.jumpkindset`이 필요합니다.

### 심볼 후킹

[바이너리 로드](https://docs.angr.io/docs/loading.html)를 다시 생각해 봅시다. 동적 링킹된 프로그램은 종송성으로 라이브러리에서 가져와야 하는 목록을 갖고 있습니다.
`project.hook_symbol` API를 사용해 주소 연결을 할 수 있습니다.

```python
>>> class NotVeryRand(SimProcedure):
...     def run(self, return_values=None):
...         if 'rand_idx' in self.state.globals:
...             rand_idx = self.state.globals['rand_idx']
...         else:
...             rand_idx = 0
... 
...         out = return_values[rand_idx % len(return_values)]
...         self.state.globals['rand_idx'] = rand_idx + 1
...         return out

>>> project.hook_symbol('rand', NotVeryRand(return_values=[413, 612, 1025, 1111]))
```


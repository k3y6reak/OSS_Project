# 3_Advanced topics

## Understanding the Execution Pipeline

만약 이것을 만드는데 코어에 대한 지식이 거의 없다면, angr는 매우 유연하고 강렬한 에뮬레이터입니다. 가장 많은 효과를 얻으려면,  `path_group.step()`을 말할때마다 어떤 일이 일어나는지 알고 싶을 것입니다. 
이것은 더 진보된 문서로 만들 생각입니다; `PathGroup`, `ExplorationTechnique`, `Path`, `SimState` 및 `SimEngine`의 기능과 의도를 이해해야만 지금 무엇에 관해 말하려는지 이해할 수 있을 것입니다!  이제 angr 소스를 열어서 이 작업을 수행할 수 있습니다.

### Path Groups

첫 발을 내딛어보죠.

#### `step()`

`PathGroup.step()` 함수는 많은 선택적 파라미터를 가지고 있습니다. 이 중 가장 중요한 것은 `stash`, `n`, `until`과 `step_func`입니다. `n`은 즉시 사용됩니다. `step()` 함수는 `_one_step()` 함수를 호출하고 n 단계가 발생하거나 다른 종료 조건이 발생할 때까지 모든 파라미터를 전달하면서 루프를 반복합니다. n이 제공되지 않으면 until 함수가 제공되지 않는 한 1이 default 값입니다. 이 경우 until은 100000 - 무한입니다.

그러나 종료 조건을 확인하기 전에 `step_func`가 적용됩니다. 이 함수는 현재 경로의 그룹을 가져오고, 새로운 경로 그룹을 반환하여 이를 대체합니다. step function을 작성할 때 대부분의 공통 경로 그룹 함수가 경로 그룹을 반환한다는 점을 상기하는 것이 유용합니다 - 만약 경로 그룹이 변경 불가능할 경우(생성자에서 `immutable=True`), 새 오브젝트이지만 그것은 이전과 같은 동일한 오브젝트입니다.

이제 종료 조건을 확인해봅시다 - 우리가 작업중인 stash("active"가 default)가 비었거나, `until` 콜백 함수가 True를 반환할 때입니다. 만약 이러한 조건이 모두 충족되지 않을 경우, `_one_step()`을 다시 호출하기 위해 루프백합니다.

#### `_one_step()`

이것은 ExplorationTechnique가 무언가에 영향을 끼칠 수 있는 곳입니다. 만약 어떤 exploration technique가 `step` override를 제공했다면, 이것이 어디선가 호출되었다는 것입니다. 이 기술이 영리한 점은 이들의 효과가 결합될 수 있다는 점입니다. 어떻게 이런 일이 가능한걸까요? `step`을 구현하는 exploration technique에는 경로 그룹이 주어지며, 새 경로 그룹을 반환하고, 아주 약간 전진하며 exploration technique의 효과를 적용시킵니다. 이것은 필연적으로 경로 그룹에서 `step()`을 호출하는 exploration technique와 관련됩니다. 그러면 이 문서가 다시 시작하면서 설명하는 사이클은 프로세스가 `_one_step()`에 도달했을 때를 제외하고 현재 exploration technique가 스텝 콜백의 리스트에서 튀어나온다는 것입니다. 이런 스텝 콜백을 제공하는 exploration technique들이 더 많이 있다면, 다음 것이 호출되며 리스트가 빌 때까지 반복합니다. 콜백에서 반환이 되면, `_one_step`은 콜백을 콜백 스택으로 푸시하고 반환합니다.

요약하자면, 스텝 콜백을 제공하는 exploration technique는 다음과 같이 처리됩니다:
* 엔드 유저가 `step()`을 호출
* `step()`이 `_one_step()`을 호출
* `_one_step()`이 active `step` exploration technique 콜백 리스트로부터 단일 exploration technique를 꺼내고, 현재 작업중인 경로 그룹으로 호출
* 이 콜백은 호출 된 경로 그룹에서 `step()`을 호출
* 이 프로세스는 더 이상의 콜백이 없을 때까지 반복

일단 스텝 콜백이 더이상 없거나 시작하는 스텝 콜백이 더이상 없을 경우 디폴트 스테핑 프로시저로 돌아갑니다. 여기에는 원래 `PathGroup.step()` - `selector_func`에 전달되었던 파라미터가 하나 더 포함됩니다.  만약 존재하는 경우에는, 우리가 실제로 작동할 작업 stash의 경로를 필터링하는 데 사용됩니다. 이 각각의 경로에 대해 `PathGroup._one_path_step()`을 호출하여 아직 사용되지 않은 모든 파라미터를 다시 전달합니다. `_one_path_step()`은 해당 경로를 스테핑 한 경로(normal, unconstrained, unsat, pruned, errored)를 분류한 리스트의 튜플을 반환합니다. 유틸리티 함수인 `PathGroup._record_step_results()`는 이러한 목록들을 작업하여 경로 그룹에 포함된 stash들의 새로운 집ㅎ바을 반복하여 작성하고, exploration technique가 제공할 수 있는 필터 콜백을 적용합니다.

#### _one_path_step()

PathGroup에 대한 전반을 거의 다 만들었습니다. 먼저, `step_path` exploration technique hook을 적용해야합니다. 이러한 hook은 스텝 콜백만큼 예쁘게 적용되지는 않습니다. 단 하나만 적용할 수 있으며, 나머지는 실패한 경우에만 사용됩니다. `step_path` hook가 성공하면 `_one_path_step()`에서 즉시 결과가 반환됩니다. 필터 콜백에 대한 요구사항은 `_one_path_step()`이 반환해야하는 리스트와 동일한 튜플을 반환하는 것입니다. 이들 모두가 실패하거나, 더이상 시작할 것이 없다면 다시 default 프로시저로 돌아갑니다.

Note: 공식 문서에서 리팩토링 예정입니다.

먼저, 이 경로에 에러가 있는지 확인합니다. 이 작업은 `check_func` 파라미터를 통해 `step()`으로 진행되며, `_one_path_step()`으로 완전히 전달되거나 해당 함수가 제공되지 않으면 `errored` 속성을 통해 경로가 전달됩니다. 경로에 오류가 발생하면 이는 즉시 중단되고, errored stash에 경로를 표시합니다. 그리고 다음 경로로 이동합니다. 만약 `successor_func`가 `step()`에 대한 파라미터로 제공되면 사용됩니다 - "normal" successor의 리스트를 반환합니다. 만약 파라미터가 제공되지 않으면 경로에서 `step()`을 호출합니다. 이 함수는 normal successor의 리스트를 반환하는 동일한 속성을 갖습니다. 그리고 다음 경로의 `unconstrained_successors`와 `unsat_successors` 속성에 접근하여 해당하는 리스트들을 검색합니다. 이들이 모두 거대한 튜플의 적절한 위치에 반환됩니다.

### Paths

Path는 약간 재앙이며, 곧 사라질 것입니다. 현재로서는 `Path.step()`에 대한 대부분의 파라미터를 successor generation 프로세스로 전달한 다음 successor 각각을 가져와서 새 경로로 매핑한다는 것만 알면 될 것입니다. 그리고 그 방법에 따라 error-catching을 수행하고 실행 계보에 대한 일부 메타데이터를 효율적으로 기록합니다. kicker는 `step()`이 호출되면 Path가 결국 `project.factory.successors (state, **kwargs)`를 호출한다는 것입니다.

### Engine Selection

바라건대, angr 문서는 당신이 이 페이지에 도달할 때까지 `SimEngine`이 어떻게 상태를 취하고 successor를 생성할지 알고 있는 장치라는 것을 안다고 생각하겠습니다. 어떤 엔진을 사용할 지 어떻게 알 수 있을까요? 각각의 프로젝트는 `factory`에서 엔진 목록을 가지고 있으며, `project.factory.successors`의 기본 동작은 작업의 첫번째 결과를 순서대로 모두 가져오는 역할을 합니다. 물론 이 동작을 변경할 수 있는 몇가지 방법이 있습니다.

* `default_engine=True` 매개변수가 전달되면 시도 할 엔진은 일반적으로 last-resort default 엔진인 `SimEngineVEX`입니다.
* 리스트가 매개변수 엔진에서 전달되면 기본 엔진 목록 대신 사용됩니다.

기본 엔진 목록은 기본적으로 다음과 같습니다.

* `SimEngineFailure`
* `SimEngineSyscall`
* `SimEngineHook`
* `SimEngineUnicorn`
* `SimEngineVEX`

각 엔진에는 `check()` 메소드가 있습니다. 이는 사용하는 것이 적절한지 신속하게 판별합니다. 만약 `check()`가 통과되면 `process()`가 실제로 successor를 생성하는데 사용됩니다. 반면 `check()`가 통과되더라도 `.processed` 속성이 `False`로 설정된 `SimSuccessors` 객체를 반환하면 `process()`가 실패할 수 있습니다. 이 두 메소드는 모두 쌓여있는 프로시저들의 우위에 의해 아직 필터링되지 않은 모든 키워드 인수의 파라미터로 전달됩니다. 유용한 파라미터 중 일부는 `addr`과 `jumpkind`이며, 일반적으로 상태에 대해 추출되는 각 정보에 대한 override로 사용됩니다.

마지막으로 엔진이 상태를 처리하면 시스템 콜의 경우 명령 포인터를 수정하기 위해 결과가 잠시 후 처리됩니다. 실행이 `ljk_Sys*`라는 jumpkind와 함께 종료되면 `SimOS`를 호출하고, 현재 syscall에 대한 주소를 검색합니다. 그리고 결과 상태의 명령 포인터가 해당 주소로 변경됩니다. 원래 주소는 `ip_at_syscall`이라는 상태 레지스터에 저장됩니다. 이것은 순수한 실행에는 필요하지 않지만 정적 분석에서는 syscall을 일반 코드와 별도의 주소에 두는 점에서 유용합니다.

### Engines

`SimEngineFailure`는 에러 케이스를 처리합니다. 이전의 jumpkind가 `ljk_EmFail`, `ljk_Sig*`, `ljk_NoDecode`(주소가 연결되지 않은 경우에만 해당) 또는 `ljk_Exit` 중 하나일 때만 사용됩니다. 처음 네가지 경우는 예외를 발생시키는 행동을 합니다. 마지막 경우는 successor를 단순히 생성하지 않는 방식입니다.

`SimEngineSyscall`은 syscall을 서비스합니다. 이전의 jumpkind가 `ljk_Sys*` 형식의 항목일 때 사용됩니다. `SimOS`를 호출하여 syscall에 응답하면서 실행해야하는 `SimProcedure`를 검색한 다음 실행합니다. 매우 간단하죠!

`SimEngineHook`은 angr에서 후킹 기능을 제공해줍니다. 상태가 후킹된 주소에 있고 이전 jumpkind가 `ljk_NoHook`이 아닌 경우에 사용됩니다. 단순히 주어진 훅을 찾고, SimProcedure 인스턴스를 검색하기 위해 `hook.instantiate()`를 호출한 다음 해당 프로시저를 실행합니다. 이 클래스는 후킹을 위해 특수화된 `SimEngineProcedure` 클래스의 하위 서브클래스입니다. 파라미터 프로시저가 필요하므로 항상 검사가 성공하게 되고, 훅에서 가져올 SimProcedure 대신 이 프로시저가 사용됩니다.

`SimEngineUnicorn`은 Unicorn Engine으로 구체적인 실행을 수행합니다. 상태 옵션인 `o.UNICORN`이 활성화되었을 때 사용되고, 최대 효율성을 위해 설계된 다른 조건이 충족될 때 사용됩니다.(아래 설명 참조)

`SimEngineVEX`는 큰 역할을 합니다. 이전의 항목들을 사용할 수 없을 때마다 사용됩니다. 현재 주소에서 IRSB로 바이트를 lift 시도한 다음 IRSB를 symbolic하게 실행합니다.  이 프로세스를 제어할 수 있는 많은 파라미터가 있으므로 [API reference](http://angr.io/api-doc/angr.html#angr.engines.vex.engine.SimEngineVEX.process) 참조하세요.

`SimEngineVEX`가 IRSB를 파면서 실행하는 정확한 프로세스는 문서화가 잘 되어있습니다.

### Engine instances

스테핑 프로세스에 대한 파라미터 외에도 이 엔진들의 새로운 버전을 인스턴스화 할수도 있습니다. 각 엔진이 어떤 옵션을 사용할 수 있는지 확인하려면 API 문서를 참조하세요. 새 엔진 인스턴스가 생기면 step 프로세스로 전달하거나 자동으로 사용되도록 `project.factory.engines` 목록에 직접 입력할 수도 있습니다.

## When using Unicorn Engine

`o.UNICORN` 상태에 옵션을 추가하면 모든 단계에서 `SimEngineUnicorn`이 호출되며, 구체적으로 Unicorn을 사용하여 실행되는지 확인할 수 있습니다.

보통 원하는 것은 미리 정의된 `o.unicorn`(소문자) 옵션 세트를 프로그램의 상태에 추가하는 것이겠죠.

```
unicorn = { UNICORN, UNICORN_SYM_REGS_SUPPORT, INITIALIZE_ZERO_REGISTERS, UNICORN_HANDLE_TRANSMIT_SYSCALL }
```

이것들은 당신의 경험을 크게 향상시킬 몇 가지 추가 기능과 default값들을 가능하게 할 것입니다. 또한 `state.unicorn` 플러그인에서 조정할 수 있는 많은 옵션이 있습니다.

unicorn이 작동하는 방식을 이해하는 좋은 방법은 로그를 출력하면서 확인하는 것입니다.

`(logging.getLogger('angr.engines.unicorn_engine').setLevel('DEBUG');`
 `logging.getLogger('angr.state_plugins.unicorn_engine').setLevel('DEBUG')`을 unicorn에서 실행한 샘플입니다.
```
INFO    | 2017-02-25 08:19:48,012 | angr.state_plugins.unicorn | started emulation at 0x4012f9 (1000000 steps)
```

여기서 angr은 0x4012f9의 기본 블록부터 unicorn 엔진으로 전환됩니다. 최대 단계 수는 1000000으로 설정되어 있으므로 실행하는동안 Unicorn에서 1000000 블록 동안 유지되면 자동으로 튀어나옵니다. 이것은 무한 루프에 빠지는 것을 방지하기 위한 것입니다. 블록 수는 `state.unicorn.max_steps` 변수를 통해 구성할 수 있습니다.

```
INFO    | 2017-02-25 08:19:48,014 | angr.state_plugins.unicorn | mmap [0x401000, 0x401fff], 5 (symbolic)
INFO    | 2017-02-25 08:19:48,016 | angr.state_plugins.unicorn | mmap [0x7fffffffffe0000, 0x7fffffffffeffff], 3 (symbolic)
INFO    | 2017-02-25 08:19:48,019 | angr.state_plugins.unicorn | mmap [0x6010000, 0x601ffff], 3
INFO    | 2017-02-25 08:19:48,022 | angr.state_plugins.unicorn | mmap [0x602000, 0x602fff], 3 (symbolic)
INFO    | 2017-02-25 08:19:48,023 | angr.state_plugins.unicorn | mmap [0x400000, 0x400fff], 5
INFO    | 2017-02-25 08:19:48,025 | angr.state_plugins.unicorn | mmap [0x7000000, 0x7000fff], 5
```

angr는 unicorn 엔진이 접근할 때 엑세스하는 데이터의 지연 매핑을 수행합니다. 0x401000은 실행중인 명령어들의 페이지이고, 0x7fffffffffe0000은 스택입니다. 이 페이지 중 일부는 symbolic입니다.  즉, 액세스 할 때 Unicorn에서 실행이 중단되는 데이터가 적어도 일부는 포함되어 있는 것을 의미합니다.

```
INFO    | 2017-02-25 08:19:48,037 | angr.state_plugins.unicorn | finished emulation at 0x7000080 after 3 steps: STOP_STOPPOINT
```

실행은 3개의 basic block(계산 된 낭비, 필요한 설정 등을 고려하는 것)을 위해 Unicorn에서 머무르며, 그 이후 simprocedure의 위치에 도달하고 angr에서 simproc을 실행하기 위해 점프합니다.

```
INFO    | 2017-02-25 08:19:48,076 | angr.state_plugins.unicorn | started emulation at 0x40175d (1000000 steps)
INFO    | 2017-02-25 08:19:48,077 | angr.state_plugins.unicorn | mmap [0x401000, 0x401fff], 5 (symbolic)
INFO    | 2017-02-25 08:19:48,079 | angr.state_plugins.unicorn | mmap [0x7fffffffffe0000, 0x7fffffffffeffff], 3 (symbolic)
INFO    | 2017-02-25 08:19:48,081 | angr.state_plugins.unicorn | mmap [0x6010000, 0x601ffff], 3
```

simprocedure 이후에 실행은 Unicorn으로 점프하여 돌아옵니다.

```
WARNING | 2017-02-25 08:19:48,082 | angr.state_plugins.unicorn | fetching empty page [0x0, 0xfff]
INFO    | 2017-02-25 08:19:48,103 | angr.state_plugins.unicorn | finished emulation at 0x401777 after 1 steps: STOP_EXECNONE
```

바이너리가 zero-page에 접근했기 때문에 실행은 거의 바로 Unicorn에서 나타납니다.

```
INFO    | 2017-02-25 08:19:48,120 | angr.engines.unicorn_engine | not enough runs since last unicorn (100)
INFO    | 2017-02-25 08:19:48,125 | angr.engines.unicorn_engine | not enough runs since last unicorn (99)
```

쓰레싱과 Unicorn(비용이 큼)에서 벗어나기 위해 Unicorn으로 다시 진입하기 전에 특정 조건(i.e. X 블록에 대한 symbolic 메모리 액세스 없이)을 기다리는 cooldown(`state.unicorn` 플로그인의 속성)이 있습니다. unicorn의 실행은 simprocedure 또는 syscall 이외에 다른 조건 때문에 중단됩니다. 여기서 100블록만큼 기다리기 위한 조건은 점프해서 돌아오기 전에 점프하는 것입니다.
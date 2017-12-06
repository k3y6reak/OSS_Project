# 3_Advanced topics

## Gotchas when using angr

이번 섹션에서는 angr에서 users/victims가 자주 실행되는 gotchas의 리스트가 포함되어있습니다.

### SimProcedure inaccuracy

symbolic execution을 하기 쉽게 만들기 위해 angr은 common library function을 파이썬으로 작성한 summary들로 교체합니다. 이러한 summary들을 SimProcedures라고 부릅니다. SimProcedures는 symbolic string에서 실행되는 `strlen`과 같이 path explosion를 막아줍니다.

1. SimProcedure를 비활성화 하세요([angr.Project class](http://angr.io/api-doc/angr.html#module-angr.project)에 옵션을 전달하여 특정 SimProcedures를 제외할 수 있습니다). 이것은 문제의 함수에 대한 입력을 제한하는 것에 매우 주의하지 않는 한 path explosion으로 이어질 가능성이 있다는 단점이 있습니다. path explosion은 Veritesting과 같은 다른 angr 기능을 통해 부분적으로 막을 수 있습니다.
2. SimProcedure를 문제의 상황에 직접 작성된 것으로 대체하세요. 예를 들어, 우리의 scanf 구현은 완벽하지 않지만 알려진 format string의 단일 문자열을 지원하기만 하면 정확히 수행 할 hook를 작성할 수 있습니다.
3. SimProcedure를 수정하세요.

### Unsupported syscalls

시스템 콜은 SimProcedures로 구현됩니다. 안타깝게도 angr에서는 아직 구현되지 않은 시스템 콜이 존재합니다. 지원되지 않는 시스템 콜은 몇 가지 해결 방안이 있습니다.

1. 시스템 콜을 구현하세요. TODO: 추후 공식 문서 업데이트 예정
2. `project.hook`를 사용하여 callsite를 ad-hoc 방식으로 상태에 필요한 수정을 하기 위해 후킹합니다.
3. syscall 반환 값을 큐에 넣으려면 `state.posix.queued_syscall_returns` 리스트를 사용하세요. 만약 반환 값이 큐에 있다면 시스템 콜이 실행되지 않고 해당 값이 대신 사용됩니다. 게다가 함수를 "반환 값"으로 대신 큐에 넣을 수 있으므로 시스템 콜이 트리거 될 때 함수가 그 상태에 적용됩니다.

### Symbolic memory model

angr에서 사용하는 기본 메모리 모델은 [Mayhem](https://users.ece.cmu.edu/~dbrumley/pdf/Cha%20et%20al._2012_Unleashing%20Mayhem%20on%20Binary%20Code.pdf)에서 영감을 얻었습니다. 이 메모리 모델은 제한된 symbolic R/W를 지원합니다. 읽기의 메모리 인덱스가 symbolic이고 이 인덱스의 가능한 범위 값의 범위가 너무 넓으면 인덱스는 단일 값으로 구체화됩니다. 쓰기의 메모리 인덱스가 전반적으로 symbolic이라면 인덱스는 단일 값으로 구체화됩니다. 이것은 `state.memory`의 메모리 구체화 전략을 변경하여 구성할 수 있습니다.

### Symbolic lengths

SimProcedures와 특히 `read()`및 `write()`와 같은 시스템 콜은 버퍼의 길이가 symbolic인 상황으로 진행될 수 있습니다. 일반적으로 이것을 처리하는 것은 매우 어렵습니다: 많은 경우에, 이 길이는 나중에 실행 단계에서 철저하게 구체화되거나 소급적으로 구체화됩니다. 심지어 그렇지 않은 경우에도 원본 또는 대상 파일이 약간 "이상하게" 보일 수 있습니다.
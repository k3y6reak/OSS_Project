# 6_Appendix

## List of State Options

### State Modes

이것들은 `mode = xxx`를 상태 생성자에 건네주면서 가능합니다.

| 모드 이름 | 설명 |
| --- | --- |
| `symbolic` | 기본 모드. 대부분의 에뮬레이션 및 분석 작업에 유용 |
| `symbolic_approximating` | symbolic 모드. 제약 조건 해결에 대한 근사값을 사용할 수 있음 | 
| `static` | 정적 분석에 유용한 설정. 메모리 모델은 추상적인 영역 매핑 시스템이 되고, 호출을 건너 뛰는 "후위 반환" successor가 추가됨 |
| `fastpath` | 매우 가벼운 정적 분석을 위한 설정. 실행은 코드의 동작을 빠르게 살펴볼 수 있도록 모든 집중적인 처리를 건너뜀 |
| `tracing` | 주어진 입력을 가진 프로그램을 통해 구체적으로 실행하기 위한 설정. unicorn을 활성화하고 resilience 옵션을 활성화하며 access violation을 올바르게 에뮬레이트 하려고 시도 |

### Option Sets

이들은 `angr.option.xxx`와 같은 옵션 세트입니다.

| 세트 이름 | 설명 |
| --- | --- |
| `common_options` | 기본 실행에 필요한 옵션 |
| `symbolic` | 기본 symbolic 실행에 필요한 옵션 |
| `resilience` | 지원되지 않은 작업에 대한 angr의 에뮬레이션을 강화하고, 결과를 unconstrained symbolic value로 처리하고, `state.history.events`에 상황을 기록하여 계속 수행하려고 시도하는 옵션 |
| `refs` | angr이 `history.actions`의 종속성 정보로 완료되는 모든 메모리, 레지스터 및 임시 참조의 로그를 유지하도록 하는 옵션. 메모리 소비 큼 |
| `approximation` | z3를 호출하는 대신 value-set 분석을 통해 제약 조건의 근사치를 해결할 수 있는 옵션 |
| `simplification` | 메모리 또는 레지스터 저장 공간에 도달하기 전에 z3의 단순화기를 통해 데이터를 실행하는 옵션 |
| `unicorn` | concrete 데이터에서 실행되도록 unicorn 엔진을 활성화하는 옵션 |

### Options

이들은 개별 옵션 개체로 `angr.options.XXX`로 사용합니다.

| 옵션 이름 | 설명 | 세트 | 모드 | 비고 |
| --- | --- | --- | --- | --- |
| `ABSTRACT_MEMORY` | `SimAbstractMemory`를 사용하여 메모리를 개별 영역으로 모델링 | | `static` | |
| `ABSTRACT_SOLVER` | 단순화 도중 제약 조건 세트의 분할을 허용 | | `static` | |
| `ACTION_DEPS` | `SimActions`의 종속적 추적 | | | |
| `APPROXIMATE_GUARDS` | 방어 조건을 평가할 때 VSA 사용 | | | |
| `APPROXIMATE_MEMORY_INDICES` | 메모리 indice를 평가할 때 VSA 사용 | `approximation` | `symbolic_approximating` | |
| `APPROXIMATE_MEMORY_SIZES` | 메모리 load/store 크기를 평가할 때 VSA 사용 | `approximation` | `symbolic_approximating` | |
| `APPROXIMATE_SATISFIABILITY` | 상태 안정성을 평가하기 위해 VSA 사용 |  `approximation` | `symbolic_approximating` | |
| `AST_DEPS` | 모든 명확한 AST에 대한 종속성 추적을 가능하게 함 | | | During execution |
| `AUTO_REFS` | `SimProcedures`에서 종속성을 추적하는데 사용되는 내부 옵션 | | | During execution |
| `AVOID_MULTIVALUED_READS` | 기호화된 주소를 가진 읽기에 대해 메모리를 건드리지 않고 기호 값을 반환 | | `fastpath` | |
| `AVOID_MULTIVALUED_WRITES` | 기호화된 주소를 가진 쓰기를 수행하지 않음 | | `fastpath` | |
| `BEST_EFFORT_MEMORY_STORING` | 실제로 작아보이지만 큰 심볼 사이즈의 쓰기를 다룸 | | `static`, `fastpath` | |
| `BLOCK_SCOPE_CONSTRAINTS` | 각 블록 끝에 있는 제약 리스트 제거 | | `static` | |
| `BREAK_SIRSB_END` | 디버그 : 각 블록의 끝에 breakpoint 트리거 | | | |
| `BREAK_SIRSB_START` | 디버그 : 각 블록 시작에 breakpoint 트리거 | | | |
| `BREAK_SIRSTMT_END` | 디버그 : 각 IR문의 끝에 breakpoint 트리거 | | | |
| `BREAK_SIRSTMT_START` | 디버그 : 각 IR문의 시작에 breakpoint 트리거 | | | |
| `BYPASS_ERRORED_IRCCALL` | unconstrained symbolic value를 반환해서 실패한 helper 처리 | `resilience` | `fastpath`, `tracing` | |
| `BYPASS_ERRORED_IROP` | unconstrained symbolic value를 반환해서 실패한 작업 처리 | `resilience` | `fastpath`, `tracing` | |
| `BYPASS_UNSUPPORTED_IRCCALL` | unconstrained symbolic value를 반환해서 지원되지 않은 helper 처리 | `resilience` | `fastpath`, `tracing` | |
| `BYPASS_UNSUPPORTED_IRDIRTY` | unconstrained symbolic value를 반환해서 지원되지 않은 더티 helper 처리 | `resilience` | `fastpath`, `tracing` | |
| `BYPASS_UNSUPPORTED_IREXPR` | unconstrained symbolic value를 반환해서 지원되지 않은 IR식 처리 | `resilience` | `fastpath`, `tracing` | |
| `BYPASS_UNSUPPORTED_IROP` | unconstrained symbolic value를 반환해서 지원되지 않은 연산 처리 | `resilience` | `fastpath`, `tracing` | |
| `BYPASS_UNSUPPORTED_IRSTMT` | unconstrained symbolic value를 반환해서 지원되지 않은 IR식 처리 | `resilience` | `fastpath`, `tracing` | |
| `BYPASS_UNSUPPORTED_SYSCALL` | unconstrained symbolic value를 반환해서 지원되지 않는 syscall 처리 | `resilience` | `fastpath`, `tracing` | |

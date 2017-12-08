# 3_Advanced topics

## Symbolic memory addressing

angr은 symbolic memory addressing을 지원합니다. 즉 메모리로의 오프셋은 symbolic일 수 있습니다. 우리는 "Mayhem"에서 영감을 얻었습니다. 특히 이것은 angr이 symbolic address를 쓰기 대상으로 사용할 때 구체화된다는 것을 의미합니다. symbolic write를 순수하게 symbolic하게 다루거나 symbolic read를 취급하는것처럼 "symbolically"하게 기대하는 경향이 있기 때문에 약간 놀랐습니다. 그러나 이는 기본 기능이 아닙니다. 하지만 angr의 대부분의 것들처럼 이 또한 구성 가능합니다.

주소를 해석하는 동작은 구체화된 전략에 의해 관리되며, 구체화된 전략은 `angr.concretization_stategies.SimConcretizationStrategy`의 하위 클래스입니다. 읽기에 대한 구체화 전략은 `state.memory.read_strategies`에 설정되고 쓰기는 `state.memory.write_strategies`에 저장됩니다. 이러한 전략은 순서대로 호출되며, 그 중 하나가 symbolic index의 주소를 확인할 수 있습니다. 자신의 구체화 전략을 설정하거나(위에서 설명한 `SimInspect address_concretization` breakpoint를 이용) angr가 symbolic address를 해석하는 방법을 변경할 수 있습니다.

예를 들어 angr의 기본 구체화 전략은 아래와 같습니다.
1. `angr.plugins.symbolic_memory.MultiwriteAnnotation`으로 주석 처리된 모든 index에 대한 symbolic write(최대 128개의 가능한 솔루션 포함)을 허용하는 조건부 구체화 전략
2. symbolic index의 가능한 최대 해를 선택하는 구체화 전략
모든 인덱스에 대해 symbolic write를 가능하게 하려면 상태 생성 시 `SYMBOLIC_WRITE_ADDRESSES` 옵션을 추가하거나

`angr.concretization_strategies.SimConcretizationStrategyRange` 객체를 `state.memory.write_strategies`에 저장합니다. strategy 객체는 하나의 인수를 취하는데, 이것은 가능한 포기할 수 있는 최대 범위의 솔루션을 포기하고 다음(아마 non-symbolic) 전략으로 이동합니다.

## Writing concretization strategies

공식 문서 추가 예정
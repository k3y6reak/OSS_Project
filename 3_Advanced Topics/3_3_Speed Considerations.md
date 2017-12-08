# 3_Advanced topics

## Speed considerations

분석 도구 또는 에뮬레이터로서 angr의 속도는 파이썬으로 작성되었기 때문에 사실 좀 느립니다. 어쨌든, angr를 더 빠르게 하기 위한 최적화 옵션과 조정값들은 많이 존재합니다.

### General tips

* pypy를 사용하세요. [Pypy](http://pypy.org/)는 파이썬 코드를 최적화된 jitting을 수행하는 파이썬 인터프리터의 대체품입니다.
* 필요 없으면 공유 라이브러리를 로드하지 마세요. angr의 기본 설정은 OS 라이브러리에서 직접 로드하는 것을 포함하여 한 바이너리와 호환되는 공유 라이브러리를 찾기 위해 큰 비용을 들입니다. 이것은 많은 시나리오에서 상황을 복잡하게 만들 수 있죠. bare-bone symbolic execution보다 추상적인 분석을 수행할 경우, 특히 CFG를 만들 경우에는 다루기 쉽도록 정밀도를 희생시키려는 trade-off를 원할 수 있습니다. angr은 존재하지 않는 함수에 대한 라이브러리 호출이 발생할 때 수행하지 않습니다.
* 후킹과 SimProcedures를 사용하세요. 공유 라이브러리를 사용하는 경우에는 점프하려고 하는 복잡한 라이브러리 함수에 대해 SimProcedure를 작성해야합니다.
* SimInspect를 사용하세요. [SimInspect](https://docs.angr.io/docs/simulation.html#breakpoints)는 많이 사용되지 않지만 angr의 가장 강력한 기능 중 하낭비니다. 메모리 index 분석(angr에서 다소 느림)을 포함하여 거의 모든 angr 동작을 연결하고 수정할 수 있습니다.
* 구체적인 전략을 세우세요. 메모리 index 문제에 대한것 보다 더욱 효과적인 해결책은 전략을 구체화 하는 것입니다.
* 대체 Solver를 사용하세요. `angr.options.REPLACEMENT_SOLVER` 옵션을 사용하여 대체 Solver를 사용할 수 있습니다. 대체 솔버를 사용하면 solving time을 구체적으로 지정할 수 있습니다. 약간 문제가 있고 까다로운편이긴 하지만 좋은 해결책이 될 수 있을 것입니다.

### If you're performing lots of concrete or partially-concrete execution

* unicorn 엔진을 사용하세요. 만약 unicorn 엔진을 설치할 경우 구체적인 에뮬레이션을 위해 angr에서 얻는 이점이 많을 것입니다. 이를 활성화하려면 `angr.options.unicorn` 옵션을 추가하세요.
* fast memory와 fast register를 활성화하세요. `angr.options.FAST_MEMORY`와 `angr.options.FAST_REGISTERS`가 이를 도와줄 것입니다. 이것들은 메모리/레지스터를 정확도를 다소 포기하는 대신 속도를 향상시키는 메모리 모델을 사용합니다.
* 입력 시간을 최소화하세요. 실행하기 전에 입력을 대표하는 symbolic data로 `state.posix.files[0]`을 채운 다음 원하는 방식으로 symbolic data를 제한한 다음 구체적인 파일 크기를 설정합니다.(`state.posix.files[0].size = ???`)
* afterburner를 사용하세요. unicorn을 사용하는 동안 `UNICORN_THRESHOLD_CONCRETIZATION` 옵션을 추가하면 angr는 symbolic 값들을 구체화하여 unicorn에서 더 많은 시간을 할애할 수 있도록 임계 값을 늘립니다. 값의 종류는 아래와 같습니다.
	* `state.se.unicorn.concretization_threshold_memory`
	* `state.se.unicorn.concretization_threshold_registers`
	* `state.se.unicorn.concretization_threshold_instruction`
	* `state.se.unicorn.always_concretize`
	* `state.se.unicorn.never_concretize`
	* `state.se.unicorn.concretize_at`
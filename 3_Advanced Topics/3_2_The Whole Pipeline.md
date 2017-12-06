# 3_Advanced topics

## Understanding the Execution Pipeline

만약 이것을 만드는데 코어에 대한 지식이 거의 없다면, angr는 매우 유연하고 강렬한 에뮬레이터입니다. 가장 많은 효과를 얻으려면,  `path_group.step()`을 말할때마다 어떤 일이 일어나는지 알고 싶을 것입니다. 
이것은 더 진보된 문서로 만들 생각입니다; `PathGroup`, `ExplorationTechnique`, `Path`, `SimState` 및 `SimEngine`의 기능과 의도를 이해해야만 지금 무엇에 관해 말하려는지 이해할 수 있을 것입니다!  이제 angr 소스를 열어서 이 작업을 수행할 수 있습니다.

### Path Groups

첫 발을 내딛어보죠.

#### `step()`

`PathGroup.step()` 함수는 많은 선택적 파라미터를 가지고 있습니다. 이 중 가장 중요한 것은 `stash`, `n`, `until`과 `step_func`입니다. `n`은 즉시 사용됩니다. `step()` 함수는 `_one_step()` 함수를 호출하고 n 단계가 발생하거나 다른 종료 조건이 발생할 때까지 모든 파라미터를 전달하면서 루프를 반복합니다. n이 제공되지 않으면 until 함수가 제공되지 않는 한 1이 default 값입니다. 이 경우 until은 100000 - 무한입니다.

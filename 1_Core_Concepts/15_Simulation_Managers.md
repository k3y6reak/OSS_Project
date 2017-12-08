## Simulation Manager

angr에서 가장 중요한 제어 인터페이스는 SimulationManager입니다. 이를 사용하면 프로그램의 상태 공간을 탐색하기위한 검색 방법윽 적용하여 상태 그룹에 대한 symbolic execution을 동시에 제어할 수 있습니다.

Simulation Manager는 여러 상태를 다룰 수 있습니다. state는 숨겨져 있어 필터링하고 병합하고 원하는대로 이동할 수 있습니다.

### 단계

Simulation Manager는 `.step()`을 이용해 기본 블록에 의해 숨겨져있는 상태를 한 단계 이동시키는 것입니다.

```python
>>> import angr
>>> proj = angr.Project('examples/fauxware/fauxware', auto_load_libs=False)
>>> state = proj.factory.entry_state()
>>> simgr = proj.factory.simgr(state)
>>> simgr.active
[<SimState @ 0x400580>]

>>> simgr.step()
>>> simgr.active
[<SimState @ 0x400540>]
```

숨겨진 모델의 진정한 능력은 조건 분기문을 만나면 두가지 상태 모두 동기화 할 수 있다는 것입니다. 단계 별로 실행할 때 `.run()`을 사용할 수 있습니다.

```python
# Step until the first symbolic branch
>>> while len(simgr.active) == 1:
...    simgr.step()

>>> simgr
<SimulationManager with 2 active>
>>> simgr.active
[<SimState @ 0x400692>, <SimState @ 0x400699>]

# Step until everything terminates
>>> simgr.run()
>>> simgr
<SimulationManager with 3 deadended>
```

3개의 deadended 상태를 갖고 있습니다. 시스템의 `exit`에 도달했기 때문에 실행 중 다음 상태를 만들지 못하면 deadended가 출력됩니다.


### 은닉 관리

다른 은닉 방법을 살펴보겠습니다.

은닉된 것으로 이동할 경우 `.move()`를 사용할 수 있습니다.

```python
>>> simgr.move(from_stash='deadended', to_stash='authenticated', filter_func=lambda s: 'Welcome' in s.posix.dumps(1))
>>> simgr
<SimulationManager with 2 authenticated, 1 deadended>
```


### 은닉 타입

| 은닉 | 설명|
| --- | --- |
| active | 다음 은닉 상태가 존재합니다. |
| deadended | 상태가 더 이상 유효하지 않고 unsat 상태 또는 유효하지 않은 명령어 포인터를 포함 등 실행할 수 없는 상태. | 
| pruned | `LAZY_SOLVES`를 사용할 때 상태는 필요한 경우를 제외하고 만족 여부를 확인하지 않습니다. 상태가 unsat로 판명되면 언제 unsat 상태가 됐는지 탐색합니다. |
| unconstrained | save_unconstrained 옵션이 SimulationManager에 전달되면 명령 포인터를 사용해 제한되지 않은 상태가 만들어집니다. |
| unsat | `save_unsat` 옵션이 SimulationManager에 전달되면 만족할 수 없는 상태가 만들어집니다. |


### 단순 탐색

가장 일반적인 작업은 특정 주소에 도달하는 상태를 찾고 다른 주소를 통과하는 상태를 제거하는 것입니다. `.explore()` 함수를 이용해 경로를 찾습니다.

`find`를 사용하면 해당 주소로 이동할 수 있을 때 까지 만족하는 조건을 찾아 실행합니다. `avoid`는 해당 주소를 회피하는데 사용합니다.

간단한 [crackme](https://docs.angr.io/docs/examples.html#reverseme-modern-binary-exploitation---csci-4968)예제를 보겠습니다.

```python
>>> proj = angr.Project('examples/CSCI-4968-MBE/challenges/crackme0x00a/crackme0x00a')
>>> simgr = proj.factory.simgr()
>>> simgr.explore(find=lambda s: "Congrats" in s.posix.dumps(1))
<SimulationManager with 1 active, 1 found>
>>> s = simgr.found[0]
>>> print s.posix.dumps(1)
Enter password: Congrats!

>>> flag = s.posix.dumps(0)
>>> print(flag)
g00dJ0B!

```


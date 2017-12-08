# 2_Built-in Analyses

## 백워드 슬라이싱

프로그램 슬라이스는 일반적으로 0개 이상의 명령문을 제거하여 원본 프로그램으로부터 가져온 명령문의 하위 집합입니다. 슬라이싱은 디버깅과 프로그램을 이해하는데 종종 도움이 됩니다. 예를 들어, 일반적으로 프로그램 슬라이스에서 변수의 원천을 찾는 것이 더 쉽습니다.
`백워드슬라이스`는 프로그램의 대상에서 구성되며, 대상에서 이 슬라이스 끝의 모든 데이터 플로우를 나타냅니다.
angr은 백워드슬라이스라는 기본 내장 분석 기능이 있어 백워드 프로그램 슬라이스를 구성합니다. 이 섹션에서는 angr의 `백워드슬라이스` 분석이 어떻게 동작하는지, 그리고 구현 선택과 제약 사항에 대한 심도 깊은 토론이 이어집니다.

### First Step First

`백워드슬라이스`를 만들기 위해서는 아래의 정보들을 입력해야합니다.
* **Required** CFG.  프로그램의 CFG. 이 CFG는 반드시 accurate CFG(CFGAccurate)여야만 합니다.
* **Required** Target. 백워드 슬라이스가 끝나는 최종 목적지입니다.
* **Optional** `CDG`. Control Dependence Graph(CDG)는 CFG에서 파생된 것입니다. angr은 이러한 목적을 위해 `CDG` 분석 기능이 내장되어있습니다.
* **Optional** `DDG`. Data Dependence Graph(DDG)는 CFG의 위에 구축되어있습니다. angr은 이러한 목적을 위해 `DDG` 분석 기능이 내장되어있습니다.

`백워드슬라이스`는 아래의 코드로 구성될 수 있습니다.

```python
>>> import angr
# Load the project
>>> b = angr.Project("examples/fauxware/fauxware", load_options={"auto_load_libs": False})

# Generate a CFG first. In order to generate data dependence graph afterwards,
# you’ll have to keep all input states by specifying keep_stat=True. Feel free 
# to provide more parameters (for example, context_sensitivity_level)for CFG 
# recovery based on your needs.
>>> cfg = b.analyses.CFGAccurate(context_sensitivity_level=2, keep_state=True)

# Generate the control dependence graph
>>> cdg = b.analyses.CDG(cfg)

# Build the data dependence graph. It might take a while. Be patient!
>>> ddg = b.analyses.DDG(cfg)

# See where we wanna go... let’s go to the exit() call, which is modeled as a 
# SimProcedure.
>>> target_func = cfg.kb.functions.function(name="exit")
# We need the CFGNode instance
>>> target_node = cfg.get_any_node(target_func.addr)

# Let’s get a BackwardSlice out of them!
# `targets` is a list of objects, where each one is either a CodeLocation 
# object, or a tuple of CFGNode instance and a statement ID. Setting statement 
# ID to -1 means the very beginning of that CFGNode. A SimProcedure does not 
# have any statement, so you should always specify -1 for it.
>>> bs = b.analyses.BackwardSlice(cfg, cdg=cdg, ddg=ddg, targets=[ (target_node, -1) ])

# Here is our awesome program slice!
>>> print bs
```

때때로 DDG를 얻는것이 힘들 수 있습니다. 그렇다면 간단하게 CFG 위에 프로그램 슬라이스를 만들 수도 있습니다. 이것이 기본적으로 DDG가 선택적 파라미터인 이유입니다. 다음을 통해 CFG를 기반으로 백워드슬라이스를 만들 수 있습니다.

```python
>>> bs = b.analyses.BackwardSlice(cfg, control_flow_slice=True)
BackwardSlice (to [(<CFGNode exit (0x10000a0) [0]>, -1)])
```

### `백워드슬라이스` 객체 사용하기

`백워드슬라이스` 객체를 사용하기 전에 이 클래스의 디자인이 현재 상당희 임의적이라는 것을 알아두세요. 그리고 근 시일 내에 변경될 수 있습니다. 

#### 구성

구성 후 `백워드슬라이스`는 프로그램 슬라이스를 설명하는 아래와 같은 구성 요소들이 있습니다.

| 멤버 | 모드 | 의미 |
| --- | --- | --- |
| runs_in_slice | CFG-only | 프로그램 슬라이스에 있는 블록 및 SimProcedure의 주소와 이들 사이의 전환을 보여주는 `networkx.DiGraph` 인스턴스 |
| cfg_nodes_in_slice | CFG-only | 프로그램 슬라이스에 있는 CFGNode 사이의 전환을 보여주는 `networkx.DiGraph` 인스턴스 |
| chosen_statements | With DDG | basic block 주소를 프로그램 슬라이스의 일부인 statement ID의 리스트에 매핑하는 딕셔너리 |
| chosen_exits | With DDG | basic block 주소를 "exits" 목록에 매핑하는 딕셔너리. 리스트의 각 exit는 프로그램 슬라이스에서 유효한 전환입니다. |

`chosen_exit`의 각 "exit"는 statement ID와 대상 주소 리스트를 포함하는 튜플입니다. 예를 들어, "exit"는 다음과 같을 수 있습니다.

```
(35, [ 0x400020 ])
```

만약 "exit"가 basic block의 default exit이라면 다음과 같을 것입니다.

```
(“default”, [ 0x400085 ])
```

### Export an Annotated Control Flow Graph
공식 문서 추가 예정

### User-friendly Representation
`BackwardSlice.dbg_repr()`를 살펴보세요!

공식 문서 추가 예정

### Implementation Choices
공식 문서 추가 예정

### Limitations
공식 문서 추가 예정

### Completeness
공식 문서 추가 예정

### Soundness
공식 문서 추가 예정

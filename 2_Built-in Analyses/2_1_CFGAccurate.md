# 3_Built-in Analyses

@(CFGAccurate)[Backward Slicing, Function Identifier]

이 장에서는 angr의 context sensitivity나  Function Manager와 같은 중요한 개념을 살펴보면서  angr의 **CFGAccurate** 분석에 대해 자세하게 알아볼 것입니다.

### 개요

바이너리에서 할 수 있는 가장 기본적인 분석 방법은 **Control Flow Graph**입니다. 이 CFG는 바이너리에서 jumps/calls/rets/etc 등 실행의 분기가 일어나는 basic blocks를 시각적으로 표현하는 그래프입니다.
angr에서는 _fast CFG_와 _accurate CFG(CFGAccurate)_ 두 가지 형태의 CFG를 생성할 수 있습니다.  이름에서 유추할 수 있듯이, fast CFG를 생성하는 것은 일반적으로 accurate 방식보다 더 빠릅니다. 일반적으로 CFGFast가 사용자들이 원하는 형태일 것입니다. 이 페이지는 CFGAccurate에 대해 살펴볼 것입니다.

accurateCFG는 아래와 같은 명령어를 통해 만들어낼 수 있습니다.

```python
>>> import angr
# load your project
>>> b = angr.Project('/bin/true', load_options={'auto_load_libs': False})

# generate an accurate CFG
>>> cfg = b.analyses.CFGAccurate(keep_state=True)
```
또한 CFG의 커스터마이징을 위한 옵션들도 존재합니다.
|옵션|설명|
|:-------|:--------|
|context_sensitivity_level|이는 context sensitivity의 분석 레벨을 세팅합니다. 이에 대한 정보를 확인하고싶다면 아래의 context sensitivity level 섹션을 살펴보세요. default 값은 1입니다.|
|starts|분석할 때 entry point로서 사용하기 위한 주소들의 리스트입니다.|
|avoid_runs|분석할 때 무시하고 진행하기 위한 주소들의 리스트입니다.|
|call_depth|몇몇 number calls에서 분석의 depth를 제한합니다. 이것은 "call\_depth를 1로 세팅"하면서 직접 점프할 수 있는 특정한 함수들을 체크할 때 유용합니다.|
|initial_state|initial state는 CFG에 제공될 수 있으며, 이는 분석을 통해 사용됩니다.|
|keep_state|메모리를 절약하기 위해 기본적으로 각각의 basic block의 state가 삭제됩니다. 만약 _keep\_state_가 True라면, 이 state는 CFGNode에 저장됩니다.|
|enable_symbolic_back_traversal|indirect jump를 해결하기 위해 집중할지의 여부|
|enable_advanced_backward_slicing|direct jump를 해결하기 위해 집중할지의 여부|
|more!|최근에 업데이트 되는 옵션들에 대한 정보는 b.analyses.CFGAccurate의 docstring을 확인하세요.|

###Context Sensitivity Level

angr은 모든 basic block을 실행하고 그 블록들을 검토하면서 CFG를 생성합니다. 이로 인해 몇몇 문제점들이 발생합니다.  basic block은 다른 context들에서 다르게 작동할 수 있습니다.  예를 들어, block이 함수의 return으로 종료된다면 해당 basic block을 포함하는 함수의 다른 caller에 따라 return하는 대상이 달라집니다.

context sensitivity level은 개념적으로 caller가 callstack을 유지할 수 있는 수입니다. 이 개념을 설명하기 위해서 아래 코드를 살펴보겠습니다.

```cpp
void error(char *error)
{
    puts(error);
}

void alpha()
{
    puts("alpha");
    error("alpha!");
}

void beta()
{
    puts("beta");
    error("beta!");
}

void main()
{
    alpha();
    beta();
}
```

위의 샘플은 main>alpha>puts, main>alpha>error>puts, main>beta>puts,  main>beta>error>puts의 네 가지 콜 체인이 있습니다. 이 경우 angr은 두 체인은 실행할 수 있지만 큰 바이너리에서는 불가능합니다. 따라서 angr은 context sensitivity level에 의해 제한된 상태로 블록을 실행합니다. 즉, 각각의 함수는 호출된 고유한 context마다 재분석합니다.

예를 들어, 위의 puts() 함수는 다양한 context sensitivity level에서 아래와 같은 context로 분석됩니다.
|레벨|의미|Contexts|
|:--------|:--------||
|0|Callee-only|`puts`|
|1|One caller, plus callee|`alpha>puts` `beta>puts` `error>puts`|
|2|Two callers, plus callee|`alpha>error>puts` `main>alpha>puts` `beta>error>puts` `main>beta>puts`|
|3|Three callers, plus callee|`main>alpha>error>puts` `main>alpha>puts` `main>beta>error>puts` `main>beta>puts`|

context sensitivity level을 올리게 되면 CFG로부터 더 많은 정보를 얻을 수 있다는 장점이 있습니다. 예를 들어, context sensitivity가 1일 경우 CFG는 alpha에서 호출될 때 puts는 alpha를 return하며, error가 호출되면 puts에서 alpha를 return해줍니다. context sensitivity가 0일 경우 CFG는 간단하게 puts는 alpha, beta, 그리고 error를 return해줍니다. 이것은 구체적으로 IDA에서 사용되는 context sensitivity level입니다. context sensitivity level을 높이게 되면 분석 시간이 기하급수적으로 증가한다는 단점이 있습니다.

###Using the CFG

CFG의 코어는 [NetworkX](https://networkx.github.io/) di-graph입니다. 즉, 모든 일반 NetworkX API들을 사용할 수 있다는 말이 되겠죠.

```python
>>> print "This is the graph:", cfg.graph
>>> print "It has %d nodes and %d edges" % (len(cfg.graph.nodes()), len(cfg.graph.edges()))
```

CFG 그래프의 노드는 CFGNode 클래스의 인스턴스입니다. context sensitivity로 인해 주어진 basic block은 그래프에서 다중 노드를 가질 수 있습니다.(다중 context의 경우)

```python
# this grabs *any* node at a given location:
>>> entry_node = cfg.get_any_node(b.entry)

# on the other hand, this grabs all of the nodes
>>> print "There were %d contexts for the entry block" % len(cfg.get_all_nodes(b.entry))

# we can also look up predecessors and successors
>>> print "Predecessors of the entry point:", entry_node.predecessors
>>> print "Successors of the entry point:", entry_node.successors
>>> print "Successors (and type of jump) of the entry point:", [ jumpkind + " to " + str(node.addr) for node,jumpkind in cfg.get_successors_and_jumpkind(entry_node) ]
```

###Viewing the CFG

CFG의 렌더링은 어려운 문제입니다. angr은 CFG 분석 결과를 렌더링하기 위한 built-in 메커니즘을 제공하지 않습니다. 그리고 matplotlib와 같은 기존의 그래프 렌더링 라이브러리를 사용하려고 시도한다면 이미지를 사용할 수 없는 결과를 초래하게 됩니다.
angr CFG를 보기 위한 하나의 솔루션은 [axt's angr-utils repository](https://github.com/axt/angr-utils)입니다.

###Shared Libraries

CFG 분석은 서로 다른 이진 객체의 코드 흐름을 구분하지 않습니다. 즉, 이것은 기본적으로 로드된 공유 라이브러리를 통해 control flow를 분석하려고 시도한다는 것입니다. 분석 시간을 며칠로 연장할 것이기 때문에 이것은 의도된 행동이 아닙니다. 공유 라이브러리 없이 바이너리를 로드하기 위해서는 Project constructor에 다음의 키워드 인자를 추가하세요: `load\_options={'auto\_load\_libs': False}`

###Function Manager
CFG의 결과는 `cfg.kb.functions`를 통해 접근할 수 있는 Function Manager라고 불리는 오브젝트를 생성합니다. 이 객체를 가장 일반적으로 사용하는 경우는 dictionary와 같은 것에 접근하는 것입니다. 이것은 주소를 `Function` 객체에 매핑합니다. 이 객체는 함수에 대한 속성을 알려줍니다.

```python
>>> entry_func = cfg.kb.functions[b.entry]
```

Functions에는 몇가지 중요한 속성이 있습니다.
* `entry_func.block_addrs`는 함수에 속하는 basic block이 시작하는 주소들의 집합입니다.
* `entry_func.blocks`는 capstone을 사용하여 디스어셈블하고 탐색할 수 있는 함수에 속한 basic block의 집합입니다.
* `entry_func.string_references()`는 함수의 어느 지점에서든 참조된 모든 상수 문자열들의 리스트를 반환합니다. 그것들은 (addr, string) 튜플의 형태인데, addr은 바이너리의 데이터 섹션에 있는 주소이고, strings는 문자열의 값을 포함하는 python string입니다.
* `entry_func_returning`은 함수가 return할 수 있는지 없는지 검증하는 boolean 값입니다. False는 모든 경로가 반환되지 않는 것을 나타냅니다.
* `entry_func.callable`은 이 함수를 참조하는 angr Callable 객체입니다. python 인자를 가진 python 함수와 같이 호출할 수 있으며, 이러한 인수를 사용하여 함수를 실행한 것처럼 실제 결과(symbolic일 수 있다)를 얻어낼 수 있습니다.
* `entry_func.transition_graph`는 함수 자체 내의 control flow를 설명하는 NetworkX DiGraph입니다. IDA가 기능별 수준에서 표시해주는 CFG와 비슷합니다.
* `entry_func.name`은 함수의 이름입니다.
* `entry_func.has_unresolved_calls`와 `entry.has_unresolved_jumps`는 CFG 내의 부정확성을 감지하는 것과 관련이 있습니다. 때대로 간접 호출이나 jump가 가능한 대상이 무엇인지 감지할 수 없습니다. 만약 함수 내에서 발생한다면 그 함수는 적절한 `has_unresolved_*`의 값을 True로 세팅합니다.
* `entry_func.get_call_sites()`는 다른 함수의 호출에서 끝의 basic block에 해당하는 모든 주소들의 집합을 반환합니다.
* `entry_func.get_call_target(callsite_addr)`은 callsite_addr이 call site address의 리스트에서 주어질 경우 해당 callsite가 호출할 위치를 반환합니다.
* `entry_func.get_call_return(callsite_addr)`은 callsite_addr이 call site address의 리스트에서 주어질 경우 해당 callsite가 반환될 위치를 반환합니다.

이 외에도 많은 속성들이 있습니다!

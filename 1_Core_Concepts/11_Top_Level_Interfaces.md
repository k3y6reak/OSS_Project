### 핵심 개념

angr를 시작하기 전에 몇 가지 기본 개념과 오브젝트를 구성하는 방법을 알아야 합니다.

angr를 사용하는 첫 번째 작업은 프로젝트에 바이너리를 로드하는 것입니다. `/bin/true`를 예로 사용할 것입니다.

```python
>>> import angr
>>> proj = angr.Project('/bin/true')
```

위와 같이 작성하면 `/bin/true`에 대한 분석 및 시뮬레이션을 할 수 있습니다.


#### 기본 속성

먼저 프로젝트에 대한 기본 속성인 아키텍쳐, 파일 이름, 시작 주소를 갖습니다.

```python
>>> import monkeyhex # this will format numerical results in hexadecimal
>>> proj.arch
<Arch AMD64 (LE)>
>>> proj.entry
0x401670
>>> proj.filename
'/bin/true'
```

- arch는 `archinfo.Arch` 객체의 인스턴스 입니다. 위 경우 리틀 엔디안 amd64 입니다. 
- entry는 바이너리의 시작 지점입니다.
- filename은 바이너리의 파일 이름입니다.

#### loader

가상 주소 공강에서 바이너리 파일을 나타내는 것은 어렵습니다. 이를 처리하기 위해서 CLE라는 모듈을 사용합니다.
CLE의 결과는 `.loader` 속성에서 사용할 수 있습니다.

```python
>>> proj.loader
<Loaded true, maps [0x400000:0x5004000]>

>>> proj.loader.shared_objects # may look a little different for you!
{'ld-linux-x86-64.so.2': <ELF Object ld-2.24.so, maps [0x2000000:0x2227167]>,
 'libc.so.6': <ELF Object libc-2.24.so, maps [0x1000000:0x13c699f]>}

>>> proj.loader.min_addr
0x400000
>>> proj.loader.max_addr
0x5004000

>>> proj.loader.main_object  # we've loaded several binaries into this project. Here's the main one!
<ELF Object true, maps [0x400000:0x60721f]>

>>> proj.loader.main_object.execstack  # sample query: does this binary have an executable stack?
False
>>> proj.loader.main_object.pic  # sample query: is this binary position-independent?
True
```

#### factory

대부분의 project를 인스턴스화 해야합니다. 공통 객체에 대한 `project.factory` 생성자를 제공합니다.


##### block

`project.factory.block()`은 입력된 주소로 기본 블록 단위로 추출합니다.

```python
>>> block = proj.factory.block(proj.entry) # lift a block of code from the program's entry point
<Block for 0x401670, 42 bytes>

>>> block.pp()                          # pretty-print a disassembly to stdout
0x401670:       xor     ebp, ebp
0x401672:       mov     r9, rdx
0x401675:       pop     rsi
0x401676:       mov     rdx, rsp
0x401679:       and     rsp, 0xfffffffffffffff0
0x40167d:       push    rax
0x40167e:       push    rsp
0x40167f:       lea     r8, [rip + 0x2e2a]
0x401686:       lea     rcx, [rip + 0x2db3]
0x40168d:       lea     rdi, [rip - 0xd4]
0x401694:       call    qword ptr [rip + 0x205866]

>>> block.instructions                  # how many instructions are there?
0xb
>>> block.instruction_addrs             # what are the addresses of the instructions?
[0x401670, 0x401672, 0x401675, 0x401676, 0x401679, 0x40167d, 0x40167e, 0x40167f, 0x401686, 0x40168d, 0x401694]
```

block를 사용해서 코드 블록의 다른 표현 방식을 출력할 수 있습니다.

```python
>>> block.capstone                       # capstone disassembly
<CapstoneBlock for 0x401670>
>>> block.vex                            # VEX IRSB (that's a python internal address, not a program address)
<pyvex.block.IRSB at 0x7706330>
```

##### states

`project` 객체는 프로그램의 초기화 이미지를 나타냅니다. angr를 사용하여 실행 할 때 프로그램 상태를 나타내는 `SimState`가 있습니다.

```python
>>> state = proj.factory.entry_state()
<SimState @ 0x401670>
```

SimState는 프로그램의 메모리, 레지스터, 파일 시스템 데이터를 포함하고 있습니다.

```python
>>> state.regs.rip        # get the current instruction pointer
<BV64 0x401670>
>>> state.regs.rax
<BV64 0x1c>
>>> state.mem[proj.entry].int.resolved  # interpret the memory at the entry point as a C int
<BV32 0x8949ed31>
```

python의 int가 아니며 bitvector 입니다.

```python
>>> bv = state.solver.BVV(0x1234, 32)       # create a 32-bit-wide bitvector with value 0x1234
<BV32 0x1234>                               # BVV stands for bitvector value
>>> state.solver.eval(bv)                # convert to python int
0x1234
```

bitvector 를 레지스터와 메모리에 다시 저장하거나 python 정수를 직접 저장 할 수 있고 적절한 비트 벡터로 변환됩니다.

```python
>>> state.regs.rsi = state.solver.BVV(3, 64)
>>> state.regs.rsi
<BV64 0x3>

>>> state.mem[0x1000].long = 4
>>> state.mem[0x1000].long.resolved
<BV64 0x4>
```

`mem`을 사용하는 방법은 아래와 같습니다.

 - array[index] 표기법을 사용하여 주소 지정
 - `.<type>` 이 char, short, int, long 등 으로 해석되야 할 때.
 - 다음 중 하나를 수행 할 수 있습니다.
   - bitvector나 python int 중 하나에 값 저장.
   - `.resolved` 값을 비트 벡터로 가져오기.
   - `.concrete` 값을 int로 가져오기.

##### 분석

angr는 프로그램에서 정보를 추출하는데 사용할 수 있는 몇 가지 제공되는 패키지가 있습니다.
```python
>>> proj.analyses.            # Press TAB here in ipython to get an autocomplete-listing of everything:
 proj.analyses.BackwardSlice        proj.analyses.CongruencyCheck      proj.analyses.reload_analyses       
 proj.analyses.BinaryOptimizer      proj.analyses.DDG                  proj.analyses.StaticHooker          
 proj.analyses.BinDiff              proj.analyses.DFG                  proj.analyses.VariableRecovery      
 proj.analyses.BoyScout             proj.analyses.Disassembly          proj.analyses.VariableRecoveryFast  
 proj.analyses.CDG                  proj.analyses.GirlScout            proj.analyses.Veritesting           
 proj.analyses.CFG                  proj.analyses.Identifier           proj.analyses.VFG                   
 proj.analyses.CFGAccurate          proj.analyses.LoopFinder           proj.analyses.VSA_DDG               
 proj.analyses.CFGFast              proj.analyses.Reassembler
 ```

사용하는 방법을 찾으려면 [API문서](http://angr.io/api-doc/angr.html?highlight=cfg#module-angr.analysis)를 살펴보세요.

```python
# Originally, when we loaded this binary it also loaded all its dependencies into the same virtual address  space
# This is undesirable for most analysis.
>>> proj = angr.Project('/bin/true', auto_load_libs=False)
>>> cfg = proj.analyses.CFGFast()
<CFGFast Analysis Result at 0x2d85130>

# cfg.graph is a networkx DiGraph full of CFGNode instances
# You should go look up the networkx APIs to learn how to use this!
>>> cfg.graph
<networkx.classes.digraph.DiGraph at 0x2da43a0>
>>> len(cfg.graph.nodes())
951

# To get the CFGNode for a given address, use cfg.get_any_node
>>> entry_node = cfg.get_any_node(proj.entry)
>>> len(list(cfg.graph.successors(entry_node)))
2
```


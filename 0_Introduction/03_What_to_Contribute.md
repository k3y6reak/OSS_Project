### 도움이 필요합니다.

angr는 거대한 프로젝트로 유지하기가 어렵습니다. 다양한 사람들이 참여할 수 있도록 TODO 항목이 나열되어 있습니다.

#### 문서

문서화가 거의 돼 있지 않습니다. 많은 사람들의 도움이 필요합니다.

#### API

누락된 사항을 파악하기 위해 github에 tracking 이슈를 만들었습니다.

1. [angr](https://github.com/angr/angr/issues/145)
2. [claripy](https://github.com/angr/claripy/issues/17)
3. [cle](https://github.com/angr/cle/issues/29)
4. [pyvex](https://github.com/angr/pyvex/issues/34)

#### GitBook

이 GitBook에는 몇 가지 핵심 부분이 있습니다.
1. TODO 작성
2. 페이지를 보기 쉽게 간단한 표 사용.

#### angr 코스

angr를 이용하여 개발을 한다면 정말 유익할 것입니다. 사람들이 점점 angr의 기능을 사용해야 할 필요가 있습니다.

#### 재 연구

아쉽게도 모든 사람들이 angr를 연구하는 것은 아닙니다. 이를 해결할 때까지 프레임워크 내에서 재사용이 가능하다록 angr를 정기적으로 관련 작업을 구현해야 합니다.

### 개발

#### angr 관리

angr GUI인 [angr-management](https://github.com/angr/angr-management)는 많은 작업이 필요합니다. 아래 내용은 현재 angr-management에서 누락된 항목입니다.

 - IDA Pro의 네비게이터 툴바처럼 프로그램의 메모리 공간에 내용을 보여주는 것.
 - 프로그램의 텍스트 기반 Disassembly.
 - 프로그램의 상태의 세부 정보 (레지스터, 메모리 등)
 - 상호 참조

#### IDA 플러그인

angr의 많은 기능들이 IDA에 이용될 수 있습니다.

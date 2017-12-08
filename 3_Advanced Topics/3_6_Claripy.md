# 3_Advanced topics

## Solver Engine

angr의 솔버 엔진은 Claripy라고 불립니다. Claripy는 다음을 노출합니다.

* Claripy AST(`claripy.ast.Base`의 하위 클래스)는 복잡하고 symbolic한 식과 상호작용할 수 있는 통일된 방법을 제공합니다.
* Claripy 프론트엔드는 서로 다른 백엔드에서 식을 해결(제약적인 solving 포함)에 대한 통일된 인터페이스를 제공합니다.

내부적으로, Claripy는 여러가지 다른 백엔드(복잡한 bitvector, VSA construct, SAT solver)의 공동 작업을 원활하게 중재합니다. 이것들 참 골치아픈 녀석들입니다.

대부분의 angr 사용자는 Claripy와 직접 소통할 필요는 없습니다(단, claripy AST 객체는 symbolic 식을 나타내는데, 이는 제외). --angr는 Claripy와의 대부분의 상호작용을 내부적으로 처리합니다. 그러나 식을 다루기 위해서는 Claripy에 대한 이해가 있는 편이 좋을 수 있습니다.

## Claripy ASTs

Claripy AST는 Claripy가 지원하는 구문간의 차이점을 추상화시킵니다. 이들을 기본 데이터의 타입에 대한 작업 트리(즉, (a + b) / c)를 정의합니다. Claripy는 요청을 백엔드에 전달하여 기본 객체 자체에 이러한 작업의 적용을 처리하도록 합니다.

현재 Claripy는 다음과 같은 유형의 AST를 지원합니다.

| 이름 | 설명 | 서포팅 주체(Claripy 백엔드) | 예제 코드  |
| ---- | ---- |  ---- |  ---- |
| BV | 이것은 bitvector이며, symbolic(이름 포함)이거나 concrete(값)합니다. 이는 비트 단위의 크기를 갖습니다. | BackendConcrete, BackendVSA, BackendZ3 | 1) 32비트 symbolic bitvector "x" : `claripy.BVS('x', 32)` <br />2) `0xc001b3475`의 값을 갖는 32비트 bitvector : `claripy.BVV(0xc001b3a75, 32)` <br />3) 1000과 2000 사이의 10으로 나눌 수 있는 32비트 "strided interval"(VSA 문서 참조) : `claripy.SI(name='x', bits=32, lower_bound=1000, upper_bound=2000, stride=10)` |
| FP | 이것은 소숫점을 가진 수이며, symbolic(이름 포함)이거나 concrete(값)입니다. | BackendConcrete, BackendZ3 | TODO |
| Bool | 이것은 boolean 연산입니다(True 또는 False) | BackendConcrete, BackendVSA, BackendZ3 | `claripy.BoolV(True)` 또는 `claripy.true` 또는 `claripy.false` 또는 두 AST를 비교할 때는 `claripy.BVS('x', 32) < claripy.BVS('y', 32)`와 같이 사용|

위의 생성 코드는 모두 `claripy.AST` 객체를 반환하며, 이 객체를 사용하여 작업을 수행할 수 있습니다.
AST는 여러가지 유용한 작업을 제공합니다.

```python
>>> import claripy

>>> bv = claripy.BVV(0x41424344, 32)

# Size - you can get the size of an AST with .size()
>>> assert bv.size() == 32

# Reversing - .reversed is the reversed version of the BVV
>>> assert bv.reversed is claripy.BVV(0x44434241, 32)
>>> assert bv.reversed.reversed is bv

# Depth - you can get the depth of the AST
>>> print bv.depth
>>> assert bv.depth == 1
>>> x = claripy.BVS('x', 32)
>>> assert (x+bv).depth == 2
>>> assert ((x+bv)/10).depth == 3
```

AST에 조건(==, != 등)을 적용하면 수행되는 조건을 나타내는 AST가 반환됩니다.

```python
>>> r = bv == x
>>> assert isinstance(r, claripy.ast.Bool)

>>> p = bv == bv
>>> assert isinstance(p, claripy.ast.Bool)
>>> assert p.is_true()
```

이런 조건들을 다양한 방법으로 조합할 수 있습니다.

```python
>>> q = claripy.And(claripy.Or(bv == x, bv * 2 == x, bv * 3 == x), x == 0)
>>> assert isinstance(p, claripy.ast.Bool)
```

이것의 유용한 점은Claripy solver를 사용할 때 명확해질 것입니다. 일반적으로 Claripy는 모든 일반 파이썬 작업(+, -, |, == 등)을 지원하며 Claripy 인스턴스 객체를 통해 추가 작업을 제공합니다. 후자에서 사용할 수 있는 작업 목록이 있습니다.

| 이름 | 설명 | 예시 |
| ----- | ----- | ----- |
| LShR | bit 표현식(BVV, BV, SI) 오른쪽 논리 쉬프트 연산 | `claripy.LShR(x, 10)`
| SignExt | bit 표현식에서 Sign-extend | `claripy.SignExt(32, x)` 또는 `x.sign_extend(32)` |
| ZeroExt | bit 표현식에서 Zero-extend | `claripy.ZeroExt(32, x)` 또는 `x.zero_extend(32)` |
| Extract | bit 표현식에서 주어진 비트(우측부터 포함하여 에서 zero-indexed)를 추출 | x의 가장 우측 바이트 추출 : `Claripy.Extract(7, 0, x)` 또는 `x[7:0]` |
| Concat | 몇 개의 bit 표현식을 합치거나 새로운 표현식을 만듬 | `claripy.Concat(x, y, z)` |
| RotateLeft | bit 표현식을 좌측으로 회전 | `claripy.RotateLeft(x, 8)` |
| RotateRight | bit 표현식을 우측으로 회전 | `claripy.RotateRight(x, 8)` |
| Reverse | bit 표현식을 반전 | `claripy.Reverse(x)` 또는 `x.reversed` |
| And | 논리 and | `	claripy.And(x == y, x > 0)` |
| Or | 논리 Or | `claripy.Or(x == y, y < 10)` |
| Not | 논리 Not | `claripy.Not(x == y)`는 `x != y`와 동일 |
| If | if-then-else | 최대 값을 선택 : `claripy.If(x > y, x, y)` |
| ULE | Unsigned, 작거나 같을 때 | `claripy.ULE(x, y)` |
| ULT | Unsigned, 작을 때 | `claripy.ULT(x, y)` |
| UGE | Unsigned, 크거나 같을 때 | `claripy.UGE(x, y)` |
| UGT | Unsigned, 클 때 | `claripy.UGT(x, y)` |
| SLE | Signed, 작거나 같을 때 | `claripy.SLE(x, y)` |
| SLT | Signed, 작을 때 | `claripy.SLT(x, y)` |
| SGE | Signed, 크거나 같을 때 | `claripy.SGE(x, y)` |
| SGT | Signed, 클 때 | `claripy.SGT(x, y)` |


# 6_Appendix

## List of Claripy Operations

### Arithmetic and Logic

| 이름 | 설명 | 예시 |
| ----- | ----- | ----- |
| LShR | 오른쪽 논리 쉬프트 연산 | `x.LShR(10)`
| RotateLeft | 표현식을 좌측으로 회전 | `x.RotateLeft(8)` |
| RotateRight | 표현식을 우측으로 회전 | `x.RotateRight(8)` |
| And | 논리 and | `	solver.And(x == y, x > 0)` |
| Or | 논리 Or | `solver.Or(x == y, y < 10)` |
| Not | 논리 Not | `solver.Not(x == y)`는 `x != y`와 동일 |
| If | if-then-else | 최대 값을 선택 : `solver.If(x > y, x, y)` |
| ULE | Unsigned, 작거나 같을 때 | `x.ULE(y)` |
| ULT | Unsigned, 작을 때 | `x.ULT(y)` |
| UGE | Unsigned, 크거나 같을 때 | `x.UGE(y)` |
| UGT | Unsigned, 클 때 | `x.UGT(y)` |
| SLE | Signed, 작거나 같을 때 | `x.SLE(y)` |
| SLT | Signed, 작을 때 | `x.SLT(y)` |
| SGE | Signed, 크거나 같을 때 | `x.SGE(y)` |
| SGT | Signed, 클 때 | `x.SGT(y)` |

### Bitvector Manipulation

| 이름 | 설명 | 예시 |
| ----- | ----- | ----- |
| SignExt | n개의 부호 비트가 있는 왼쪽에 bitvector 채움 | `x.sign_extend(n)` |
| ZeroExt | n개의 zero 비트가 있는 왼쪽에 bitvector 채움 | `x.zero_extend(n)` |
| Extract | 표현식에서 주어진 비트(우측부터 포함하여 에서 zero-indexed)를 추출 | x의 LSB 추출 : `x[7:0]` |
| Concat | 몇 개의 표현식을 합치거나 새로운 표현식을 만듬 | `x.Concat(y, ...)` |

### Extra Functionality

AST를 분석하고 연산 집합을 구성하여 구현할 수 있는 미리 패키징된 작업들이 있지만, 더 쉬운 방식이 아래 있습니다.

* bitvector를 `val.chop(n)`을 이용하여 n 비트 덩어리 목록으로 잘라낼 수 있습니다.
* bitvector를 `x.reversed`로 endian-reverse 할 수 있습니다.
* `val.length`를 사용하여 bitvector의 너비를 비트 단위로 가져올 수 있습니다.
* AST에 `val.symbolic`이 있는 symbolic component가 있는지 테스트할 수 있습니다.
* `val.variables`를 사용하여 AST를 작성하는데 관련된 모든 symbolic variable의 이름 집합을 가져올 수 있습니다.
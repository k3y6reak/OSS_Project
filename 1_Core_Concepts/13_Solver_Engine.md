### Symbolic 표현과 제약 해결

angr의 강력함은. 애뮬레이터가 아니라 symbolic 변수를 실행가능하는 것에 있습니다. 변수가 실제 값을 갖고있다고 말하는 것 대신에 단순히 이름을 효과적으로 나타내는 것입니다. 산술 연산을 수행하면 연산트리가 생성됩니다. AST는 z3와 같은 SMT solver 조건으로 변환 할 수 있습니다. "일정 순서의 결과가 주어지면 입력된 값은 무엇일까요?"와 같은 질문을 할 수 있는데 이를 angr로 사용하는 방법을 배우게 됩니다.


#### Bitvector로 작업

간단한 프로젝트를 만들어 봅니다.

```python
>>> import angr, monkeyhex
>>> proj = angr.Project('/bin/true')
>>> state = proj.factory.entry_state()
```

bitvector는 어떤 수의 비트를 말합니다.

```python
# 64-bit bitvectors with concrete values 1 and 100
>>> one = state.solver.BVV(1, 64)
>>> one
 <BV64 0x1>
>>> one_hundred = state.solver.BVV(100, 64)
>>> one_hundred
 <BV64 0x64>

# create a 27-bit bitvector with concrete value 9
>>> weird_nine = state.solver.BVV(9, 27)
>>> weird_nine
<BV27 0x9>
```

이러한 비트를 bitvector라고 부르고 이를 이용해 산술연산을 할 수 있습니다.

```python
>>> one + one_hundred
<BV64 0x65>

# You can provide normal python integers and they will be coerced to the appropriate type:
>>> one_hundred + 0x100
<BV64 0x164>

# The semantics of normal wrapping arithmetic apply
>>> one_hundred - one*200
<BV64 0xffffffffffffff9c>
```

`one + weird_nine`의 연산을 타입이 맞지 않아 연산을 할 수 없습니다. 따라서 `weird_nine`의 길이를 확장할 수 있습니다.

```python
>>> weird_nine.zero_extend(64 - 27)
<BV64 0x9>
>>> one + weird_nine.zero_extend(64 - 27)
<BV64 0xa>
```

`zero_extnd`는 주어진 bitvector의 왼쪽에 0으로 채워넣습니다. 

```python
# Create a bitvector symbol named "x" of length 64 bits
>>> x = state.solver.BVS("x", 64)
>>> x
<BV64 x_9_64>
>>> y = state.solver.BVS("y", 64)
>>> y
<BV64 y_10_64>
```

`x`와 `y`는 중학교 수학에서 배운 변수와 같습니다. 이를 산술연산 할 수 있지만 숫자가 출력되지 않습니다. 대신 AST가 출력됩니다.

```python
>>> x + one
<BV64 x_9_64 + 0x1>

>>> (x + one) / 2
<BV64 (x_9_64 + 0x1) / 0x2>

>>> x - y
<BV64 x_9_64 - y_10_64>
```

AST에는 `.op`와 `.args`가 있습니다. op는 연산자의 이름을 나타내고 args는 사용되는 값을 말합니다. 연산이 아닌 경우에는 `BVV`, `BVS` 등으로 표현됩니다.

```python
>>> tree = (x + 1) / (y + 2)
>>> tree
<BV64 (x_9_64 + 0x1) / (y_10_64 + 0x2)>
>>> tree.op
'__div__'
>>> tree.args
(<BV64 x_9_64 + 0x1>, <BV64 y_10_64 + 0x2>)
>>> tree.args[0].op
'__add__'
>>> tree.args[0].args
(<BV64 x_9_64>, <BV64 0x1>)
>>> tree.args[0].args[1].op
'BVV'
>>> tree.args[0].args[1].args
(1, 64)
```

#### Symbolic 표현

두 개의 AST에서 비교 연산을 하면 bitvector가 아닌 bool 값이 출력됩니다.

```python
>>> x == 1
<Bool x_9_64 == 0x1>
>>> x == one
<Bool x_9_64 == 0x1>
>>> x > 2
<Bool x_9_64 > 0x2>
>>> x + y == one_hundred + 5
<Bool (x_9_64 + y_10_64) == 0x69>
>>> one_hundred > 5
<Bool True>
>>> one_hundred > -5
<Bool False>
```

마지막 연산을 보면 one_hundred는 -5보다 큰 경우이지만 -5가. `<BV64 0xfffffffffffffffb>`로 표현되기 때문에 `one_hundred.SGT(-5)`를 사용해야 합니다.

정확한 값이 없기 때문에 if나 while문에서 조건에 직접 변수를 비교해서는 안되며 있더라고 `if one > one_hundred`는 예외를 발생합니다. 대신 `solver.is_true`와 `solver_is_false`를 사용해야 합니다.

```python
>>> yes = one == 1
>>> no = one == 2
>>> maybe = x == y
>>> state.solver.is_true(yes)
True
>>> state.solver.is_false(yes)
False
>>> state.solver.is_true(no)
False
>>> state.solver.is_false(no)
True
>>> state.solver.is_true(maybe)
False
>>> state.solver.is_false(maybe)
False
```

#### 제약 해결

```python
>>> state.solver.add(x > y)
>>> state.solver.add(y > 2)
>>> state.solver.add(10 > x)
>>> state.solver.eval(x)
4
```

위와 같은 제약조건을 추가하면 `state.solver.eval(y)` 를 통해 x에 따른 y 값을 얻을 수 있습니다.

```python
# get a fresh state without constraints
>>> state = proj.factory.entry_state()
>>> input = state.solver.BVS('input', 64)
>>> operation = (((input + 4) * 3) >> 1) + input
>>> output = 200
>>> state.solver.add(operation == output)
>>> state.solver.eval(input)
0x3333333333333381
```

위 연산은 출력에 따른 입력을 찾는 것입니다. 만약 모순된 제약 조건을 추가하면 출력값이 이상하거나 예외를 발생시킵니다. `state.satisfiable()`를 이용해 만족을 하는지에 대한 여부도 알 수 있습니다.

```python
>>> state.solver.add(input < 2**32)
>>> state.satisfiable()
False
```

변수만 아니라 복잡한 식도 가능합니다.

```python
# fresh state
>>> state = proj.factory.entry_state()
>>> state.solver.add(x - y >= 4)
>>> state.solver.add(y > 0)
>>> state.solver.eval(x)
5
>>> state.solver.eval(y)
1
>>> state.solver.eval(x + y)
6
```

#### 해결 함수

`eval`은 해답을 출력해주는데 여러개의 값을 원할 수 있습니다.
 - `solver.eval(expression)` : 하나의 해결책을 출력합니다.
 - `solver.eval_one(expression)` : 해결책을 출력하지만 둘 이상의 해결책이 있다면 오류를 출력합니다.
 - `solver.eval_upto(expression, n)` : 최대 n개의 해결책을 주며 n보다 작으면 n보다 작은 수를 출력합니다
 - `solver.eval_atleast(expression, n)` : n보다 작으면 오류를 출력합니다.
 - `solver.eval_exact(expression, n)` : n개의 해답을 출력하고 더 적거나 많은 경우 오류를 출력합니다.
 - `solver.min(expression)` : 최소한의 해답을 출력합니다.
 - `solver.max(expression)` : 최대한의 해답을 출력합니다.
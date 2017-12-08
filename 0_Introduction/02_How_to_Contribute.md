### 버그 리포팅

만약 angr가 해결하지 못하거나 버그가 나타난다면 알려주세요!

1. angr/binaries 와 angr/angr fork 만들기
2. 문제된 바이너리와 함께 angr/binaries의 pull 요청하기.
3. `angr/tests/borken_x.py`, `angr/tests/broken_y.py`등 테스트 케이스와 함께 angr/angr pull 요청하기.

angr에서 제공하는 테스트 케이스 형식을 따르도록 해주세요.

```python
def test_some_broken_feature():
    p = angr.Project("some_binary")
    result = p.analyses.SomethingThatDoesNotWork()
    assert result == "what it should *actually* be if it worked"

if __name__ == '__main__':
    test_some_broken_feature()
```

이러한 형식은 버그를 빨리 고치는데 도움을 줍니다.


### angr 개발

좋은 상태를 유지하기 위한 몇가지 가이드라인이 있습니다.

#### 코딩 스타일

[PEP8 코드 협약](http://legacy.python.org/dev/peps/pep-0008/)에 맞추고 있습니다. vim을 사용한다면 [파이썬 모드](https://github.com/python-mode/python-mode) 플러그인만 있으면 됩니다.

angr의 일부분의 코드를 작성할 경우 다음의 경우를 생각해야 합니다.

getter와 setter 대신에 `@property` decorator와 같은 attribute 접근을 사용해주세요.
Java가 아니고 iPython이기 때문에 속성은 탭 완성을 가능하게 합니다.

우리가 제공하는 `.pylintrc`를 사용하세요. CI 서버에서 빌드 실패가 나타날 수 있습니다.

절대로 `raise Exception`이나 `assert False`를 하지마세요. 올바른 예외 처리를 사용해야 합니다.
올바른 예외 처리가 없다면 `AngerError`나 `SimError`를 사용하세요.

tabs 사용을 자제하고 들여쓰기를 사용하세요. 표준은 4칸이며 스페이스와 탭을 혼용해서 사용하는 것은 좋지 못합니다.

긴 줄은 코드를 읽기 불편하기 때문에 120자 내로 작성하도록 합니다.

큰 기능은 작은 기능으로 나누는 것이 좋습니다.

항상 디버깅 할 때 접근할 수 있도록 `__` 대신에 `_`를 사용하세요. 

#### 문서

코드를 문서화 하고, 모든 클래스 정의와 함수 정의에는 설명이 있어야합니다.
- 무엇을 하는지?
- 매개 변수의 타입과 의미는 무엇인지?
- 반환 값은 무엇인지?

[sphinx](http://www.sphinx-doc.org/en/stable/)를 이용하여 API 문서를 작성합니다. sphinx는 함수 매개변수, 반환 값, 형식 등을 문서화 하는 특수 키워드를 지원합니다.

아래 내용은 함수 문서의 예시 입니다. 변수 설명은 가능한 읽을 수 있도록 작성해야 합니다.

```python
def prune(self, filter_func=None, from_stash=None, to_stash=None):
    """
    Prune unsatisfiable paths from a stash.

    :param filter_func: Only prune paths that match this filter.
    :param from_stash:  Prune paths from this stash. (default: 'active')
    :param to_stash:    Put pruned paths in this stash. (default: 'pruned')

    :returns:           The resulting PathGroup.
    :rtype:             PathGroup
    """
```

위와 같은 방식은 함수의 매개변수가 명확하게 인식할 수 있다는 장점이 있습니다. 문서를 반복적으로 작성할 경우 아래의 방식 처럼 작성할 수 있습니다.

```python
def read_bytes(self, addr, n):
    """
    Read `n` bytes at address `addr` in memory and return an array of bytes.
    """
```

#### 단위 시험

새로운 기능을 추가하고 테스트 케이스가 없으면 해당 기능은 정상적으로 작동하지 않을 수 있기 때문에 테스트 케이스를 작성해야 합니다.

커밋에서 기능을 검사하는 CI 서버를 구동 중입니다. 서버에서 테스트를 실행하게 하려면 해당 repository의 폴더에 일치하는 파일의 [nosetests](https://nose.readthedocs.org/en/latest/) 에 혀용되는 형식으로 작성하세요.
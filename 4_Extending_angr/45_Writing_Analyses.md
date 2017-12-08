## Analyses 작성하기

Analyses는 `angr.Analysis` 클래스를 상속하여 만들 수 있습니다. 이 장에서는 다양한 기능을 타나내는 analyses를 만듭니다.

```python
>>> import angr

>>> class MockAnalysis(angr.Analysis):
...     def __init__(self, option):
...         self.option = option

>>> angr.register_analysis(MockAnalysis, 'MockAnalysis')
```

새로운 analysis를 보도록 합시다.

```python
>>> proj = angr.Project("/bin/true")
>>> mock = proj.analyses.MockAnalysis('this is my option')
>>> assert mock.option == 'this is my option'
```

프로젝트를 가져온 후 새로운 analysis를 등록한 경우 `proj.analyses.reload_analyses()`를 이용하여 프로젝트의 등록 된 분석의 목록을 업데이트 해야 합니다.

### project와 작업

Analysis는 자동으로 `self.project` 속성 아래에서 실행하는 프로젝트를 가지고 있습니다. 이를 이용하여 프로젝트와 상화 작용하고 분석합니다.

```python
>>> class ProjectSummary(angr.Analysis):
...     def __init__(self):
...         self.result = 'This project is a %s binary with an entry point at %#x.' % (self.project.arch.name, self.project.entry)

>>> angr.register_analysis(ProjectSummary, 'ProjectSummary')
>>> proj = angr.Project("/bin/true")

>>> summary = proj.analyses.ProjectSummary()
>>> print summary.result
This project is a AMD64 binary with an entry point at 0x401410.
```

### Naming Analyses

`register_analysis` 호출은 셀제로 angr에 분석을 추가하는 것입니다. 이름은 `project.analyses` 객체 아래에 어떻게 나타내는 것인지 입니다. 일반적으로 분석 클래스와 동일한 이름을 사용해야 하지만, 짧은 이름을 사용하는 경우도 가능합니다.

```python
>>> class FunctionBlockAverage(angr.Analysis):
...     def __init__(self):
...         self._cfg = self.project.analyses.CFG()
...         self.avg = len(self._cfg.nodes()) / len(self._cfg.function_manager.functions)

>>> angr.register_analysis(FunctionBlockAverage, 'FuncSize')

```

그런 다음 특정 이름을 사용하여 분석을 호출 할 수 있습니다. `b.analyses.FuncSize()`가 있습니다.


### 분석 복원

때때로 코드가 예외가 발생할 수 있습니다.

Analysis 기본 클래스는 `self.resilience`에서 복원 context manager 를 제공합니다.

```python
>>> class ComplexFunctionAnalysis(angr.Analysis):
...     def __init__(self):
...         self._cfg = self.project.analyses.CFG()
...         self.results = { }
...         for addr, func in self._cfg.function_manager.functions.iteritems():
...             with self._resilience():
...                 if addr % 2 == 0:
...                     raise ValueError("can't handle functions at even addresses")
...                 else:
...                     self.results[addr] = "GOOD"
```

context manager는 throw된 예외를 잡아 유형, 메시지 및 추적 튜플로 `self.errors`에 기혹합니다. (단, 추적은 삭제되지 않습니다.)
## angr가 무엇이며, 어떻게 사용하는가?

angr는 Mayhem, KLEE 등 Dynamic symbolic execution와 Static analyses를 수행할 수 있는 Multi-architecture binary 분석 툴입니다.

바이너리 분석이 복잡하기 때문에 angr도 복잡하게 만들어졌지만 문서를 통해서 쉽게 사용할 수 있도록 했습니다.

바이너리를 프로그래밍적으로 분석하기 위해서 몇가지 문제를 해결해야 합니다.

	- 분석 프로그램에 바이너리를 로드하기.
	- 바이너리를 중간 표현(Intermediate Representation (IR))로 변환하기.
	- 실제 분석 수행
		- 종속성 분석, 프로그램 분할과 같은 부분 또는 전체 프로그램 정적 분석.
		- Overflow가 일어날 수 있을 때까지 실행할 수 있는 것 처럼 프로그램의 상태공간 분석.
		- 위 두 예시의 결합. (Overflow를 찾을 때까지 프로그램 실행)

angr는 이러한 문제를 해결하기 위한 요소가 있으며, 이 문서는 어떻게 작동하는지 사용자가 원하는 목표를 이룰 수 있도록 설명합니다.

### 시작하기

설치 방법은 [여기]()에서 찾을 수 있습니다.

### 인용

angr는 학업에 사용하는 경우 논문을 인용해 주세요.

```
@article{shoshitaishvili2016state,
  title={SoK: (State of) The Art of War: Offensive Techniques in Binary Analysis},
  author={Shoshitaishvili, Yan and Wang, Ruoyu and Salls, Christopher and Stephens, Nick and Polino, Mario and Dutcher, Audrey and Grosen, John and Feng, Siji and Hauser, Christophe and Kruegel, Christopher and Vigna, Giovanni},
  booktitle={IEEE Symposium on Security and Privacy},
  year={2016}
}

@article{stephens2016driller,
  title={Driller: Augmenting Fuzzing Through Selective Symbolic Execution},
  author={Stephens, Nick and Grosen, John and Salls, Christopher and Dutcher, Audrey and Wang, Ruoyu and Corbetta, Jacopo and Shoshitaishvili, Yan and Kruegel, Christopher and Vigna, Giovanni},
  booktitle={NDSS},
  year={2016}
}

@article{shoshitaishvili2015firmalice,
  title={Firmalice - Automatic Detection of Authentication Bypass Vulnerabilities in Binary Firmware},
  author={Shoshitaishvili, Yan and Wang, Ruoyu and Hauser, Christophe and Kruegel, Christopher and Vigna, Giovanni},
  booktitle={NDSS},
  year={2015}
}

```

### 지원

angr를 사용하는데 도움을 받으려면 아래를 참고해 주세요.

- Mail: angr@lists.cs.ucsb.edu
- Slack channel: [angr.slack.com](https://angr.slack.com/)
- IRC channel: #angr on [freenode](https://freenode.net/)
# 2_Built-in Analyses

## Identifier

Identifier는 CGC 바이너리에서 common library function을 식별하기 위해 테스트 케이스를 사용합니다. 스택의 변수/인자에 대한 기본 정보를 찾아 사전에 필터링합니다. 스택 변수에 대한 정보는 일반적으로 다른 프로젝트에서 유용할 수 있습니다.

```python
>>> import angr

# get all the matches
>>> p = angr.Project("../binaries/tests/i386/identifiable")
>>> idfer = p.analyses.Identifier()
# note that .run() yields results so make sure to iterate through them or call list() etc
>>> for addr, symbol in idfer.run():
...     print hex(addr), symbol

0x8048e60 memcmp
0x8048ef0 memcpy
0x8048f60 memmove
0x8049030 memset
0x8049320 fdprintf
0x8049a70 sprintf
0x8049f40 strcasecmp
0x804a0f0 strcmp
0x804a190 strcpy
0x804a260 strlen
0x804a3d0 strncmp
0x804a620 strtol
0x804aa00 strtol
0x80485b0 free
0x804aab0 free
0x804aad0 free
0x8048660 malloc
0x80485b0 free
```

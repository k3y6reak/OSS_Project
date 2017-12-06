### 바이너리 로딩 - CLE와 angr project

저번 문서에서는 angr의 로딩 기능을 자세히 알아보지 못했습니다. `/bin/true`를 로드한 다음 다시 로드할 때 공유 라이브러리 없이 했습니다. 또한 `proj.loader`를 사용해봤는데 인터페이스의 작은 차이들을 살펴보도록 하겠습니다.

angr의 CLE에 대해서 간략히 알아봤는데 CLE는 "CLE Loads Everything"의 약자이며 바이너리와 라이브러리를 가져와서 작업하기 쉬운 방식으로 사용됩니다.

#### loader

다시 로드하고 로드와 상호작용하는 방법을 알아보겠습니다.

```python
>>> import angr, monkeyhex
>>> proj = angr.Project('/bin/true')
>>> proj.loader
<Loaded true, maps [0x400000:0x5008000]>
```

##### 로드된 객체

`cle.loader`는 로드된 바이너리 객체의 전체 집합을 나타내며 메모리 공간에 로드 및 매핑 됩니다.
각 바이너리 객체는 `cle.Backend`에 의해서 로드됩니다. 

CLE가 로드한 객체의 목록을 `loader.all_objects`로 확인 할 수 있습니다.

```python
# All loaded objects
>>> proj.loader.all_objects
[<ELF Object fauxware, maps [0x400000:0x60105f]>,
 <ELF Object libc.so.6, maps [0x1000000:0x13c42bf]>,
 <ELF Object ld-linux-x86-64.so.2, maps [0x2000000:0x22241c7]>,
 <ELFTLSObject Object cle##tls, maps [0x3000000:0x300d010]>,
 <KernelObject Object cle##kernel, maps [0x4000000:0x4008000]>,
 <ExternObject Object cle##externs, maps [0x5000000:0x5008000]>

# This is the "main" object, the one that you directly specified when loading the project
>>> proj.loader.main_object
<ELF Object true, maps [0x400000:0x60105f]>

# This is a dictionary mapping from shared object name to object
>>> proj.loader.shared_objects
{ 'libc.so.6': <ELF Object libc.so.6, maps [0x1000000:0x13c42bf]>
  'ld-linux-x86-64.so.2': <ELF Object ld-linux-x86-64.so.2, maps [0x2000000:0x22241c7]>}

# Here's all the objects that were loaded from ELF files
# If this were a windows program we'd use all_pe_objects!
>>> proj.loader.all_elf_objects
[<ELF Object true, maps [0x400000:0x60105f]>,
 <ELF Object libc.so.6, maps [0x1000000:0x13c42bf]>,
 <ELF Object ld-linux-x86-64.so.2, maps [0x2000000:0x22241c7]>]

# Here's the "externs object", which we use to provide addresses for unresolved imports and angr internals
>>> proj.loader.extern_object
<ExternObject Object cle##externs, maps [0x5000000:0x5008000]>

# This object is used to provide addresses for emulated syscalls
>>> proj.loader.kernel_object
<KernelObject Object cle##kernel, maps [0x4000000:0x4008000]>

# Finally, you can to get a reference to an object given an address in it
>>> proj.loader.find_object_containing(0x400000)
<ELF Object true, maps [0x400000:0x60105f]>
```

객체와 직접 상호작용하여 메타데이터를 추출 할 수 있습니다.

```python
>>> obj = proj.loader.main_object

# The entry point of the object
>>> obj.entry
0x400580

>>> obj.min_addr, obj.max_addr
(0x400000, 0x60105f)

# Retrieve this ELF's segments and sections
>>> obj.segments
<Regions: [<ELFSegment offset=0x0, flags=0x5, filesize=0xa74, vaddr=0x400000, memsize=0xa74>,
           <ELFSegment offset=0xe28, flags=0x6, filesize=0x228, vaddr=0x600e28, memsize=0x238>]>
>>> obj.sections
<Regions: [<Unnamed | offset 0x0, vaddr 0x0, size 0x0>,
           <.interp | offset 0x238, vaddr 0x400238, size 0x1c>,
           <.note.ABI-tag | offset 0x254, vaddr 0x400254, size 0x20>,
            ...etc

# You can get an individual segment or section by an address it contains:
>>> obj.find_segment_containing(obj.entry)
<ELFSegment offset=0x0, flags=0x5, filesize=0xa74, vaddr=0x400000, memsize=0xa74>
>>> obj.find_section_containing(obj.entry)
<.text | offset 0x580, vaddr 0x400580, size 0x338>

# Get the address of the PLT stub for a symbol
>>> addr = obj.plt['__libc_start_main']
>>> addr
0x400540
>>> obj.reverse_plt[addr]
'__libc_start_main'

# Show the prelinked base of the object and the location it was actually mapped into memory by CLE
>>> obj.linked_base
0x400000
>>> obj.mapped_base
0x400000
```

##### symbols과 재배치

CLE를 이용하여 sybol을 작업할 수 있습니다. 심볼은 실행 포맷의 기본이되는 개념입니다.

CLE에서 `loader.find_symbol`을 이용하여 심볼을 쉽게 얻을 수 있습니다.

```python
>>> malloc = proj.loader.find_symbol('malloc')
>>> malloc
<Symbol "malloc" in libc.so.6 at 0x1054400>
```

심볼의 주소는 3가지 방식으로 출력할 수 있습니다.

 - `.rebased_addr`은 전역 주소 공간을 나타냅니다.
 - `.linked_addr`은 바이너리에 미리 링킹된 상대적인 주소입니다.
 - `.relative_addr`은 객체 기준의 상대적인 주소입니다. RVA(relative virtual address)입니다.

```python
>>> malloc.name
'malloc'

>>> malloc.owner_obj
<ELF Object libc.so.6, maps [0x1000000:0x13c42bf]>

>>> malloc.rebased_addr
0x1054400
>>> malloc.linked_addr
0x54400
>>> malloc.relative_addr
0x54400
```

추가적으로 디버그 정보도 제공합니다. libc는 malloc을 export하고 메인 바이너리에 의존합니다. 만약 CLE가 malloc 심볼을 메인 객체에 직접 준다면 import 입니다.

```python
>>> malloc.is_export
True
>>> malloc.is_import
False

# On Loader, the method is find_symbol because it performs a search operation to find the symbol.
# On an individual object, the method is get_symbol because there can only be one symbol with a given name.
>>> main_malloc = proj.loader.main_object.get_symbol("malloc")
>>> main_malloc
<Symbol "malloc" in true (import)>
>>> main_malloc.is_export
False
>>> main_malloc.is_import
True
>>> main_malloc.resolvedby
<Symbol "malloc" in libc.so.6 at 0x1054400>
```

export, import 관계를 메모리에 저장해야 할 경우 재배치에 의해 처리됩니다.

```python
# Relocations don't have a good pretty-printing, so those addresses are python-internal, unrelated to our program
>>> proj.loader.shared_objects['libc.so.6'].imports
{u'__libc_enable_secure': <cle.backends.relocations.generic.GenericJumpslotReloc at 0x4221fb0>,
 u'__tls_get_addr': <cle.backends.relocations.generic.GenericJumpslotReloc at 0x425d150>,
 u'_dl_argv': <cle.backends.relocations.generic.GenericJumpslotReloc at 0x4254d90>,
 u'_dl_find_dso_for_object': <cle.backends.relocations.generic.GenericJumpslotReloc at 0x425d130>,
 u'_dl_starting_up': <cle.backends.relocations.generic.GenericJumpslotReloc at 0x42548d0>,
 u'_rtld_global': <cle.backends.relocations.generic.GenericJumpslotReloc at 0x4221e70>,
 u'_rtld_global_ro': <cle.backends.relocations.generic.GenericJumpslotReloc at 0x4254210>}
```

#### 로딩 옵션

`angr.Project`로 로딩할 때 `cle.Loader`에 옵션을 전달하려면 Project로 전달하면 CLE로 전달됩니다

##### 기본 옵션

CLE는 자동적으로 공유 라이브러리의 의존을 활성화하거나 비활성화를 할 수 있습니다. 추가적으로 `except_missing_libs`가 true로 설정 돼 있으면 공유 라이브러리에 종속적인 바이너리가 있을 때 마다 예외가 발생합니다.

공유 라이브러이 종속성에 의존이 해결되지 않을 때 `force_load_libs`에 문자열로 전달되고 처리할 수 있습니다. 또한 `skip_libs`에 문자열로 전달할 경우 의존성을 해결할 수 있습니다. 추가적으로, `custom_ld_path`에 전달하는 경우 공유 라이브러리를 위한 경로를 찾습니다.

##### 바이너리 별 옵션

특정 바이너리 객체에만 적용되게  `main_ops`와 `lib_opts`을 이용할 수 있습니다. 

 - `backend` : 클래스 또는 이름으로 사용할 백엔드
 - `custom_base_addr` : 사용할 기본 주소
 - `custom_arch` : 사용할 아키텍쳐 이름

예시)

```python
angr.Project(main_opts={'backend': 'ida', 'custom_arch': 'i386'}, lib_opts={'libc.so.6': {'backend': 'elf'}})
```

##### 백엔드

CLE는 ELF, PE, CGC, Mach-O, ELF 코어 덤프 파일을 정적으로 로드하고 마찬가지로 IDA와 함께 로드할 수 있습니다.

일부 백엔드는 아키텍처를 자동으로 찾을 수 없기 때문에 `custom_arch`를 지정해야 합니다.

| 백엔드 | 설명 | custtom_arch 필요여부 |
| --- | --- | --- |
| elf | PyELFTools 기반 ELF 정적 로더 | no |
| pe | PEFile 기반 PE 정적 로더 | no |
| mach-o | Mach-O 정적 로더. dynamic linking이나 리베이스를 지원하지 않습니다. | no |
| cgc | Cyber Grand Challenge 바이너리 정적 로더 | no |
| backedcgc | CGC 바이너리를 위한 정적 로더 | no |
| ida | IDA 인스턴스  | yes |
| blob | 메모리 안에 파일을 로드 | yes |


#### Symbolic 함수 요약

기본적으로 Project는 `SimProcedures` symbolic 요약에 의해 외부 호출을 라이브러리 함수로 대체합니다. 내장 프로시저인 `angr.SIM_PROCEDURES` 딕셔너리에서 사용할 수 있습니다.
libc, posix, win32, stubs 패키지와 라이브러리 함수 이름을 입력합니다. 실제 라이브러리 함수 대신에 SimProcdure를 실행하면 많은 분석을 쉽게 할 수 있습니다.

주어진 함수를 위한 가낭한 요약이 없는 경우:
 - `auto_load_libs`이면 실제 라이브러리 함수가 실행됩니다. blic의 일부 함수는 분석하기 매우 복잡하고 실행하려고 하는 경로의 수가 엄청나게 증가할 수 있습니다.
 - `auto_load_libs`가 `False`일 경우 Project는 `ReturnUnconstrained`라 불리는 SimProcdeure에 의해 해결됩니다.
 - `angr.Project`가 아닌 `cle.Loader` 를 사용하는 `use_sim_procedures`가 `False`이면 (기본값은 `True`) SimProcedures와 함께 외부 객체에 의해 symbol이 제공됩니다.


##### 후킹

이 방식은 후킹이라 불리는 python 요약과 함께 라이브러리 코드로 대체될 수 있습니다. 또한 이를 수행할 수 있습니다.
모든 단계에서 angr가 현재 주소를 검사하고 일치하는 경우 해당 주소에서 바이너리 코드 대신 후킹을 진행합니다. `proj.hook(addr, hook)`의 `hook`은 SimProcedure 인스턴스입니다.

```python
>>> stub_func = angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained'] # this is a CLASS
>>> proj.hook(0x10000, stub_func())  # hook with an instance of the class

>>> proj.is_hooked(0x10000)            # these functions should be pretty self-explanitory
True
>>> proj.unhook(0x10000)
>>> proj.hooked_by(0x10000)
<ReturnUnconstrained>

>>> @proj.hook(0x20000, length=5)
... def my_hook(state):
...     state.regs.rax = 1

>>> proj.is_hooked(0x20000)
True
```


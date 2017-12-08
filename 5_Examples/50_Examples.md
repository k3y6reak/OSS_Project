## 예제

angr를 이용해 실제 해킹대회 및 바이너리를 분석할 때 어떻게 사용되는지 알아보겠습니다.

```c
#include <stdio.h>

int main(void)
{
	int num = 0;
	printf("Input : ");
	scanf("%d", &num);

	if(num == 12)
	{
		printf("Ok!\n");
	}
	else
	{
		printf("No");
	}

	return 0;
}
```

위 c코드를 살펴보면 Ok!가 출력되려면 num 값이 12가 되야 하는 것을 쉽게 알 수 있습니다. 하지만 코드는 주어지지 않고 바이너리만 제공되는 경우 어떻게 분석을 해야 할까요?

실제 해당 코드를 컴파일 하고 gdb를 이용해 어셈블리어를 살펴보겠습니다.

```gdb
pwndbg> b*main
Breakpoint 1 at 0x400646
pwndbg> r
Starting program: /home/k3y6reak/Desktop/test 

Breakpoint 1, 0x0000000000400646 in main ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
[─────────────────────────────────────────────────────────────────────────REGISTERS─────────────────────────────────────────────────────────────────────────]
*RAX  0x400646 (main) ◂— push   rbp
 RBX  0x0
 RCX  0x0
*RDX  0x7fffffffdde8 —▸ 0x7fffffffe18d ◂— 'XDG_VTNR=7'
*RDI  0x1
*RSI  0x7fffffffddd8 —▸ 0x7fffffffe171 ◂— 0x336b2f656d6f682f ('/home/k3')
*R8   0x400740 (__libc_csu_fini) ◂— ret    
*R9   0x7ffff7de7ab0 (_dl_fini) ◂— push   rbp
*R10  0x846
*R11  0x7ffff7a2d740 (__libc_start_main) ◂— push   r14
*R12  0x400550 (_start) ◂— xor    ebp, ebp
*R13  0x7fffffffddd0 ◂— 0x1
 R14  0x0
 R15  0x0
*RBP  0x4006d0 (__libc_csu_init) ◂— push   r15
*RSP  0x7fffffffdcf8 —▸ 0x7ffff7a2d830 (__libc_start_main+240) ◂— mov    edi, eax
*RIP  0x400646 (main) ◂— push   rbp
[──────────────────────────────────────────────────────────────────────────DISASM───────────────────────────────────────────────────────────────────────────]
 ► 0x400646 <main>       push   rbp                           <0x4006d0>
   0x400647 <main+1>     mov    rbp, rsp
   0x40064a <main+4>     sub    rsp, 0x10
   0x40064e <main+8>     mov    rax, qword ptr fs:[0x28]
   0x400657 <main+17>    mov    qword ptr [rbp - 8], rax
   0x40065b <main+21>    xor    eax, eax
   0x40065d <main+23>    mov    dword ptr [rbp - 0xc], 0
   0x400664 <main+30>    mov    edi, 0x400754
   0x400669 <main+35>    mov    eax, 0
   0x40066e <main+40>    call   printf@plt                    <0x400510>
 
   0x400673 <main+45>    lea    rax, [rbp - 0xc]
[───────────────────────────────────────────────────────────────────────────STACK───────────────────────────────────────────────────────────────────────────]
00:0000│ rsp  0x7fffffffdcf8 —▸ 0x7ffff7a2d830 (__libc_start_main+240) ◂— mov    edi, eax
01:0008│      0x7fffffffdd00 ◂— 0x0
02:0010│      0x7fffffffdd08 —▸ 0x7fffffffddd8 —▸ 0x7fffffffe171 ◂— 0x336b2f656d6f682f ('/home/k3')
03:0018│      0x7fffffffdd10 ◂— 0x100000000
04:0020│      0x7fffffffdd18 —▸ 0x400646 (main) ◂— push   rbp
05:0028│      0x7fffffffdd20 ◂— 0x0
06:0030│      0x7fffffffdd28 ◂— 0x7ce28d65fee07d37
07:0038│      0x7fffffffdd30 —▸ 0x400550 (_start) ◂— xor    ebp, ebp
[─────────────────────────────────────────────────────────────────────────BACKTRACE─────────────────────────────────────────────────────────────────────────]
 ► f 0           400646 main
   f 1     7ffff7a2d830 __libc_start_main+240
Breakpoint *main

```

```gdb
pwndbg> disassemble main
Dump of assembler code for function main:
=> 0x0000000000400646 <+0>:	push   rbp
   0x0000000000400647 <+1>:	mov    rbp,rsp
   0x000000000040064a <+4>:	sub    rsp,0x10
   0x000000000040064e <+8>:	mov    rax,QWORD PTR fs:0x28
   0x0000000000400657 <+17>:	mov    QWORD PTR [rbp-0x8],rax
   0x000000000040065b <+21>:	xor    eax,eax
   0x000000000040065d <+23>:	mov    DWORD PTR [rbp-0xc],0x0
   0x0000000000400664 <+30>:	mov    edi,0x400754
   0x0000000000400669 <+35>:	mov    eax,0x0
   0x000000000040066e <+40>:	call   0x400510 <printf@plt>
   0x0000000000400673 <+45>:	lea    rax,[rbp-0xc]
   0x0000000000400677 <+49>:	mov    rsi,rax
   0x000000000040067a <+52>:	mov    edi,0x40075d
   0x000000000040067f <+57>:	mov    eax,0x0
   0x0000000000400684 <+62>:	call   0x400530 <__isoc99_scanf@plt>
   0x0000000000400689 <+67>:	mov    eax,DWORD PTR [rbp-0xc]
   0x000000000040068c <+70>:	cmp    eax,0xc
   0x000000000040068f <+73>:	jne    0x40069d <main+87>
   0x0000000000400691 <+75>:	mov    edi,0x400760
   0x0000000000400696 <+80>:	call   0x4004f0 <puts@plt>
   0x000000000040069b <+85>:	jmp    0x4006a7 <main+97>
   0x000000000040069d <+87>:	mov    edi,0x400764
   0x00000000004006a2 <+92>:	call   0x4004f0 <puts@plt>
   0x00000000004006a7 <+97>:	mov    eax,0x0
   0x00000000004006ac <+102>:	mov    rdx,QWORD PTR [rbp-0x8]
   0x00000000004006b0 <+106>:	xor    rdx,QWORD PTR fs:0x28
   0x00000000004006b9 <+115>:	je     0x4006c0 <main+122>
   0x00000000004006bb <+117>:	call   0x400500 <__stack_chk_fail@plt>
   0x00000000004006c0 <+122>:	leave  
   0x00000000004006c1 <+123>:	ret    
End of assembler dump.

```

위 어셈을 확인해 보면 `0x000000000040068c <+70>:	cmp    eax,0xc`에서 0xc와 비교하고 있습니다. 해당 위치에서 조건을 확인한 다는 것을 할 수 있고 이를 직접 디버거로 살펴봐야 합니다.
만약 num 값을 비교하기 전 사람이 쉽게 풀지 못하는 수학적 연산이 존재한다면 어떻게 할까요?

angr를 이용하면 하나씩 어셈블리어를 살펴보지 않아도 찾아가야할 주소와 찾아가지 말아야 할 주소만을 이용해 값을 쉽게 찾을 수 있습니다.

위 예제에서는 `0x400691`로 이동해야 "Ok"가 출력되고 `0x40069d`로 이동하면 "No"가 출력되는 것을 알 수 있습니다.

```python
import angr

def main():
	proj = angr.Project('./test', load_options={'auto_load_libs': False})
	path_group = proj.factory.path_group(threads=4)
	path_group.explore(find=0x40096b, avoid=0x40069d)
	return path_group.found[0].state.posix.dumps(1)

if __name__ == '__main__':
	print repr(main())
```


위와 같이 angr를 import 하고 find에 0x400691을 넣고 avoid에 0x40069d를 넣고 실행합니다.

```bash
root@ubuntu:/home/k3y6reak/Desktop# python crack.py 
WARNING | 2017-12-08 20:00:44,866 | simuvex.plugins.symbolic_memory | Concretizing symbolic length. Much sad; think about implementing.
'Input : Ok!\n'
```

단순히 python 코드만을 이용해 찾아갈 주소와 피해야할 주소만을 이용하여 `ok`가 출력된 것을 볼 수 있다. 이렇게 특정 입력값을 직접 분석하지 않고 찾아갈 수 있다.


또 다른 예로는 실제 해킹 대회 DEFCON에서 출제된 baby-re 라는 문제를 풀어보겠다.

baby-re는 IDA로 디컴파일한 결과를 보면 아래와 같다.

![baby_re_1](https://github.com/k3y6reak/OSS_Project/blob/master/img/baby_re_1.png)

0부터 12까지 총 13개의 값을 입력하고 `CeckSolution` 값이 true가 돼야 flag를 출력해준다.

구조를 살펴보면 아래와 같다.

![baby_re_2](https://github.com/k3y6reak/OSS_Project/blob/master/img/baby_re_2.png)

flag를 출력해 주는 부분과 wrong을 출력해 주는 부분이 있는 것을 알 수 있다. find는 `0x40294b` avoid는 `0x402941`로 하면 된다.

```python
import angr

def main():
	proj = angr.Project('./test', load_options={'auto_load_libs': False})
	path_group = proj.factory.path_group(threads=4)
	path_group.explore(find=0x40294b, avoid=0x402941)
	return path_group.found[0].state.posix.dumps(1)

if __name__ == '__main__':
	print repr(main())
```

위 python 코드를 작성하여 실행하면 아래와 같이 Math is hard!가 출력된다.

![baby_re_3](https://github.com/k3y6reak/OSS_Project/blob/master/img/baby_re_3.png)
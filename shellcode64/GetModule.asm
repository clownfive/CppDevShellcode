.code

numadd proc
	mov rax, rcx
	add rax, rdx
	ret
numadd endp


GetModuleKernel proc
	xor r8, r8
	xor rax, rax
	xor r10, r10
	add r10, 60h
	mov rax, gs:[r10]     ;通过GS寄存器获取PEB基址
	mov rax, [rax + 18h]  ;获取PEB中Ldr数据结构的基址
	mov rax, [rax + 10h]  ;获取Ldr数据结构的InmemoryOrderModuleList字段的基址
	mov rax, [rax]		   ;获取InmemoryOrderModuleList链表第一个节点 用这个取就是ntdll的基址
	mov rax, [rax]		   ;获取InmemoryOrderModuleList链表第一个节点  用这个就是kernen32的基址
	mov rax, [rax + 30h]  ;获取节点中BaseAddress字段，既kernel32.dll的基址
	ret
GetModuleKernel endp



end
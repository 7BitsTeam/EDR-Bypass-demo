.code

EXTERN SW3_GetSyscallNumber: PROC

EXTERN SW3_GetSyscallAddress: PROC

NtCreateProcess PROC
	int 3
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0F5A717B7h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r15, rax                           ; Save the address of the syscall
	mov ecx, 0F5A717B7h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15                                ; Jump to -> Invoke system call.
NtCreateProcess ENDP

NtCreateThreadEx PROC
	int 3
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 094AF2795h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r15, rax                           ; Save the address of the syscall
	mov ecx, 094AF2795h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15                                ; Jump to -> Invoke system call.
NtCreateThreadEx ENDP

NtOpenProcess PROC
	int 3
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 04E2E47B4h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r15, rax                           ; Save the address of the syscall
	mov ecx, 04E2E47B4h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15                                ; Jump to -> Invoke system call.
NtOpenProcess ENDP

NtOpenProcessToken PROC
	int 3
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 03DAF1132h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r15, rax                           ; Save the address of the syscall
	mov ecx, 03DAF1132h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15                                ; Jump to -> Invoke system call.
NtOpenProcessToken ENDP

NtTestAlert PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 00E94313Eh        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r15, rax                           ; Save the address of the syscall
	mov ecx, 00E94313Eh        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15                                ; Jump to -> Invoke system call.
NtTestAlert ENDP

NtOpenThread PROC
	int 3
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 01838D296h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r15, rax                           ; Save the address of the syscall
	mov ecx, 01838D296h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15                                ; Jump to -> Invoke system call.
NtOpenThread ENDP

NtSuspendProcess PROC
	int 3
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0D31DF082h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r15, rax                           ; Save the address of the syscall
	mov ecx, 0D31DF082h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15                                ; Jump to -> Invoke system call.
NtSuspendProcess ENDP

NtSuspendThread PROC
	int 3
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 09947D46Eh        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r15, rax                           ; Save the address of the syscall
	mov ecx, 09947D46Eh        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15                                ; Jump to -> Invoke system call.
NtSuspendThread ENDP

NtResumeProcess PROC
	int 3
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 05DC3545Eh        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r15, rax                           ; Save the address of the syscall
	mov ecx, 05DC3545Eh        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15                                ; Jump to -> Invoke system call.
NtResumeProcess ENDP

NtResumeThread PROC
	int 3
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 018BE9C9Fh        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r15, rax                           ; Save the address of the syscall
	mov ecx, 018BE9C9Fh        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15                                ; Jump to -> Invoke system call.
NtResumeThread ENDP

NtGetContextThread PROC
	int 3
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 017304B00h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r15, rax                           ; Save the address of the syscall
	mov ecx, 017304B00h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15                                ; Jump to -> Invoke system call.
NtGetContextThread ENDP

NtSetContextThread PROC
	int 3
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0B0A8F400h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r15, rax                           ; Save the address of the syscall
	mov ecx, 0B0A8F400h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15                                ; Jump to -> Invoke system call.
NtSetContextThread ENDP

NtClose PROC
	int 3
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 02DA5DAA8h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r15, rax                           ; Save the address of the syscall
	mov ecx, 02DA5DAA8h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15                                ; Jump to -> Invoke system call.
NtClose ENDP

NtReadVirtualMemory PROC
	int 3
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0105EDF09h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r15, rax                           ; Save the address of the syscall
	mov ecx, 0105EDF09h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15                                ; Jump to -> Invoke system call.
NtReadVirtualMemory ENDP

NtWriteVirtualMemory PROC
	int 3
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 007950903h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r15, rax                           ; Save the address of the syscall
	mov ecx, 007950903h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15                                ; Jump to -> Invoke system call.
NtWriteVirtualMemory ENDP

NtAllocateVirtualMemory PROC
	int 3
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 039913313h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r15, rax                           ; Save the address of the syscall
	mov ecx, 039913313h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15                                ; Jump to -> Invoke system call.
NtAllocateVirtualMemory ENDP

NtProtectVirtualMemory PROC
	int 3
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 01D8F0903h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r15, rax                           ; Save the address of the syscall
	mov ecx, 01D8F0903h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15                                ; Jump to -> Invoke system call.
NtProtectVirtualMemory ENDP

NtFreeVirtualMemory PROC
	int 3
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 03DA10713h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r15, rax                           ; Save the address of the syscall
	mov ecx, 03DA10713h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15                                ; Jump to -> Invoke system call.
NtFreeVirtualMemory ENDP

NtQuerySystemInformation PROC
	int 3
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0148A1E1Fh        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r15, rax                           ; Save the address of the syscall
	mov ecx, 0148A1E1Fh        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15                                ; Jump to -> Invoke system call.
NtQuerySystemInformation ENDP

NtQueryDirectoryFile PROC
	int 3
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0A0B4CE7Ch        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r15, rax                           ; Save the address of the syscall
	mov ecx, 0A0B4CE7Ch        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15                                ; Jump to -> Invoke system call.
NtQueryDirectoryFile ENDP

NtQueryInformationFile PROC
	int 3
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 05A3A34BEh        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r15, rax                           ; Save the address of the syscall
	mov ecx, 05A3A34BEh        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15                                ; Jump to -> Invoke system call.
NtQueryInformationFile ENDP

NtQueryInformationProcess PROC
	int 3
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0C541D0C0h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r15, rax                           ; Save the address of the syscall
	mov ecx, 0C541D0C0h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15                                ; Jump to -> Invoke system call.
NtQueryInformationProcess ENDP

NtQueryInformationThread PROC
	int 3
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0B48FBE21h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r15, rax                           ; Save the address of the syscall
	mov ecx, 0B48FBE21h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15                                ; Jump to -> Invoke system call.
NtQueryInformationThread ENDP

NtCreateSection PROC
	int 3
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 01E971E05h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r15, rax                           ; Save the address of the syscall
	mov ecx, 01E971E05h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15                                ; Jump to -> Invoke system call.
NtCreateSection ENDP

NtOpenSection PROC
	int 3
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0CE38D0D5h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r15, rax                           ; Save the address of the syscall
	mov ecx, 0CE38D0D5h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15                                ; Jump to -> Invoke system call.
NtOpenSection ENDP

NtMapViewOfSection PROC
	int 3
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 008972E47h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r15, rax                           ; Save the address of the syscall
	mov ecx, 008972E47h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15                                ; Jump to -> Invoke system call.
NtMapViewOfSection ENDP

NtUnmapViewOfSection PROC
	int 3
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0164DF406h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r15, rax                           ; Save the address of the syscall
	mov ecx, 0164DF406h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15                                ; Jump to -> Invoke system call.
NtUnmapViewOfSection ENDP

NtAdjustPrivilegesToken PROC
	int 3
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 043DD4B40h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r15, rax                           ; Save the address of the syscall
	mov ecx, 043DD4B40h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15                                ; Jump to -> Invoke system call.
NtAdjustPrivilegesToken ENDP

NtDeviceIoControlFile PROC
	int 3
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 03F3657B2h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r15, rax                           ; Save the address of the syscall
	mov ecx, 03F3657B2h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15                                ; Jump to -> Invoke system call.
NtDeviceIoControlFile ENDP

NtQueueApcThread PROC
	int 3
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 03E860C37h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r15, rax                           ; Save the address of the syscall
	mov ecx, 03E860C37h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15                                ; Jump to -> Invoke system call.
NtQueueApcThread ENDP

NtWaitForMultipleObjects PROC
	int 3
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 051256B89h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
	mov r15, rax                           ; Save the address of the syscall
	mov ecx, 051256B89h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15                                ; Jump to -> Invoke system call.
NtWaitForMultipleObjects ENDP

end
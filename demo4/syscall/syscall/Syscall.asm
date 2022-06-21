.code
	SysNtCreateFile proc
			mov r10, rcx
			mov eax, 55h
			syscall
			ret
	SysNtCreateFile endp
end
.code


bye :
ret

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
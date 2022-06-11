使用字符串加密、异或加密、沙箱绕过方式进行bypass AV。

dem2 使用 CreateThread方式创建新进程极易被拦截，改用EtwpCreateEtwThread加载shellcode，改版的程序为demo3.
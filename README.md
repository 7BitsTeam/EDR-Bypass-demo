# EDR-Bypass-demo
Some demos to bypass EDRs or AVs by 78itsT3@m

## 本文为7bits系列文章《红队队开发基础-基础免杀》的示例代码

### demo 1-3 为《红队队开发基础-基础免杀（一）》的内容

- demo1：

  c++代码，使用disableETW，shellcode加密，隐藏导入表的免杀方式对shellcode进行免杀

- demo2:

  c#代码，使用字符串加密、异或加密、沙箱绕过方式进行bypass AV。

- demo3:

  c#代码，优化demo2的shellcode加载方式，修改SharpInjector，使用EtwpCreateEtwThread加载shellcode。

### demo 4 为《红队队开发基础-基础免杀（二）》的内容

- demo4：

  c++代码，利用规避常见的恶意API调用模式，规避“系统调用标记”技术，结合demo 1 2 3 中的静态混淆技术进行免杀。

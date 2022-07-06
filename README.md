# EDR-Bypass-demo
Some demos to bypass EDRs or AVs by 78itsT3@m

## 本文为7bits系列文章《红队队开发基础-基础免杀》的示例代码

### 欢迎关注我们的公众号 - Zbits2022

![](/images/qrcode.jpg)

### demo 1-3 为《红队队开发基础-基础免杀（一）》的内容

- demo1：

  c++代码，使用disableETW，shellcode加密，隐藏导入表的免杀方式对shellcode进行免杀

- demo2:

  c#代码，使用字符串加密、异或加密、沙箱绕过方式进行bypass AV。

- demo3:

  c#代码，优化demo2的shellcode加载方式，修改SharpInjector，使用EtwpCreateEtwThread加载shellcode。

### demo 4-5 为《红队队开发基础-基础免杀（二）》的内容

- demo4：

  c++代码，最简单的syscall例子

- demo5:

  c++代码，使用SysWhispers3的jump方法，绕过对syscall的静态检查

### demo 6 为《红队开发基础-基础免杀（三）》的内容

- demo6:

  c++代码，修改RefleXXion使其对user32.dll进行unhook。

### chapter4 demo1-4为《红队开发基础-基础免杀（四）》的内容

下面的例子均是忽略流量特征的情况：

- demo1：base64+xor混淆shellcode，过360，火绒。

![](/images/360.png)

![](/images/hr.png)

- demo2：加强了静态混淆，过definder，麦咖啡。

![](/images/def.png)

![](/images/mcafee.png)

- demo3：加入syscall及apc调用方式，过卡巴斯基edr

![](/images/kar.png)

- demo4：加入beacon的内存加密，过eset edr

![](/images/eset.png)



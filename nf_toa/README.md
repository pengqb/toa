# nf_toa
toa implemented by netfilter,Complete example
在openeuler 4.19 上验证通过
可以实现lb增加toa,servcer解析toa。
ipv6实现还不支持。

	- lb侧，下载`nf_to_add.ko`文件
	- 使用 `sudo insmod nf_to_add.ko` 命令进行安装
		-  `sudo insmod nf_to_add.ko port=3306` 只对3306端口进行流出封装
		-  `sudo insmod nf_to_add.ko port=3306,3309` 对3306-3309端口进行流出封装, 支持端口区间
		-  `sudo insmod nf_to_add.ko outPort=3306,3323` 对3306,3323端口流出数据包进行封装,不支持端口区间
	- 使用 `sudo rmmod nf_to_add` 命令进行卸载
	- server侧，下载`nf_toa.ko`文件
	- 使用 `sudo insmod nf_toa.ko` 命令进行安装
		-  `sudo insmod nf_toa.ko port=3306` 只对3306端口进行流入读取
		-  `sudo insmod nf_toa.ko port=3306,3309` 对3306-3309端口进行流入读取, 支持端口区间
		-  `sudo insmod nf_toa.ko inPort=3306,3323` 对3306,3323端口流入数据包进行读取,不支持端口区间
	- 使用 `sudo rmmod nf_toa` 命令进行卸载
	- 安装完成后通过dmesg -Tx -w 查看启动日志, 如发现`Custom tcp filter init successed`类似日志即启动成功
	- 内核应用可能导致系统蓝屏, 请注意系统版或修改后在使用。建议优先在测试环境测试完成后再应用到线上。
	- 测试时可以指定端口,当只有一台机器安装插件后telnet命令不可用, 两台都安装后telnet命令正常。
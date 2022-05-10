# DPDK

雪云网络定制

## 简介

Intel开源的快速包处理框架。官方介绍如下：


> DPDK is a set of libraries and drivers for fast packet processing.
> It supports many processor architectures and both FreeBSD and Linux.
>
> The DPDK uses the Open Source BSD-3-Clause license for the core libraries
> and drivers. The kernel components are GPL-2.0 licensed.
>
>  Please check the doc directory for release notes,
> API documentation, and sample application information.
>
> For questions and usage discussions, subscribe to: users@dpdk.org
> Report bugs and issues to the development mailing list: dev@dpdk.org

**雪云定制版本**相比**原版DPDK**支持了如下的功能：

* **Hybrid Dataplane**，满足All in One场景，实现业务、非业务流量互不干扰、性能互不影响
* **Userspace IO**，为雪云网络SDN整体设计提供技术实现基础
* 借助AF_XDP抽象硬件，广泛兼容各种网络设备，通用性增强

## minixdp驱动

此驱动是雪云网络为了兼容各种网络设备而设计，驱动位于驱动目录的`net/minixdp`中。

### 驱动全景图

思维导图由XMind绘制，按照代码执行的顺序绘画（前两层级除外），浏览时沿着向下看即可。

建议右键打开新页面看，图比较大。

![minixdp](./resources/minixdp.png)

### 驱动参数

| 参数键名     | 参数值类型  | 警告  | 参数值说明                                                                                    |
|----------|--------|-----|------------------------------------------------------------------------------------------|
| iface    | string |     | 关联的网络接口名称，例如`eth0`、`ens192`                                                              |
| xdp_prog | string | Y   | XDP程序路径，用于载入eBPF XDP程序分离数据包。该参数将会在后续版本移除，相应的字节码将会直接集成到驱动内部。同时，此参数必须要指定，否则DPDK会载入一个它自己的程序 |

**注意**：带有警告标记的，说明此设计后期已确定会存在破坏性改动。

### 验证

在接口正确配置后，会自动加载eBPF程序及其内部的Map，判断是否加载成功，可以使用`bpftool`工具查看。

使用`ip link`可以看到下边的内容，如果关联的接口均成功加载了XDP程序就会出现ID，就说明加载成功了。

```bash
6: ens1f2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdp qdisc mq state UP mode DEFAULT group default qlen 1000
    link/ether 00:25:90:ea:2b:6a brd ff:ff:ff:ff:ff:ff
    prog/xdp id 1070    <- 这里就是绑定的程序的ID，说明加载成功
    altname enp4s0f2
```

如果要验证是否正确加载了我们自己的程序，可以使用`bpftool`查看map。

```bash
$ sudo bpftool map show
295: perf_event_array  name arp_cache_map  flags 0x0    <- arp_cache_map 是ARP同步用的
        key 4B  value 4B  max_entries 1024  memlock 8192B
296: lpm_trie  name redirect_v4_map  flags 0x1    <- redirect_v4_map 是查找目标IPv4是否在需要重定向的路由中
        key 8B  value 1B  max_entries 1024  memlock 16384B
297: xskmap  name xsk_map  flags 0x0    <- xsk_map 是查找所在的队列关联的XSK
        key 4B  value 4B  max_entries 128  memlock 4096B
298: array  name entry.rodata  flags 0x480
        key 4B  value 7B  max_entries 1  memlock 4096B
        frozen
        pids dpdk-l2fwd(3728913)
```

只要能看到这几个Map同时存在，就能确定我们的eBPF程序加载成功了并且没有遇到问题。

## DPDK EAL参数说明

**注意**：仅在DPDK直接编译的二进制文件中有EAL参数，`DPE`在编译时会禁用EAL参数。

此部分为DPDK的EAL参数说明，我将拿example中的`l2fwd`这个示例程序来说明。此处，我使用的RTE_SDK不安装直接编译，因此得到的是一个全静态编译的文件，文件体积相当大（不剥离驱动足足有28M）。

### 参考执行命令

```bash
sudo ./examples/dpdk-l2fwd --vdev net_minixdp0,iface=ens1f2,xdp_prog=/home/xuegao/entry.c.o --vdev net_minixdp1,iface=ens1f3,xdp_prog=/home/xuegao/entry.c.o --no-huge --no-pci -m 128 --iova-mode=va --log-level pmd.net.minixdp:debug -- -p 3
```

### 命令分段解释

| 分段命令                                                             | 说明                                                                        |
|------------------------------------------------------------------|---------------------------------------------------------------------------|
| sudo                                                             | 一定需要root执行，否则无权限配置接口。需要注意的是，程序默认不检查uid，因此如果不以root执行，EAL初始化可能能通过，但是运行时会出问题 |
| ./examples/dpdk-l2fwd                                            | 编译出的二进制文件，此处我使用的example中的`l2fwd`示例程序                                      |
| --vdev net_minixdp0,iface=ens1f2,xdp_prog=/home/xuegao/entry.c.o | vdev接口信息，其中包含驱动名称、父接口名称、XDP程序路径                                           |
| --no-huge                                                        | 禁用巨页，有性能需求可以重新打开。嵌入式硬件会不支持                                                |
| --no-pci                                                         | 禁用PCI                                                                     |
| -m 128                                                           | 分配的内存大小，要结合程序调整，`DPE`设计会偏小一些                                              |
| --iova-mode=va                                                   | 内存地址模式，保持VA即可，兼容性考虑                                                       |
| --log-level pmd.net.minixdp:debug                                | 驱动日志等级                                                                    |
| --                                                               | ``--``前为EAL参数，后边为程序参数                                                     |

## 常见程序参数说明

除了EAL参数，还有一些其他程序内部的参数，此处我列举了一些DPDK中比较常见的参数来说明。

需要注意的是，`DPE`可能不会沿用这些参数，但是这些常用参数了解有助于测试example示例程序。

| 命令   | 说明                                                                         |
|------|----------------------------------------------------------------------------|
| -p 3 | 端口掩码（port mask），用于标识启动哪些接口，因为vdev接口默认可能是关闭的。此处的`3`二进制即为`0000 0011`，即开启两个端口 |

## 编译

### 所需依赖

操作系统建议Fedora 34。

安装依赖：

```bash
dnf groupinstall "Development Tools" -y
dnf install unzip vim curl wget -y
dnf install meson python3-pyelftools python3-pip numactl-devel libbpf-devel libpcap-devel openssl-devel -y
pip3 install -i https://pypi.tuna.tsinghua.edu.cn/simple ninja
```

### 编译参数

编译需要加参数，禁用掉不必要的驱动和库，可以大幅缩小二进制文件体积。完整编译驱动，二进制文件体积大概在28M左右，禁用不必要的东西后，可以缩小到3M左右。

```bash
meson build -Dexamples=l2fwd -Dplatform=generic -Denable_drivers=net/minixdp,mempool/bucket,mempool/ring,mempool/stack -Ddisable_libs=gpudev,power,vhost -Dmax_lcores=8 -Dtests=false
cd build
ninja
```

## 名次释义

此处对文中出现的一些自造词进行解释。

| 英文               | 中文简称  | 详细                                                                                             |
|------------------|-------|------------------------------------------------------------------------------------------------|
| Hybrid Dataplane | 混合数据面 | 借助Linux XSK实现对网络队列的预先分离和重定向，能够将仅业务需求的数据包转移到DPDK内部处理、其他保持原有转发路线，数据面就成了DPDK+Linux协同工作，因此命名为混合数据面 |
| Userspace IO     | 用户态IO | 借助独立于内核外部的缓冲区管理网络IO，因此命名为用户态IO                                                                 |


# `tyuTool`工具使用

> Tuya Uart Tool

---


## 使用

安装`poetry`，用来启动`python`的虚拟环境：`pip3 install poetry`

修改`python`版本，根据自己`linux`中的`python`版本修改`pyproject.toml`

请使用`python 3.8`，其他版本未验证

```
[tool.poetry.dependencies]
python = "3.8.10"
```

创建虚拟环境，在项目目录执行：`poetry install --no-dev`

给用户增加串口操作权限：`sudo usermod -aG dialout $USER`

**重启**一次虚拟机

在项目目录，启动虚拟环境：`poetry shell`

连接涂鸦设备，虚拟机引入该设备，查看是否引入：`ls /dev/tty*`


### 命令行使用

`python ./tyutool_cli.py -h`

支持烧录（`write`）和读取（`read`）两种操作方法

```shell
Usage: tyutool_cli.py [OPTIONS] COMMAND [ARGS]...

  Tuya Uart Tool.

Options:
  -d, --debug    Show debug message
  -v, --version  Show the version and exit.
  -h, --help     Show this message and exit.

Commands:
  write
  read
  upgrade
```


#### 烧录

示例：`python ./tyutool_cli.py write -d BK7231N -p /dev/ttyACM0 -b 2000000 -f ./bk.bin`

`python ./tyutool_cli.py write -h`

```
Options:
  -d, --device [BK7231N|RTL8720CF]
                                  Soc name
  -p, --port TEXT                 Target port  [required]
  -b, --baud INTEGER              Uart baud rate [115200]
  -s, --start <LAMBDA>            Flash address of start [0x11000]
  -f, --file TEXT                 file of BIN  [required]
  -h, --help                      Show this message and exit.
```


#### 读取

示例：`python ./tyutool_cli.py read -d bk7231n -p /dev/ttyACM0 -b 2000000 -s 0x11000 -l 0x200000 -f read.bin`

`python ./tyutool_cli.py read -h`

```
Options:
  -d, --device [BK7231N|RTL8720CF]
                                  Soc name
  -p, --port TEXT                 Target port  [required]
  -b, --baud INTEGER              Uart baud rate [115200]
  -s, --start <LAMBDA>            Flash address of start [0x11000]
  -l, --length <LAMBDA>           Flash read length [0x200000]
  -f, --file TEXT                 file of BIN  [required]
  -h, --help                      Show this message and exit.
```


### GUI使用

启动：`python ./tyutool_gui.py`


## 下载可执行程序

> [Linux-CLI](https://images.tuyacn.com/smart/embed/package/vscode/data/ide_serial/tyutool_cli.tar.gz)
>
> [Linux-GUI](https://images.tuyacn.com/smart/embed/package/vscode/data/ide_serial/tyutool_gui.tar.gz)
>
> [Windows-CLI](https://images.tuyacn.com/smart/embed/package/vscode/data/ide_serial/win_tyutool_cli.tar.gz)
>
> [Windows-GUI](https://images.tuyacn.com/smart/embed/package/vscode/data/ide_serial/win_tyutool_gui.tar.gz)
>
> [MAC-ARM64-CLI](https://images.tuyacn.com/smart/embed/package/vscode/data/ide_serial/darwin_arm64_tyutool_cli.tar.gz)
>
> [MAC-ARM64-GUI](https://images.tuyacn.com/smart/embed/package/vscode/data/ide_serial/darwin_arm64_tyutool_gui.tar.gz)
>
> [MAC-X86-CLI](https://images.tuyacn.com/smart/embed/package/vscode/data/ide_serial/darwin_x86_tyutool_cli.tar.gz)
>
> [MAC-X86-GUI](https://images.tuyacn.com/smart/embed/package/vscode/data/ide_serial/darwin_x86_tyutool_gui.tar.gz)

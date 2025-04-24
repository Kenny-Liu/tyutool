# `tyuTool`工具开发

> Tuya Uart Tool

---


## UI开发

调整ui使用命令：`pyside6-designer ./tyutool/gui/ui_main.ui`

ui文件转py文件：`pyside6-uic ./tyutool/gui/ui_main.ui -o ./tyutool/gui/ui_main.py`


## 新协议开发

`cp`一份`./tyutool/flash/xxxxx`，修改为目标芯片名称

完成`xxxxx_flash.py`中`do something`部分的内容

在`./tyutool/flash/flash_interface.py`中完成新协议配置


## 生成可执行文件

在虚拟环境中安装相关库：`poetry install`

执行脚本： `./tools/build_execute.sh`

会生成目录`dist`，其中`tyutool_cli`和`tyutool_gui`，为可执行文件。


## 更新logo

执行命令`python ./tools/logo2bytes.py`

会生成文件`./tyutool/gui/ui_logo.py`


## 更新升级文件

1. 首先修改`./tyutool/util/util.py`中的`TYUTOOL_VERSION`变量值，提交代码并打上`tag`

1. 分别在4个环境（Linux/Windows/Mac-x86/Mac-arm64）中执行命令（`./tools/build_package.sh`）

1. linux将生成的文件：`tyutool_cli.tar.gz`、`tyutool_gui.tar.gz`、`ideserial.json`、`upgrade_config.json`

1. windows将生成文件：`win_tyutool_cli.tar.gz`、`win_tyutool_gui.tar.gz`

1. Mac x86将生成文件：`darwin_x86_tyutool_cli.tar.gz`、`darwin_x86_tyutool_gui.tar.gz`

1. Mac arm64将生成文件：`darwin_arm64_tyutool_cli.tar.gz`、`darwin_arm64_tyutool_gui.tar.gz`

1. 检查`upgrade_config.json`文件中的版本号是否正确

1. 将上述**10个文件**上传[存储中心](https://bs-cn.tuya-inc.com:7799/cetus/file)，前缀为`smart/embed/package/vscode/data/ide_serial`

1. [刷新地址](https://bs-cn.tuya-inc.com:7799/cetus/cdn)，选择**目录刷新**

1. 填入以下内容，并提交

    > `https://images.tuyacn.com/smart/embed/package/vscode/data/ide_serial`


## 遗留问题

- mac环境运行慢（打包方式和开发者证书）

- T系列在不同环境和不同波特率组合下，必现的烧录失败问题


#!/usr/bin/env bash
#
# MiaoSpeed Universal Management Script
# Supports: Debian/Ubuntu, CentOS/RHEL, Arch, Alpine, OpenWrt, etc.
# Auto-detects: systemd, openrc, runit, sysvinit, screen, pm2
#
# Usage: bash miaospeed.sh [command] [options]
#
# Commands:
#   install   Install MiaoSpeed (default)
#   start     Start MiaoSpeed service
#   stop      Stop MiaoSpeed service
#   restart   Restart MiaoSpeed service
#   status    Show MiaoSpeed service status
#   config    Edit MiaoSpeed configuration
#   logs      Show MiaoSpeed logs
#   uninstall Uninstall MiaoSpeed
#

set -e

# Check Bash version for associative array support
# Bash 4.0+ is required for declare -A, provide fallback for older versions
_BASH_MAJOR_VERSION=${BASH_VERSION%%.*}
_BASH_MINOR_VERSION=${BASH_VERSION#*.}
_BASH_MINOR_VERSION=${_BASH_MINOR_VERSION%%.*}
_HAS_ASSOC_ARRAYS=false

if [[ $_BASH_MAJOR_VERSION -gt 4 ]] || [[ $_BASH_MAJOR_VERSION -eq 4 && $_BASH_MINOR_VERSION -ge 0 ]]; then
    _HAS_ASSOC_ARRAYS=true
fi

if [[ "$_HAS_ASSOC_ARRAYS" == false ]]; then
    echo "WARNING: Bash 4.0+ is required for this script."
    echo "Your Bash version: $BASH_VERSION"
    echo "Please upgrade Bash or use a newer shell."
    echo ""
    echo "macOS users: Install Homebrew Bash:"
    echo "  brew install bash"
    echo "  Then run: $(brew --prefix)/bin/bash $0 \"$@\""
    exit 1
fi

#######################################
# Internationalization (i18n)
#######################################
LANG=""
LANG_FROM_CONFIG=false

# English messages
declare -A MSG_EN=(
    [LANGUAGE_SELECT]="Please select language / 请选择语言"
    [INFO]="[INFO]"
    [WARN]="[WARN]"
    [ERROR]="[ERROR]"
    [STEP]="[STEP]"
    [MENU]="[MENU]"
    [DETECT_OS]="Detecting operating system..."
    [DETECT_INIT]="Detecting init system..."
    [FETCH_VERSION]="Fetching latest version..."
    [DOWNLOADING]="Downloading from:"
    [COMPILE_SOURCE]="Compiling from source..."
    [DEPLOY_LOCAL]="Starting local deployment..."
    [DEPLOY_DOCKER]="Starting Docker deployment..."
    [INSTALL_SERVICE]="Installing service..."
    [START_SERVICE]="Starting service..."
    [UNINSTALL]="Uninstalling MiaoSpeed..."
    [OS_INFO]="OS:"
    [ARCH_INFO]="Architecture:"
    [INIT_INFO]="Init system:"
    [DOCKER_INSTALLED]="Docker: installed"
    [DOCKER_NOT_INSTALLED]="Docker: not installed"
    [SELECT_MODE]="Select deployment mode:"
    [MODE_LOCAL]="Local deployment (user directory, no root required)"
    [MODE_DOCKER]="Docker deployment"
    [MODE_SOURCE]="Compile from source only"
    [MODE_UNINSTALL]="Uninstall MiaoSpeed"
    [MODE_EXIT]="Exit"
    [MODE_STOP]="Stop MiaoSpeed"
    [MODE_RESTART]="Restart MiaoSpeed"
    [MODE_STATUS]="Show MiaoSpeed Status"
    [MODE_START]="Start MiaoSpeed"
    [MODE_LANGUAGE]="Switch Language"
    [MODE_CONFIG]="Edit Configuration"
    [MODE_LOGS]="View Logs"
    [MODE_ADVANCED]="Advanced Configuration"
    [MODE_IMPORT]="Import Config (miaospeed://)"
    [MODE_EXPORT]="Export Config"
    [ENTER_CHOICE]="Enter your choice"
    [INVALID_CHOICE]="Invalid choice. Please try again."
    [STOPPING_SERVICE]="Stopping MiaoSpeed service..."
    [SERVICE_STOPPED]="MiaoSpeed service stopped."
    [SERVICE_STARTED]="MiaoSpeed service started."
    [SERVICE_RESTARTED]="MiaoSpeed service restarted."
    [ENTER_TOKEN]="Enter access token (press Enter to generate random):"
    [ENTER_PATH]="Enter WebSocket path (press Enter to generate random):"
    [RANDOM_TOKEN]="Generated random token:"
    [RANDOM_PATH]="Generated random path:"
    [PARAM_INFO]="=== Configuration Information ==="
    [SAVE_CONFIG]="Please save this information securely!"
    [TOKEN_INFO]="Access Token:"
    [PATH_INFO]="WebSocket Path:"
    [DOCKER_UNAVAILABLE]="Docker is not installed!"
    [DOCKER_HELP]="To install Docker, visit: https://docs.docker.com/get-docker/"
    [PRESS_ENTER]="Press Enter to continue..."
    [EXITING]="Exiting."
    [NOT_ROOT]="Note: Local deployment runs in user directory - root NOT required!"
    [SYSTEM_SERVICE_NEEDS_ROOT]="Note: System service installation requires root. Using user-level persistence instead."
    [LATEST_VERSION]="Latest version:"
    [DOWNLOADED]="Downloaded and extracted to:"
    [FAILED_DOWNLOAD]="Failed to download binary for architecture:"
    [DOWNLOAD_FAILED_AND_REASON]="Download failed. This script does not fallback to compilation."
    [REASON_NO_PREBUILT]="Your platform/architecture may not have prebuilt binaries available."
    [REASON_NETWORK]="Network error or GitHub is unreachable."
    [REASON_NOT_FOUND]="The requested binary was not found on GitHub releases."
    [SUGGEST_COMPILE]="Please compile from source manually:"
    [SUGGEST_CHECK]="Please check your network or visit https://github.com/AirportR/miaospeed/releases"
    [COMPILATION_COMPLETE]="Compilation complete."
    [COMPILATION_FAILED]="Compilation failed!"
    [NO_TLS_CERT]="No TLS certificate to embed. Put a .crt/.key pair into preconfigs/embeded/tls/ or install openssl."
    [SERVICE_ENABLED]="Service enabled"
    [INSTALL_SUCCESS]="MiaoSpeed installed successfully!"
    [DOCKER_DEPLOYED]="MiaoSpeed Docker deployed!"
    [UNINSTALL_SUCCESS]="MiaoSpeed uninstalled successfully."
    [CHOOSE_PERSISTENCE]="Choose persistence method:"
    [PERSIST_SYSTEMD]="systemd (system service, requires root)"
    [PERSIST_OPENRC]="OpenRC (system service, requires root)"
    [PERSIST_SCREEN]="screen (user session, no root)"
    [PERSIST_PM2]="PM2 (process manager, no root)"
    [PERSIST_NOAUTO]="No auto-start (manual start only)"
    [INSTALL_PM2]="Installing PM2..."
    [PM2_NOT_FOUND]="PM2 not found. Install with: npm install -g pm2"
    [SCREEN_NOT_FOUND]="screen not found. Install with: apt/brew install screen"
    [USAGE]="Usage:"
    [OPTIONS]="Options:"
    [EXAMPLES]="Examples:"
    [CONTAINER_NAME]="Container name:"
    [PORT]="Port:"
    [DOCKER_COMMANDS]="Docker commands:"
    [SERVICE_COMMANDS]="Service commands:"
    [BINARY]="Binary:"
    [CONFIG]="Config:"
    [SCREEN_START]="Start with: screen -S miaospeed -d -m"
    [SCREEN_ATTACH]="Attach with: screen -r miaospeed"
    [PM2_COMMANDS]="PM2 commands:"
    [PM2_START]="Start with: $HOME/.miaospeed/start.sh"
    [USER_DIR]="User directory:"
    [NO_SPEED]="Speedtest: disabled"
    [IPV6_ENABLED]="IPv6: enabled"
    [MTLS_ENABLED]="mTLS: enabled"
    [GO_NOT_INSTALLED]="Go is not installed. Installing..."
    # New messages
    [CONFIG_WIZARD]="Configuration Wizard"
    [CONFIG_WIZARD_DESC]="Configure MiaoSpeed parameters interactively"
    [NETWORK_SETTINGS]="Network Settings"
    [SECURITY_SETTINGS]="Security Settings"
    [PERFORMANCE_SETTINGS]="Performance Settings"
    [ADVANCED_SETTINGS]="Advanced Settings"
    [ENTER_PORT]="Enter listening port (default: 8080):"
    [ENTER_BIND]="Enter bind address (default: 0.0.0.0):"
    [ENTER_ALLOWIP]="Enter allowed IP CIDR (default: 0.0.0.0/0,::/0):"
    [ENTER_WHITELIST]="Enter bot ID whitelist (comma-separated, empty for none):"
    [ENTER_CONTHREAD]="Enter connection threads (default: 64):"
    [ENTER_TASKLIMIT]="Enter task limit (default: 1000):"
    [ENTER_SPEEDLIMIT]="Enter speed limit in bytes/sec (0 for unlimited):"
    [ENTER_PAUSE]="Enter pause seconds after speed test (0 for disabled):"
    [ENABLE_UPLOAD]="Enable upload speed test? (y/n, default: n):"
    [ENABLE_IPV6]="Enable IPv6 support? (y/n, default: n):"
    [ENABLE_MTLS]="Enable mTLS verification? (y/n, default: n):"
    [ENABLE_NOSPEED]="Disable download speed test? (y/n, default: n):"
    [ENTER_MMDB]="Enter MaxMind DB path (comma-separated for multiple, empty for none):"
    [ENTER_CERT_PUB]="Enter public key certificate path (PEM format, empty for default):"
    [ENTER_CERT_PRIV]="Enter private key path (PEM format, empty for default):"
    [ENTER_CLIENT_CA]="Enter client CA certificate path (PEM format, empty for none):"
    [CONFIG_EDIT_TITLE]="Edit Configuration"
    [CONFIG_EDIT_DESC]="Modify existing MiaoSpeed configuration"
    [CONFIG_EDIT_NOT_FOUND]="No existing configuration found. Please install first."
    [CONFIG_EDIT_RESTART]="Restart service to apply changes? (y/n):"
    [CONFIG_APPLIED]="Configuration applied!"
    [CONFIG_NOT_APPLIED]="Configuration saved but not applied."
    [LOG_VIEWER]="Log Viewer"
    [LOGS_NOT_FOUND]="No logs found."
    [LOG_FOLLOW]="Follow logs (press Ctrl+C to exit)? (y/n):"
    [IMPORT_CONFIG]="Import Configuration"
    [ENTER_CONFIG_URL]="Enter miaospeed:// config or paste the config string:"
    [IMPORT_INVALID]="Invalid configuration format."
    [IMPORT_SUCCESS]="Configuration imported successfully!"
    [EXPORT_CONFIG]="Export Configuration"
    [EXPORT_STRING]="miaospeed:// configuration string:"
    [VALID_PORT]="Invalid port. Must be between 1-65535."
    [VALID_NUMBER]="Invalid number. Please enter a valid value."
    [VALID_FILE]="File not found:"
    [PRESET_TITLE]="Configuration Presets"
    [PRESET_DESC]="Choose a preset configuration:"
    [PRESET_DEFAULT]="Default (balanced settings)"
    [PRESET_LOW]="Low Resource (for VPS with limited RAM/CPU)"
    [PRESET_HIGH]="High Performance (for powerful servers)"
    [PRESET_CUSTOM]="Custom Configuration"
    [PRESET_APPLIED]="Preset applied:"
    [CURRENT_CONFIG]="Current Configuration"
    [MODIFY_PARAM]="Modify parameter"
    [SAVE_APPLY]="Save and Apply"
    [DISCARD]="Discard changes"
    [SELECT_PARAM]="Select parameter to modify:"
    [NEW_VALUE]="Enter new value (empty to keep current):"
    [ENABLE_DISABLE]="Enable/Disable"
    [ENABLED]="enabled"
    [DISABLED]="disabled"
    [NONE]="<none>"
    [BIND_ADDRESS]="Bind Address:"
    [ALLOWED_IPS]="Allowed IPs:"
    [WHITELIST_VAL]="Whitelist:"
    [CON_THREADS]="Connection Threads:"
    [TASK_LIMIT_VAL]="Task Limit:"
    [SPEED_LIMIT_VAL]="Speed Limit:"
    [PAUSE_SECOND_VAL]="Pause Second:"
    [SPEED_TEST]="Speed Test:"
    [UPLOAD_TEST]="Upload Test:"
    [MMDB_PATH]="MMDB:"
    [CUSTOM_CERT]="Custom Cert:"
    [CLIENT_CA]="Client CA:"
    [PARAM_TOKEN]="Token"
    [PARAM_BIND]="Bind Address/Port"
    [PARAM_WS_PATH]="WebSocket Path"
    [PARAM_ALLOWIP]="Allowed IPs"
    [PARAM_WHITELIST_VAL]="Whitelist"
    [PARAM_CONTHREAD_VAL]="Connection Threads"
    [PARAM_TASKLIMIT_VAL]="Task Limit"
    [PARAM_SPEEDLIMIT_VAL]="Speed Limit"
    [PARAM_PAUSESECOND_VAL]="Pause Second"
    [PARAM_SPEEDTEST]="Speed Test (enable/disable)"
    [PARAM_UPLOADTEST]="Upload Test (enable/disable)"
    [PARAM_IPV6_OPT]="IPv6 (enable/disable)"
    [PARAM_MTLS_OPT]="mTLS (enable/disable)"
    [PARAM_MMDB_VAL]="MMDB Path"
    [PARAM_CERTS]="Custom Certificates"
    [PARAM_CLIENT_CA]="Client CA Certificate"
    [ENTER_BIND_ADDR]="Enter bind address"
    [ENTER_PUB_KEY]="Enter public key path"
    [ENTER_PRIV_KEY]="Enter private key path"
    [ENTER_CLIENT_CA_KEY]="Enter client CA certificate path"
    [LANG_EN]="English"
    [LANG_ZH]="中文"
    [LANG_CHANGED]="Language changed to:"
    [UNKNOWN_CMD]="Unknown command:"
    [UNKNOWN_OPT]="Unknown option:"
    [CLONING_SOURCE]="Cloning source code..."
    [BUILDING]="Building..."
    [TRYING_ARCH]="Trying architecture:"
    [USING_PM2]="Using PM2 for persistence..."
    [USING_SCREEN]="Using screen for persistence..."
    [NO_AUTO_CONFIG]="No auto-start configured."
    [SCREEN_WRAPPER_CREATED]="Screen wrapper created"
    [PM2_CONFIG_CREATED]="PM2 configuration created"
    [MANUAL_START_CREATED]="Manual start script created"
    [OPENRC_SERVICE_CREATED]="OpenRC service created"
    [SCREEN_WRAPPER_HINT]="Screen wrapper created. To start now: screen -dmS miaospeed"
    [PM2_CONFIG_HINT]="PM2 config created. Start with: pm2 start"
    [MANUAL_START_HINT]="Manual start script created at"
    [STARTED_SCREEN]="Started in screen session 'miaospeed'"
    [STARTED_PM2]="Started with PM2"
    [NO_AUTO_HINT]="No auto-start configured. Run manually:"
    [PULLING_DOCKER_IMAGE]="Pulling Docker image:"
    [TRYING_DOCKER_HUB]="Trying Docker Hub image..."
    [REMOVING_CONTAINER]="Removing existing container..."
    [STARTING_CONTAINER]="Starting container..."
    [BUILDING_DOCKER_IMAGE]="Building Docker image from source..."
    [STOPPING_PM2]="Stopping PM2 process..."
    [IPV6_STATUS]="IPv6:"
    [MTLS_STATUS]="mTLS:"
    [BYTES_PER_SEC]="bytes/sec"
    [SECONDS_SUFFIX]="s"
    [RUN_MANUALLY]="Run manually:"
)

# Chinese messages
declare -A MSG_ZH=(
    [LANGUAGE_SELECT]="请选择语言 / Please select language"
    [INFO]="[信息]"
    [WARN]="[警告]"
    [ERROR]="[错误]"
    [STEP]="[步骤]"
    [MENU]="[菜单]"
    [DETECT_OS]="检测操作系统..."
    [DETECT_INIT]="检测初始化系统..."
    [FETCH_VERSION]="获取最新版本..."
    [DOWNLOADING]="下载地址:"
    [COMPILE_SOURCE]="从源码编译..."
    [DEPLOY_LOCAL]="开始本地部署..."
    [DEPLOY_DOCKER]="开始 Docker 部署..."
    [INSTALL_SERVICE]="安装服务..."
    [START_SERVICE]="启动服务..."
    [UNINSTALL]="正在卸载 MiaoSpeed..."
    [OS_INFO]="操作系统:"
    [ARCH_INFO]="架构:"
    [INIT_INFO]="初始化系统:"
    [DOCKER_INSTALLED]="Docker: 已安装"
    [DOCKER_NOT_INSTALLED]="Docker: 未安装"
    [SELECT_MODE]="选择部署模式:"
    [MODE_LOCAL]="本地部署（用户目录，无需 root）"
    [MODE_DOCKER]="Docker 部署"
    [MODE_SOURCE]="仅从源码编译"
    [MODE_UNINSTALL]="卸载 MiaoSpeed"
    [MODE_EXIT]="退出"
    [MODE_STOP]="停止 MiaoSpeed"
    [MODE_RESTART]="重启 MiaoSpeed"
    [MODE_STATUS]="查看 MiaoSpeed 状态"
    [MODE_START]="启动 MiaoSpeed"
    [MODE_LANGUAGE]="切换语言"
    [MODE_CONFIG]="编辑配置"
    [MODE_LOGS]="查看日志"
    [MODE_ADVANCED]="高级配置"
    [MODE_IMPORT]="导入配置 (miaospeed://)"
    [MODE_EXPORT]="导出配置"
    [ENTER_CHOICE]="请输入您的选择"
    [INVALID_CHOICE]="无效选择，请重试。"
    [STOPPING_SERVICE]="正在停止 MiaoSpeed 服务..."
    [SERVICE_STOPPED]="MiaoSpeed 服务已停止。"
    [SERVICE_STARTED]="MiaoSpeed 服务已启动。"
    [SERVICE_RESTARTED]="MiaoSpeed 服务已重启。"
    [ENTER_TOKEN]="输入访问令牌 (按回车键随机生成):"
    [ENTER_PATH]="输入 WebSocket 路径 (按回车键随机生成):"
    [RANDOM_TOKEN]="已生成随机令牌:"
    [RANDOM_PATH]="已生成随机路径:"
    [PARAM_INFO]="=== 配置信息 ==="
    [SAVE_CONFIG]="请妥善保存此信息!"
    [TOKEN_INFO]="访问令牌:"
    [PATH_INFO]="WebSocket 路径:"
    [DOCKER_UNAVAILABLE]="Docker 未安装!"
    [DOCKER_HELP]="安装 Docker 请访问: https://docs.docker.com/get-docker/"
    [PRESS_ENTER]="按 Enter 键继续..."
    [EXITING]="正在退出。"
    [NOT_ROOT]="注意：本地部署在用户目录运行 - 不需要 root 权限！"
    [SYSTEM_SERVICE_NEEDS_ROOT]="注意：系统服务安装需要 root 权限。将使用用户级持久化。"
    [LATEST_VERSION]="最新版本:"
    [DOWNLOADED]="已下载并解压到:"
    [FAILED_DOWNLOAD]="下载以下架构的二进制文件失败:"
    [DOWNLOAD_FAILED_AND_REASON]="下载失败。本脚本不会回退到源码编译。"
    [REASON_NO_PREBUILT]="您的平台/架构可能没有预编译的二进制文件。"
    [REASON_NETWORK]="网络错误或无法访问 GitHub。"
    [REASON_NOT_FOUND]="在 GitHub 发布页中未找到请求的二进制文件。"
    [SUGGEST_COMPILE]="请手动从源码编译:"
    [SUGGEST_CHECK]="请检查网络或访问 https://github.com/AirportR/miaospeed/releases"
    [COMPILATION_COMPLETE]="编译完成。"
    [COMPILATION_FAILED]="编译失败!"
    [NO_TLS_CERT]="没有可内嵌的 TLS 证书。请把一对 .crt/.key 放进 preconfigs/embeded/tls/，或先安装 openssl。"
    [SERVICE_ENABLED]="服务已启用"
    [INSTALL_SUCCESS]="MiaoSpeed 安装成功!"
    [DOCKER_DEPLOYED]="MiaoSpeed Docker 部署完成!"
    [UNINSTALL_SUCCESS]="MiaoSpeed 卸载成功。"
    [CHOOSE_PERSISTENCE]="选择持久化方式:"
    [PERSIST_SYSTEMD]="systemd（系统服务，需要 root）"
    [PERSIST_OPENRC]="OpenRC（系统服务，需要 root）"
    [PERSIST_SCREEN]="screen（用户会话，无需 root）"
    [PERSIST_PM2]="PM2（进程管理器，无需 root）"
    [PERSIST_NOAUTO]="不自启（仅手动启动）"
    [INSTALL_PM2]="正在安装 PM2..."
    [PM2_NOT_FOUND]="未找到 PM2。安装命令: npm install -g pm2"
    [SCREEN_NOT_FOUND]="未找到 screen。安装命令: apt/brew install screen"
    [USAGE]="用法:"
    [OPTIONS]="选项:"
    [EXAMPLES]="示例:"
    [CONTAINER_NAME]="容器名称:"
    [PORT]="端口:"
    [DOCKER_COMMANDS]="Docker 命令:"
    [SERVICE_COMMANDS]="服务命令:"
    [BINARY]="二进制文件:"
    [CONFIG]="配置:"
    [SCREEN_START]="启动命令: screen -S miaospeed -d -m"
    [SCREEN_ATTACH]="连接命令: screen -r miaospeed"
    [PM2_COMMANDS]="PM2 命令:"
    [PM2_START]="启动命令: $HOME/.miaospeed/start.sh"
    [USER_DIR]="用户目录:"
    [NO_SPEED]="测速: 已禁用"
    [IPV6_ENABLED]="IPv6: 已启用"
    [MTLS_ENABLED]="mTLS: 已启用"
    [GO_NOT_INSTALLED]="Go 未安装。正在安装..."
    # New messages
    [CONFIG_WIZARD]="配置向导"
    [CONFIG_WIZARD_DESC]="交互式配置 MiaoSpeed 参数"
    [NETWORK_SETTINGS]="网络设置"
    [SECURITY_SETTINGS]="安全设置"
    [PERFORMANCE_SETTINGS]="性能设置"
    [ADVANCED_SETTINGS]="高级设置"
    [ENTER_PORT]="输入监听端口 (默认: 8080):"
    [ENTER_BIND]="输入绑定地址 (默认: 0.0.0.0):"
    [ENTER_ALLOWIP]="输入允许的 IP CIDR (默认: 0.0.0.0/0,::/0):"
    [ENTER_WHITELIST]="输入机器人 ID 白名单 (逗号分隔，留空为无限制):"
    [ENTER_CONTHREAD]="输入连接线程数 (默认: 64):"
    [ENTER_TASKLIMIT]="输入任务限制 (默认: 1000):"
    [ENTER_SPEEDLIMIT]="输入速度限制 字节/秒 (0 为无限制):"
    [ENTER_PAUSE]="输入测速后暂停秒数 (0 为禁用):"
    [ENABLE_UPLOAD]="启用上传测速? (y/n, 默认: n):"
    [ENABLE_IPV6]="启用 IPv6 支持? (y/n, 默认: n):"
    [ENABLE_MTLS]="启用 mTLS 验证? (y/n, 默认: n):"
    [ENABLE_NOSPEED]="禁用下载测速? (y/n, 默认: n):"
    [ENTER_MMDB]="输入 MaxMind 数据库路径 (多个用逗号分隔，留空为无):"
    [ENTER_CERT_PUB]="输入公钥证书路径 (PEM 格式，留空使用默认):"
    [ENTER_CERT_PRIV]="输入私钥路径 (PEM 格式，留空使用默认):"
    [ENTER_CLIENT_CA]="输入客户端 CA 证书路径 (PEM 格式，留空为无):"
    [CONFIG_EDIT_TITLE]="编辑配置"
    [CONFIG_EDIT_DESC]="修改现有 MiaoSpeed 配置"
    [CONFIG_EDIT_NOT_FOUND]="未找到现有配置。请先安装。"
    [CONFIG_EDIT_RESTART]="重启服务以应用更改? (y/n):"
    [CONFIG_APPLIED]="配置已应用!"
    [CONFIG_NOT_APPLIED]="配置已保存但未应用。"
    [LOG_VIEWER]="日志查看器"
    [LOGS_NOT_FOUND]="未找到日志。"
    [LOG_FOLLOW]="跟踪日志 (按 Ctrl+C 退出)? (y/n):"
    [IMPORT_CONFIG]="导入配置"
    [ENTER_CONFIG_URL]="输入 miaospeed:// 配置或粘贴配置字符串:"
    [IMPORT_INVALID]="无效的配置格式。"
    [IMPORT_SUCCESS]="配置导入成功!"
    [EXPORT_CONFIG]="导出配置"
    [EXPORT_STRING]="miaospeed:// 配置字符串:"
    [VALID_PORT]="无效端口。必须在 1-65535 之间。"
    [VALID_NUMBER]="无效数字。请输入有效值。"
    [VALID_FILE]="文件未找到:"
    [PRESET_TITLE]="配置预设"
    [PRESET_DESC]="选择配置预设:"
    [PRESET_DEFAULT]="默认 (平衡设置)"
    [PRESET_LOW]="低资源 (适用于内存/CPU 有限的 VPS)"
    [PRESET_HIGH]="高性能 (适用于强大的服务器)"
    [PRESET_CUSTOM]="自定义配置"
    [PRESET_APPLIED]="已应用预设:"
    [CURRENT_CONFIG]="当前配置"
    [MODIFY_PARAM]="修改参数"
    [SAVE_APPLY]="保存并应用"
    [DISCARD]="放弃更改"
    [SELECT_PARAM]="选择要修改的参数:"
    [NEW_VALUE]="输入新值 (留空保持当前值):"
    [ENABLE_DISABLE]="启用/禁用"
    [ENABLED]="已启用"
    [DISABLED]="已禁用"
    [NONE]="<无>"
    [BIND_ADDRESS]="绑定地址:"
    [ALLOWED_IPS]="允许的 IP:"
    [WHITELIST_VAL]="白名单:"
    [CON_THREADS]="连接线程:"
    [TASK_LIMIT_VAL]="任务限制:"
    [SPEED_LIMIT_VAL]="速度限制:"
    [PAUSE_SECOND_VAL]="暂停秒数:"
    [SPEED_TEST]="测速:"
    [UPLOAD_TEST]="上传测速:"
    [MMDB_PATH]="MMDB:"
    [CUSTOM_CERT]="自定义证书:"
    [CLIENT_CA]="客户端 CA:"
    [PARAM_TOKEN]="令牌"
    [PARAM_BIND]="绑定地址/端口"
    [PARAM_WS_PATH]="WebSocket 路径"
    [PARAM_ALLOWIP]="允许的 IP"
    [PARAM_WHITELIST_VAL]="白名单"
    [PARAM_CONTHREAD_VAL]="连接线程"
    [PARAM_TASKLIMIT_VAL]="任务限制"
    [PARAM_SPEEDLIMIT_VAL]="速度限制"
    [PARAM_PAUSESECOND_VAL]="暂停秒数"
    [PARAM_SPEEDTEST]="测速 (启用/禁用)"
    [PARAM_UPLOADTEST]="上传测速 (启用/禁用)"
    [PARAM_IPV6_OPT]="IPv6 (启用/禁用)"
    [PARAM_MTLS_OPT]="mTLS (启用/禁用)"
    [PARAM_MMDB_VAL]="MMDB 路径"
    [PARAM_CERTS]="自定义证书"
    [PARAM_CLIENT_CA]="客户端 CA 证书"
    [ENTER_BIND_ADDR]="输入绑定地址"
    [ENTER_PUB_KEY]="输入公钥路径"
    [ENTER_PRIV_KEY]="输入私钥路径"
    [ENTER_CLIENT_CA_KEY]="输入客户端 CA 证书路径"
    [LANG_EN]="English"
    [LANG_ZH]="中文"
    [LANG_CHANGED]="语言已更改为:"
    [UNKNOWN_CMD]="未知命令:"
    [UNKNOWN_OPT]="未知选项:"
    [CLONING_SOURCE]="正在克隆源代码..."
    [BUILDING]="正在构建..."
    [TRYING_ARCH]="尝试架构:"
    [USING_PM2]="使用 PM2 进行持久化..."
    [USING_SCREEN]="使用 screen 进行持久化..."
    [NO_AUTO_CONFIG]="未配置自动启动。"
    [SCREEN_WRAPPER_CREATED]="Screen 包装器已创建"
    [PM2_CONFIG_CREATED]="PM2 配置已创建"
    [MANUAL_START_CREATED]="手动启动脚本已创建"
    [OPENRC_SERVICE_CREATED]="OpenRC 服务已创建"
    [SCREEN_WRAPPER_HINT]="Screen 包装器已创建。现在启动: screen -dmS miaospeed"
    [PM2_CONFIG_HINT]="PM2 配置已创建。启动命令: pm2 start"
    [MANUAL_START_HINT]="手动启动脚本已创建于"
    [STARTED_SCREEN]="已在 screen 会话 'miaospeed' 中启动"
    [STARTED_PM2]="已通过 PM2 启动"
    [NO_AUTO_HINT]="未配置自动启动。手动运行:"
    [PULLING_DOCKER_IMAGE]="拉取 Docker 镜像:"
    [TRYING_DOCKER_HUB]="尝试 Docker Hub 镜像..."
    [REMOVING_CONTAINER]="移除现有容器..."
    [STARTING_CONTAINER]="启动容器..."
    [BUILDING_DOCKER_IMAGE]="从源码构建 Docker 镜像..."
    [STOPPING_PM2]="停止 PM2 进程..."
    [IPV6_STATUS]="IPv6:"
    [MTLS_STATUS]="mTLS:"
    [BYTES_PER_SEC]="字节/秒"
    [SECONDS_SUFFIX]="秒"
    [RUN_MANUALLY]="手动运行:"
)

# Get localized message
_() {
    local key="$1"
    if [[ "$LANG" == "zh" ]]; then
        echo "${MSG_ZH[$key]}"
    else
        echo "${MSG_EN[$key]}"
    fi
}

#######################################
# Color Output
#######################################
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

log_info() { echo -e "${GREEN}$(_ INFO)${NC} $1"; }
log_warn() { echo -e "${YELLOW}$(_ WARN)${NC} $1"; }
log_error() { echo -e "${RED}$(_ ERROR)${NC} $1"; }
log_step() { echo -e "${BLUE}$(_ STEP)${NC} $1"; }
log_menu() { echo -e "${CYAN}$(_ MENU)${NC} $1"; }

#######################################
# Variables
#######################################
# User-level installation (no root required)
INSTALL_DIR="$HOME/.miaospeed"
BINARY_NAME="miaospeed"
SERVICE_NAME="miaospeed"
REPO="AirportR/miaospeed"
GITHUB_API="https://api.github.com/repos/${REPO}/releases/latest"
DOWNLOAD_BASE="https://github.com/${REPO}/releases/download"

# Default configuration - all parameters supported by miaospeed
CFG_TOKEN=""
CFG_BIND="0.0.0.0:8080"
CFG_PATH="/"
CFG_ALLOWIP="0.0.0.0/0,::/0"
CFG_WHITELIST=""
CFG_NOSPEED=false
CFG_IPV6=false
CFG_MTLS=false
CFG_UPLOAD=false
CFG_CONTHREAD=64
CFG_TASKLIMIT=1000
CFG_SPEEDLIMIT=0
CFG_PAUSESECOND=0
CFG_MMDB=""
CFG_CERT_PUB=""
CFG_CERT_PRIV=""
CFG_CLIENT_CA=""

# Script options
COMMAND="install"    # "install", "start", "stop", "restart", "status", "config", "logs", "uninstall"
DEPLOY_MODE=""      # "docker" or "local"
UNINSTALL=false
COMPILE_FROM_SOURCE=false
PERSISTENCE_METHOD=""  # "systemd", "openrc", "screen", "pm2", "none"

#######################################
# Configuration File
#######################################
CONFIG_DIR="$HOME/.miaospeed"
CONFIG_FILE="$CONFIG_DIR/.manager_config"
PARAMS_FILE="$CONFIG_DIR/.params"

# Save configuration
save_config() {
    local key="$1"
    local value="$2"
    mkdir -p "$CONFIG_DIR"
    if grep -q "^${key}=" "$CONFIG_FILE" 2>/dev/null; then
        sed -i "s/^${key}=.*/${key}=${value}/" "$CONFIG_FILE"
    else
        echo "${key}=${value}" >> "$CONFIG_FILE"
    fi
}

# Save all parameters to file
save_all_params() {
    mkdir -p "$CONFIG_DIR"
    cat > "$PARAMS_FILE" << EOF
CFG_TOKEN="$CFG_TOKEN"
CFG_BIND="$CFG_BIND"
CFG_PATH="$CFG_PATH"
CFG_ALLOWIP="$CFG_ALLOWIP"
CFG_WHITELIST="$CFG_WHITELIST"
CFG_NOSPEED=$CFG_NOSPEED
CFG_IPV6=$CFG_IPV6
CFG_MTLS=$CFG_MTLS
CFG_UPLOAD=$CFG_UPLOAD
CFG_CONTHREAD=$CFG_CONTHREAD
CFG_TASKLIMIT=$CFG_TASKLIMIT
CFG_SPEEDLIMIT=$CFG_SPEEDLIMIT
CFG_PAUSESECOND=$CFG_PAUSESECOND
CFG_MMDB="$CFG_MMDB"
CFG_CERT_PUB="$CFG_CERT_PUB"
CFG_CERT_PRIV="$CFG_CERT_PRIV"
CFG_CLIENT_CA="$CFG_CLIENT_CA"
PERSISTENCE_METHOD="$PERSISTENCE_METHOD"
EOF
}

# Load all parameters from file
load_all_params() {
    if [[ -f "$PARAMS_FILE" ]]; then
        source "$PARAMS_FILE"
    fi
}

# Load configuration
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        while IFS='=' read -r key value; do
            case "$key" in
                lang)
                    LANG="$value"
                    LANG_FROM_CONFIG=true
                    ;;
                persistence_method) PERSISTENCE_METHOD="$value" ;;
            esac
        done < "$CONFIG_FILE"
    fi
    if [[ -z "$LANG" ]]; then
        LANG="en"
    fi
    # Load params if exists
    load_all_params
}

# Load saved config at startup
load_config

#######################################
# Input Validation Functions
#######################################
validate_port() {
    local port="$1"
    if [[ ! "$port" =~ ^[0-9]+$ ]] || [[ "$port" -lt 1 ]] || [[ "$port" -gt 65535 ]]; then
        return 1
    fi
    return 0
}

validate_number() {
    local num="$1"
    if [[ ! "$num" =~ ^[0-9]+$ ]]; then
        return 1
    fi
    return 0
}

validate_file() {
    local file="$1"
    if [[ -n "$file" ]] && [[ ! -f "$file" ]]; then
        return 1
    fi
    return 0
}

confirm_yes_no() {
    local prompt="$1"
    local response
    read -p "$prompt " response
    case "$response" in
        [Yy]|[Yy][Ee][Ss]|[Yy]|是) return 0 ;;
        *) return 1 ;;
    esac
}

#######################################
# Language Selection
#######################################
select_language() {
    echo ""
    echo "=================================="
    echo "   MiaoSpeed Manager"
    echo "=================================="
    echo ""
    echo "  1) English"
    echo "  2) 中文"
    echo ""
    read -p "$(_ LANGUAGE_SELECT) [1-2]: " lang_choice

    case $lang_choice in
        2|zh|zh_CN|chinese)
            LANG="zh"
            ;;
        *)
            LANG="en"
            ;;
    esac
    export LANG
    save_config "lang" "$LANG"
}

switch_language() {
    echo ""
    echo "=================================="
    echo "   $(_ MODE_LANGUAGE)"
    echo "=================================="
    echo ""
    echo "  1) $(_ LANG_EN)"
    echo "  2) $(_ LANG_ZH)"
    echo ""
    read -p "$(_ LANGUAGE_SELECT) [1-2]: " lang_choice

    case $lang_choice in
        2|zh|zh_CN|chinese)
            LANG="zh"
            ;;
        *)
            LANG="en"
            ;;
    esac
    export LANG
    save_config "lang" "$LANG"

    echo ""
    local lang_display=$(_ LANG_EN)
    [[ "$LANG" == "zh" ]] && lang_display=$(_ LANG_ZH)
    log_info "$(_ LANG_CHANGED) $lang_display"
    echo ""
    read -p "$(_ PRESS_ENTER)"
}

#######################################
# Parse Arguments
#######################################
print_usage() {
    cat << EOF
$(_ USAGE) $0 [options]

$(_ OPTIONS):
    -t, --token TOKEN           Set access token
    -p, --port PORT             Set listening port (default: 8080)
    --bind ADDRESS              Set bind address (default: 0.0.0.0)
    --path PATH                 Set WebSocket path (default: /)
    --allowip CIDR              Set allowed IP range (default: 0.0.0.0/0,::/0)
    --whitelist IDS             Set bot ID whitelist
    --no-speed                  Disable speedtest
    --ipv6                      Enable IPv6
    --mtls                      Enable mTLS
    --upload                    Enable upload speedtest
    --connthread NUM            Set connection threads (default: 64)
    --tasklimit NUM             Set task limit (default: 1000)
    --speedlimit BYTES          Set speed limit in bytes/sec
    --pause SEC                 Pause seconds after speed test
    --mmdb PATH                 MaxMind DB path(s)
    --cert-pub PATH             Public key certificate path (PEM)
    --cert-priv PATH            Private key path (PEM)
    --client-ca PATH            Client CA certificate path (PEM)
    --docker                    Deploy with Docker (skip prompt)
    --local                     Deploy locally (skip prompt)
    --persistence METHOD        Persistence: systemd, openrc, screen, pm2, none
    --compile                   Compile from source instead of downloading
    --uninstall                 Uninstall miaospeed
    --lang LANG                 Language: en or zh (default: auto)

$(_ EXAMPLES):
    $0                              # Interactive mode
    $0 --docker --port 8080         # Deploy with Docker
    $0 --local --token abc123       # Deploy locally with token
    $0 --local --persistence pm2    # Deploy with PM2 persistence
    $0 config                       # Edit configuration
    $0 logs                         # View logs

EOF
    exit 0
}

parse_args() {
    if [[ $# -gt 0 ]]; then
        case "$1" in
            install)
                COMMAND="install"
                shift
                ;;
            start)
                COMMAND="start"
                shift
                ;;
            stop)
                COMMAND="stop"
                shift
                ;;
            restart)
                COMMAND="restart"
                shift
                ;;
            status)
                COMMAND="status"
                shift
                ;;
            config)
                COMMAND="config"
                shift
                ;;
            logs)
                COMMAND="logs"
                shift
                ;;
            uninstall)
                COMMAND="uninstall"
                shift
                ;;
            -*)
                COMMAND="install"
                ;;
            *)
                log_error "$(_ UNKNOWN_CMD) $1"
                print_usage
                ;;
        esac
    fi

    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--token) CFG_TOKEN="$2"; shift 2 ;;
            -p|--port)
                if validate_port "$2"; then
                    CFG_BIND="0.0.0.0:$2"
                else
                    log_error "$(_ VALID_PORT)"
                    exit 1
                fi
                shift 2
                ;;
            --bind) CFG_BIND="$2"; shift 2 ;;
            --path) CFG_PATH="$2"; shift 2 ;;
            --allowip) CFG_ALLOWIP="$2"; shift 2 ;;
            --whitelist) CFG_WHITELIST="$2"; shift 2 ;;
            --no-speed) CFG_NOSPEED=true; shift ;;
            --ipv6) CFG_IPV6=true; shift ;;
            --mtls) CFG_MTLS=true; shift ;;
            --upload) CFG_UPLOAD=true; shift ;;
            --connthread) CFG_CONTHREAD="$2"; shift 2 ;;
            --tasklimit) CFG_TASKLIMIT="$2"; shift 2 ;;
            --speedlimit) CFG_SPEEDLIMIT="$2"; shift 2 ;;
            --pause) CFG_PAUSESECOND="$2"; shift 2 ;;
            --mmdb) CFG_MMDB="$2"; shift 2 ;;
            --cert-pub) CFG_CERT_PUB="$2"; shift 2 ;;
            --cert-priv) CFG_CERT_PRIV="$2"; shift 2 ;;
            --client-ca) CFG_CLIENT_CA="$2"; shift 2 ;;
            --docker) DEPLOY_MODE="docker"; shift ;;
            --local) DEPLOY_MODE="local"; shift ;;
            --persistence) PERSISTENCE_METHOD="$2"; shift 2 ;;
            --compile) COMPILE_FROM_SOURCE=true; shift ;;
            --lang) LANG="$2"; shift 2 ;;
            -h|--help) print_usage ;;
            *)
                log_error "$(_ UNKNOWN_OPT) $1"
                print_usage
                ;;
        esac
    done
}

#######################################
# Generate Random Values
#######################################
generate_random_string() {
    local length="${1:-32}"
    tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c "$length"
}

generate_random_path() {
    local length="${1:-16}"
    echo "/$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c "$length")"
}

#######################################
# Configuration Presets
#######################################
apply_preset() {
    local preset="$1"

    case $preset in
        default)
            CFG_CONTHREAD=64
            CFG_TASKLIMIT=1000
            CFG_SPEEDLIMIT=0
            CFG_PAUSESECOND=0
            CFG_NOSPEED=false
            CFG_UPLOAD=false
            ;;
        low)
            CFG_CONTHREAD=16
            CFG_TASKLIMIT=500
            CFG_SPEEDLIMIT=0
            CFG_PAUSESECOND=2
            CFG_NOSPEED=false
            CFG_UPLOAD=false
            ;;
        high)
            CFG_CONTHREAD=128
            CFG_TASKLIMIT=2000
            CFG_SPEEDLIMIT=0
            CFG_PAUSESECOND=0
            CFG_NOSPEED=false
            CFG_UPLOAD=true
            ;;
    esac
    log_info "$(_ PRESET_APPLIED) $preset"
}

select_preset() {
    echo ""
    log_menu "$(_ PRESET_TITLE)"
    echo "$(_ PRESET_DESC)"
    echo ""
    echo "  1) $(_ PRESET_DEFAULT)"
    echo "  2) $(_ PRESET_LOW)"
    echo "  3) $(_ PRESET_HIGH)"
    echo "  4) $(_ PRESET_CUSTOM)"
    echo "  0) $(_ MODE_EXIT)"
    echo ""
    read -p "$(_ ENTER_CHOICE) [0-4]: " choice

    case $choice in
        1) apply_preset "default" ;;
        2) apply_preset "low" ;;
        3) apply_preset "high" ;;
        4) return 0 ;;  # Custom - continue to wizard
        0) return 1 ;;  # Exit
        *)
            log_error "$(_ INVALID_CHOICE)"
            select_preset
            return $?
            ;;
    esac
    return 0
}

#######################################
# Configuration Wizard
#######################################
config_wizard() {
    echo ""
    echo "=================================="
    echo "   $(_ CONFIG_WIZARD)"
    echo "=================================="
    echo ""
    echo "$(_ CONFIG_WIZARD_DESC)"
    echo ""

    # First, offer presets
    select_preset
    local preset_result=$?
    if [[ $preset_result -eq 1 ]]; then
        return 1
    fi

    # Network Settings
    echo ""
    echo -e "${CYAN}$(_ NETWORK_SETTINGS)${NC}"
    echo "-----------------------------------"

    # Port
    local current_port
    current_port=$(echo "$CFG_BIND" | cut -d: -f2)
    [[ -z "$current_port" ]] && current_port="8080"
    read -p "$(_ ENTER_PORT) [$current_port]: " input_port
    if [[ -n "$input_port" ]]; then
        if validate_port "$input_port"; then
            CFG_BIND="0.0.0.0:$input_port"
        else
            log_error "$(_ VALID_PORT)"
        fi
    fi

    # Bind address
    read -p "$(_ ENTER_BIND) [0.0.0.0]: " input_bind
    if [[ -n "$input_bind" ]]; then
        local port=$(echo "$CFG_BIND" | cut -d: -f2)
        CFG_BIND="$input_bind:$port"
    fi

    # Allowed IPs
    read -p "$(_ ENTER_ALLOWIP) [$CFG_ALLOWIP]: " input_allowip
    [[ -n "$input_allowip" ]] && CFG_ALLOWIP="$input_allowip"

    # Whitelist
    read -p "$(_ ENTER_WHITELIST) [$CFG_WHITELIST]: " input_whitelist
    [[ -n "$input_whitelist" ]] && CFG_WHITELIST="$input_whitelist"

    # Security Settings
    echo ""
    echo -e "${CYAN}$(_ SECURITY_SETTINGS)${NC}"
    echo "-----------------------------------"

    # Token
    read -p "$(_ ENTER_TOKEN) " input_token
    if [[ -z "$input_token" ]]; then
        CFG_TOKEN=$(generate_random_string 32)
        echo -e "${GREEN}$(_ RANDOM_TOKEN) $CFG_TOKEN${NC}"
    else
        CFG_TOKEN="$input_token"
    fi

    # Path
    read -p "$(_ ENTER_PATH) " input_path
    if [[ -z "$input_path" ]]; then
        CFG_PATH=$(generate_random_path 16)
        echo -e "${GREEN}$(_ RANDOM_PATH) $CFG_PATH${NC}"
    else
        [[ ! "$input_path" =~ ^/ ]] && input_path="/$input_path"
        CFG_PATH="$input_path"
    fi

    # IPv6
    if confirm_yes_no "$(_ ENABLE_IPV6)"; then
        CFG_IPV6=true
    fi

    # mTLS
    if confirm_yes_no "$(_ ENABLE_MTLS)"; then
        CFG_MTLS=true
    fi

    # Whitelist is already set above

    # Performance Settings
    echo ""
    echo -e "${CYAN}$(_ PERFORMANCE_SETTINGS)${NC}"
    echo "-----------------------------------"

    # Connection threads
    read -p "$(_ ENTER_CONTHREAD) [$CFG_CONTHREAD]: " input_conthread
    if [[ -n "$input_conthread" ]] && validate_number "$input_conthread"; then
        CFG_CONTHREAD="$input_conthread"
    fi

    # Task limit
    read -p "$(_ ENTER_TASKLIMIT) [$CFG_TASKLIMIT]: " input_tasklimit
    if [[ -n "$input_tasklimit" ]] && validate_number "$input_tasklimit"; then
        CFG_TASKLIMIT="$input_tasklimit"
    fi

    # Speed limit
    read -p "$(_ ENTER_SPEEDLIMIT) [$CFG_SPEEDLIMIT]: " input_speedlimit
    if [[ -n "$input_speedlimit" ]] && validate_number "$input_speedlimit"; then
        CFG_SPEEDLIMIT="$input_speedlimit"
    fi

    # Pause seconds
    read -p "$(_ ENTER_PAUSE) [$CFG_PAUSESECOND]: " input_pause
    if [[ -n "$input_pause" ]] && validate_number "$input_pause"; then
        CFG_PAUSESECOND="$input_pause"
    fi

    # Speed test options
    if confirm_yes_no "$(_ ENABLE_NOSPEED)"; then
        CFG_NOSPEED=true
    fi

    if confirm_yes_no "$(_ ENABLE_UPLOAD)"; then
        CFG_UPLOAD=true
    fi

    # Advanced Settings
    echo ""
    echo -e "${CYAN}$(_ ADVANCED_SETTINGS)${NC}"
    echo "-----------------------------------"

    # MMDB
    read -p "$(_ ENTER_MMDB) [$CFG_MMDB]: " input_mmdb
    [[ -n "$input_mmdb" ]] && CFG_MMDB="$input_mmdb"

    # Custom certificates
    read -p "$(_ ENTER_CERT_PUB) [$CFG_CERT_PUB]: " input_cert_pub
    if [[ -n "$input_cert_pub" ]]; then
        if validate_file "$input_cert_pub"; then
            CFG_CERT_PUB="$input_cert_pub"
        else
            log_error "$(_ VALID_FILE) $input_cert_pub"
        fi
    fi

    read -p "$(_ ENTER_CERT_PRIV) [$CFG_CERT_PRIV]: " input_cert_priv
    if [[ -n "$input_cert_priv" ]]; then
        if validate_file "$input_cert_priv"; then
            CFG_CERT_PRIV="$input_cert_priv"
        else
            log_error "$(_ VALID_FILE) $input_cert_priv"
        fi
    fi

    read -p "$(_ ENTER_CLIENT_CA) [$CFG_CLIENT_CA]: " input_client_ca
    if [[ -n "$input_client_ca" ]]; then
        if validate_file "$input_client_ca"; then
            CFG_CLIENT_CA="$input_client_ca"
        else
            log_error "$(_ VALID_FILE) $input_client_ca"
        fi
    fi

    echo ""
    log_info "$(_ PARAM_INFO)"
    print_current_config
    echo ""

    return 0
}

#######################################
# Print Current Configuration
#######################################
print_current_config() {
    local port
    port=$(echo "$CFG_BIND" | cut -d: -f2)
    [[ -z "$port" ]] && port="8080"

    local enabled_text=$(_ ENABLED)
    local disabled_text=$(_ DISABLED)
    local none_text=$(_ NONE)

    echo "-----------------------------------"
    echo -e "${GREEN}$(_ TOKEN_INFO)${NC} ${RED}$CFG_TOKEN${NC}"
    echo -e "${GREEN}$(_ PATH_INFO)${NC} ${YELLOW}$CFG_PATH${NC}"
    echo "-----------------------------------"
    echo "$(_ BIND_ADDRESS)      $CFG_BIND"
    echo "$(_ ALLOWED_IPS)       $CFG_ALLOWIP"
    echo "$(_ WHITELIST_VAL)         ${CFG_WHITELIST:-$none_text}"
    echo "$(_ CON_THREADS): $CFG_CONTHREAD"
    echo "$(_ TASK_LIMIT_VAL):        $CFG_TASKLIMIT"
    echo "$(_ SPEED_LIMIT_VAL):       ${CFG_SPEEDLIMIT} $(_ BYTES_PER_SEC)"
    echo "$(_ PAUSE_SECOND_VAL):      ${CFG_PAUSESECOND}$(_ SECONDS_SUFFIX)"
    echo "$(_ SPEED_TEST)        $([[ "$CFG_NOSPEED" == true ]] && echo "$disabled_text" || echo "$enabled_text")"
    echo "$(_ UPLOAD_TEST):       $([[ "$CFG_UPLOAD" == true ]] && echo "$enabled_text" || echo "$disabled_text")"
    echo "$(_ IPV6_STATUS):              $([[ "$CFG_IPV6" == true ]] && echo "$enabled_text" || echo "$disabled_text")"
    echo "$(_ MTLS_STATUS):              $([[ "$CFG_MTLS" == true ]] && echo "$enabled_text" || echo "$disabled_text")"
    echo "$(_ MMDB_PATH):              ${CFG_MMDB:-$none_text}"
    echo "$(_ CUSTOM_CERT):       $([ -n "$CFG_CERT_PUB" ] && echo "$enabled_text" || echo "$disabled_text")"
    echo "$(_ CLIENT_CA)         ${CFG_CLIENT_CA:-$none_text}"
    echo "-----------------------------------"
}

#######################################
# Configuration Edit
#######################################
config_edit_menu() {
    if [[ ! -f "$PARAMS_FILE" ]]; then
        log_error "$(_ CONFIG_EDIT_NOT_FOUND)"
        return 1
    fi

    while true; do
        echo ""
        echo "=================================="
        echo "   $(_ CONFIG_EDIT_TITLE)"
        echo "=================================="
        echo ""
        echo -e "${CYAN}$(_ CURRENT_CONFIG)${NC}"
        print_current_config
        echo ""
        echo "$(_ SELECT_PARAM)"
        echo "  1) $(_ PARAM_TOKEN)"
        echo "  2) $(_ PARAM_BIND)"
        echo "  3) $(_ PARAM_WS_PATH)"
        echo "  4) $(_ PARAM_ALLOWIP)"
        echo "  5) $(_ PARAM_WHITELIST_VAL)"
        echo "  6) $(_ PARAM_CONTHREAD_VAL)"
        echo "  7) $(_ PARAM_TASKLIMIT_VAL)"
        echo "  8) $(_ PARAM_SPEEDLIMIT_VAL)"
        echo "  9) $(_ PARAM_PAUSESECOND_VAL)"
        echo " 10) $(_ PARAM_SPEEDTEST)"
        echo " 11) $(_ PARAM_UPLOADTEST)"
        echo " 12) $(_ PARAM_IPV6_OPT)"
        echo " 13) $(_ PARAM_MTLS_OPT)"
        echo " 14) $(_ PARAM_MMDB_VAL)"
        echo " 15) $(_ PARAM_CERTS)"
        echo " 16) $(_ PARAM_CLIENT_CA)"
        echo "  s) $(_ SAVE_APPLY)"
        echo "  x) $(_ DISCARD)"
        echo ""
        read -p "$(_ ENTER_CHOICE): " choice

        case $choice in
            1)
                read -p "$(_ NEW_VALUE) [$CFG_TOKEN]: " input
                [[ -n "$input" ]] && CFG_TOKEN="$input"
                ;;
            2)
                read -p "$(_ ENTER_BIND_ADDR) [$CFG_BIND]: " input
                [[ -n "$input" ]] && CFG_BIND="$input"
                ;;
            3)
                read -p "$(_ NEW_VALUE) [$CFG_PATH]: " input
                [[ -n "$input" ]] && CFG_PATH="$input"
                ;;
            4)
                read -p "$(_ NEW_VALUE) [$CFG_ALLOWIP]: " input
                [[ -n "$input" ]] && CFG_ALLOWIP="$input"
                ;;
            5)
                read -p "$(_ NEW_VALUE) [$CFG_WHITELIST]: " input
                [[ -n "$input" ]] && CFG_WHITELIST="$input"
                ;;
            6)
                read -p "$(_ NEW_VALUE) [$CFG_CONTHREAD]: " input
                [[ -n "$input" ]] && CFG_CONTHREAD="$input"
                ;;
            7)
                read -p "$(_ NEW_VALUE) [$CFG_TASKLIMIT]: " input
                [[ -n "$input" ]] && CFG_TASKLIMIT="$input"
                ;;
            8)
                read -p "$(_ NEW_VALUE) [$CFG_SPEEDLIMIT]: " input
                [[ -n "$input" ]] && CFG_SPEEDLIMIT="$input"
                ;;
            9)
                read -p "$(_ NEW_VALUE) [$CFG_PAUSESECOND]: " input
                [[ -n "$input" ]] && CFG_PAUSESECOND="$input"
                ;;
            10)
                if [[ "$CFG_NOSPEED" == true ]]; then
                    CFG_NOSPEED=false
                    log_info "$(_ SPEED_TEST) $(_ ENABLED)"
                else
                    CFG_NOSPEED=true
                    log_info "$(_ SPEED_TEST) $(_ DISABLED)"
                fi
                ;;
            11)
                if [[ "$CFG_UPLOAD" == true ]]; then
                    CFG_UPLOAD=false
                    log_info "$(_ UPLOAD_TEST) $(_ DISABLED)"
                else
                    CFG_UPLOAD=true
                    log_info "$(_ UPLOAD_TEST) $(_ ENABLED)"
                fi
                ;;
            12)
                if [[ "$CFG_IPV6" == true ]]; then
                    CFG_IPV6=false
                    log_info "IPv6: $(_ DISABLED)"
                else
                    CFG_IPV6=true
                    log_info "IPv6: $(_ ENABLED)"
                fi
                ;;
            13)
                if [[ "$CFG_MTLS" == true ]]; then
                    CFG_MTLS=false
                    log_info "mTLS: $(_ DISABLED)"
                else
                    CFG_MTLS=true
                    log_info "mTLS: $(_ ENABLED)"
                fi
                ;;
            14)
                read -p "$(_ NEW_VALUE) [$CFG_MMDB]: " input
                [[ -n "$input" ]] && CFG_MMDB="$input"
                ;;
            15)
                read -p "$(_ ENTER_PUB_KEY) [$CFG_CERT_PUB]: " input
                [[ -n "$input" ]] && CFG_CERT_PUB="$input"
                read -p "$(_ ENTER_PRIV_KEY) [$CFG_CERT_PRIV]: " input
                [[ -n "$input" ]] && CFG_CERT_PRIV="$input"
                ;;
            16)
                read -p "$(_ ENTER_CLIENT_CA_KEY) [$CFG_CLIENT_CA]: " input
                [[ -n "$input" ]] && CFG_CLIENT_CA="$input"
                ;;
            s|S)
                save_all_params
                recreate_service_files
                if confirm_yes_no "$(_ CONFIG_EDIT_RESTART)"; then
                    restart_service
                    log_info "$(_ CONFIG_APPLIED)"
                else
                    log_info "$(_ CONFIG_NOT_APPLIED)"
                fi
                return 0
                ;;
            x|X)
                return 0
                ;;
            *)
                log_error "$(_ INVALID_CHOICE)"
                ;;
        esac
    done
}

#######################################
# Export/Import Configuration
#######################################
export_config() {
    echo ""
    echo "=================================="
    echo "   $(_ EXPORT_CONFIG)"
    echo "=================================="
    echo ""

    # Create JSON config matching GlobalConfig struct in Go
    local json_config="{"
    json_config+="\"Token\":\"${CFG_TOKEN}\","
    json_config+="\"Binder\":\"${CFG_BIND}\","
    json_config+="\"Path\":\"${CFG_PATH}\","
    json_config+="\"AllowIPs\":\"${CFG_ALLOWIP}\","
    json_config+="\"WhiteList\":\"${CFG_WHITELIST}\","
    json_config+="\"NoSpeedFlag\":${CFG_NOSPEED},"
    json_config+="\"EnableIPv6\":${CFG_IPV6},"
    json_config+="\"MiaoKoSignedTLS\":${CFG_MTLS},"
    json_config+="\"EnableUploadSpeedFlag\":${CFG_UPLOAD},"
    json_config+="\"ConnTaskTreading\":${CFG_CONTHREAD},"
    json_config+="\"TaskLimit\":${CFG_TASKLIMIT},"
    json_config+="\"SpeedLimit\":${CFG_SPEEDLIMIT},"
    json_config+="\"PauseSecond\":${CFG_PAUSESECOND},"
    json_config+="\"MaxmindDB\":\"${CFG_MMDB}\""
    json_config+="}"

    # Base64 encode
    local config_b64=$(echo -n "$json_config" | base64 -w 0 2>/dev/null || echo -n "$json_config" | base64)
    echo -e "${CYAN}miaospeed://${config_b64}${NC}"
    echo ""
}

import_config() {
    echo ""
    echo "=================================="
    echo "   $(_ IMPORT_CONFIG)"
    echo "=================================="
    echo ""

    read -p "$(_ ENTER_CONFIG_URL) " config_str

    # Remove miaospeed:// prefix if present
    config_str="${config_str#miaospeed://}"

    # Decode base64
    local json_config=$(echo "$config_str" | base64 -d 2>/dev/null)

    if [[ -z "$json_config" ]]; then
        log_error "$(_ IMPORT_INVALID)"
        return 1
    fi

    # Parse JSON (simple parser using grep/sed)
    parse_json_value() {
        local json="$1"
        local key="$2"
        echo "$json" | grep -o "\"${key}\":[^,}]*" | cut -d: -f2- | tr -d '"'
    }

    parse_json_bool() {
        local json="$1"
        local key="$2"
        local val=$(echo "$json" | grep -o "\"${key}\":[^,}]*" | cut -d: -f2 | tr -d ' ')
        if [[ "$val" == "true" ]]; then
            echo "true"
        else
            echo "false"
        fi
    }

    CFG_TOKEN=$(parse_json_value "$json_config" "Token")
    CFG_BIND=$(parse_json_value "$json_config" "Binder")
    CFG_PATH=$(parse_json_value "$json_config" "Path")
    CFG_ALLOWIP=$(parse_json_value "$json_config" "AllowIPs")
    CFG_WHITELIST=$(parse_json_value "$json_config" "WhiteList")
    CFG_NOSPEED=$(parse_json_bool "$json_config" "NoSpeedFlag")
    CFG_IPV6=$(parse_json_bool "$json_config" "EnableIPv6")
    CFG_MTLS=$(parse_json_bool "$json_config" "MiaoKoSignedTLS")
    CFG_UPLOAD=$(parse_json_bool "$json_config" "EnableUploadSpeedFlag")
    CFG_CONTHREAD=$(parse_json_value "$json_config" "ConnTaskTreading")
    CFG_TASKLIMIT=$(parse_json_value "$json_config" "TaskLimit")
    CFG_SPEEDLIMIT=$(parse_json_value "$json_config" "SpeedLimit")
    CFG_PAUSESECOND=$(parse_json_value "$json_config" "PauseSecond")
    CFG_MMDB=$(parse_json_value "$json_config" "MaxmindDB")

    # Set defaults if empty
    [[ -z "$CFG_BIND" ]] && CFG_BIND="0.0.0.0:8080"
    [[ -z "$CFG_PATH" ]] && CFG_PATH="/"
    [[ -z "$CFG_ALLOWIP" ]] && CFG_ALLOWIP="0.0.0.0/0,::/0"
    [[ -z "$CFG_NOSPEED" ]] && CFG_NOSPEED=false
    [[ -z "$CFG_IPV6" ]] && CFG_IPV6=false
    [[ -z "$CFG_MTLS" ]] && CFG_MTLS=false
    [[ -z "$CFG_UPLOAD" ]] && CFG_UPLOAD=false
    [[ -z "$CFG_CONTHREAD" ]] && CFG_CONTHREAD=64
    [[ -z "$CFG_TASKLIMIT" ]] && CFG_TASKLIMIT=1000
    [[ -z "$CFG_SPEEDLIMIT" ]] && CFG_SPEEDLIMIT=0
    [[ -z "$CFG_PAUSESECOND" ]] && CFG_PAUSESECOND=0

    log_info "$(_ IMPORT_SUCCESS)"
    print_current_config
    echo ""

    return 0
}

#######################################
# Log Viewer
#######################################
view_logs() {
    echo ""
    echo "=================================="
    echo "   $(_ LOG_VIEWER)"
    echo "=================================="
    echo ""

    local method
    method=$(detect_persistence_method)

    case $method in
        pm2)
            if command -v pm2 &>/dev/null; then
                pm2 logs "$SERVICE_NAME" --lines 50
            else
                log_error "$(_ PM2_NOT_FOUND)"
            fi
            ;;
        systemd)
            if [[ $EUID -eq 0 ]] && [[ -f "/etc/systemd/system/$SERVICE_NAME.service" ]]; then
                journalctl -u "$SERVICE_NAME" -n 50 -f
            elif [[ -f "$HOME/.config/systemd/user/$SERVICE_NAME.service" ]]; then
                journalctl --user -u "$SERVICE_NAME" -n 50 -f
            else
                log_error "systemd service not found"
            fi
            ;;
        openrc)
            if [[ -f "/var/log/miaospeed.log" ]]; then
                tail -n 50 -f /var/log/miaospeed.log
            else
                log_error "$(_ LOGS_NOT_FOUND)"
            fi
            ;;
        screen)
            if [[ -f "$INSTALL_DIR/miaospeed.log" ]]; then
                tail -n 50 -f "$INSTALL_DIR/miaospeed.log"
            else
                log_warn "Screen doesn't save logs. Attach with: screen -r miaospeed"
            fi
            ;;
        *)
            if [[ -f "$INSTALL_DIR/miaospeed.log" ]]; then
                tail -n 50 -f "$INSTALL_DIR/miaospeed.log"
            else
                log_error "$(_ LOGS_NOT_FOUND)"
            fi
            ;;
    esac
}

#######################################
# System Detection
#######################################
detect_os() {
    log_step "$(_ DETECT_OS)"

    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
        OS_PRETTY=$PRETTY_NAME
    elif [[ -f /etc/openwrt_release ]]; then
        OS="openwrt"
        . /etc/openwrt_release
        OS_PRETTY="$DISTRIB_DESCRIPTION"
    else
        OS=$(uname -s | tr '[:upper:]' '[:lower:]')
        OS_PRETTY=$(uname -a)
    fi

    # Detect architecture
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) GOARCH="amd64"; ARCH_SUFFIX="amd64" ;;
        aarch64) GOARCH="arm64"; ARCH_SUFFIX="arm64" ;;
        armv7l) GOARCH="armv7"; ARCH_SUFFIX="armv7" ;;
        armv6l) GOARCH="armv6"; ARCH_SUFFIX="armv6" ;;
        armv5l) GOARCH="armv5"; ARCH_SUFFIX="armv5" ;;
        i386|i686) GOARCH="386"; ARCH_SUFFIX="386" ;;
        mips) GOARCH="mips"; ARCH_SUFFIX="mips-softfloat" ;;
        mipsle) GOARCH="mipsle"; ARCH_SUFFIX="mipsle-softfloat" ;;
        mips64) GOARCH="mips64"; ARCH_SUFFIX="mips64" ;;
        mips64le) GOARCH="mips64le"; ARCH_SUFFIX="mips64le" ;;
        riscv64) GOARCH="riscv64"; ARCH_SUFFIX="riscv64" ;;
        loongarch64) GOARCH="loong64"; ARCH_SUFFIX="loong64" ;;
        *) GOARCH="unknown"; ARCH_SUFFIX="unknown" ;;
    esac

    # Build list of architecture variants to try for downloads
    case $ARCH in
        x86_64) ARCH_LIST=("amd64") ;;
        aarch64) ARCH_LIST=("arm64") ;;
        armv7l) ARCH_LIST=("armv7" "arm") ;;
        armv6l) ARCH_LIST=("armv6" "arm") ;;
        armv5l) ARCH_LIST=("armv5" "arm") ;;
        i386|i686) ARCH_LIST=("386") ;;
        mips) ARCH_LIST=("mips-hardfloat" "mips-softfloat" "mips") ;;
        mipsle) ARCH_LIST=("mipsle-hardfloat" "mipsle-softfloat" "mipsle") ;;
        mips64) ARCH_LIST=("mips64") ;;
        mips64le) ARCH_LIST=("mips64le") ;;
        riscv64) ARCH_LIST=("riscv64") ;;
        loongarch64) ARCH_LIST=("loong64") ;;
        *) ARCH_LIST=("$GOARCH") ;;
    esac

    log_info "$(_ OS_INFO) $OS_PRETTY"
    log_info "$(_ ARCH_INFO) $ARCH (Go: $GOARCH)"
}

detect_init() {
    log_step "$(_ DETECT_INIT)"

    if [[ -d /run/systemd/system ]] || command -v systemctl &>/dev/null; then
        INIT_SYSTEM="systemd"
    elif [[ -f /etc/init.d/rc ]] && [[ -f /sbin/rc-update ]]; then
        INIT_SYSTEM="openrc"
    elif command -v sv &>/dev/null || [[ -d /etc/sv ]]; then
        INIT_SYSTEM="runit"
    elif [[ -f /etc/inittab ]] && ! grep -q openrc /etc/inittab 2>/dev/null; then
        INIT_SYSTEM="sysvinit"
    elif [[ -f /etc/inittab ]] && grep -q busybox /etc/inittab 2>/dev/null; then
        INIT_SYSTEM="busybox"
    else
        INIT_SYSTEM="unknown"
    fi

    log_info "$(_ INIT_INFO) $INIT_SYSTEM"
}

check_docker() {
    command -v docker &>/dev/null
}

check_pm2() {
    command -v pm2 &>/dev/null
}

check_screen() {
    command -v screen &>/dev/null
}

#######################################
# Download Precompiled Binary
#######################################
get_latest_version() {
    echo -e "${BLUE}$(_ STEP)${NC} $(_ FETCH_VERSION)" >&2

    local version
    version=$(curl -s "$GITHUB_API" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')

    if [[ -z "$version" ]]; then
        echo -e "${RED}$(_ ERROR)${NC} Failed to fetch latest version from GitHub API" >&2
        return 1
    fi

    echo "$version"
}

download_binary() {
    local version="$1"
    local target_arch="$2"
    local output_file="$3"

    local url="${DOWNLOAD_BASE}/${version}/miaospeed-linux-${target_arch}-${version}.tar.gz"
    local temp_file="/tmp/miaospeed-${target_arch}.tar.gz"

    log_info "$(_ DOWNLOADING) $url"

    if ! curl -L -o "$temp_file" "$url" --progress-bar 2>/dev/null; then
        if ! curl -L -o "$temp_file" "$url" -f -sS 2>/dev/null; then
            log_warn "Download failed for: $url"
            rm -f "$temp_file"
            return 1
        fi
    fi

    if ! tar -tzf "$temp_file" &>/dev/null; then
        log_warn "Downloaded file is not a valid tar.gz archive"
        rm -f "$temp_file"
        return 1
    fi

    tar -xzf "$temp_file" -C /tmp/

    local found=false
    local extracted_dir="/tmp/miaospeed-linux-${target_arch}"
    if [[ -d "$extracted_dir" ]]; then
        if [[ -f "$extracted_dir/miaospeed" ]]; then
            mv "$extracted_dir/miaospeed" "$output_file"
            rm -rf "$extracted_dir"
            found=true
        fi
    fi

    if [[ "$found" == false ]]; then
        for f in /tmp/miaospeed /tmp/miaospeed-*; do
            if [[ -f "$f" && ! "$f" =~ \.tar\.gz$ ]]; then
                mv "$f" "$output_file"
                found=true
                break
            fi
        done
    fi

    rm -f "$temp_file"

    if [[ "$found" == true ]]; then
        chmod +x "$output_file"
        log_info "$(_ DOWNLOADED) $output_file"
        return 0
    fi

    log_warn "Could not find miaospeed binary in archive"
    return 1
}

show_download_error() {
    local arch="$1"

    echo ""
    log_error "$(_ DOWNLOAD_FAILED_AND_REASON)"
    echo ""
    echo "  - $(_ REASON_NO_PREBUILT)"
    echo "  - $(_ REASON_NETWORK)"
    echo "  - $(_ REASON_NOT_FOUND)"
    echo ""
    echo "$(_ SUGGEST_CHECK)"
    echo ""
    echo "  git clone https://github.com/AirportR/miaospeed.git"
    echo "  cd miaospeed"
    echo "  CGO_ENABLED=0 go build -trimpath -ldflags='-w -s -buildid=' -o miaospeed ."
    echo ""
}

#######################################
# Compile from Source
#######################################
compile_from_source() {
    log_step "$(_ COMPILE_SOURCE)"

    if ! command -v go &>/dev/null; then
        log_error "$(_ GO_NOT_INSTALLED)"
        install_go
    fi

    local work_dir="/tmp/miaospeed-src"
    rm -rf "$work_dir"
    mkdir -p "$work_dir"

    log_info "$(_ CLONING_SOURCE)"
    git clone --depth 1 https://github.com/AirportR/miaospeed.git "$work_dir" || {
        log_error "Failed to clone repository"
        return 1
    }

    cd "$work_dir" || {
        log_error "Failed to change to directory: $work_dir"
        return 1
    }

    prepare_embedded_files || return 1

    log_info "$(_ BUILDING)"
    CGO_ENABLED=0 go build -trimpath -ldflags='-w -s -buildid=' -o miaospeed .

    if [[ ! -f miaospeed ]]; then
        log_error "$(_ COMPILATION_FAILED)"
        return 1
    fi

    cp miaospeed "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/miaospeed"

    cd / || return 1
    rm -rf "$work_dir"

    log_info "$(_ COMPILATION_COMPLETE)"
}

prepare_embedded_files() {
    mkdir -p utils/embeded
    mkdir -p preconfigs/embeded/tls
    mkdir -p engine/embeded

    if [[ ! -f "utils/embeded/BUILDTOKEN.key" ]]; then
        echo "MIAOKO4|580JxAo049R|GEnERAl|1X571R930|T0kEN" > utils/embeded/BUILDTOKEN.key
    fi

    # preconfigs/embeded/tls 整个目录会被内嵌，且编译要求这里至少有一对 TLS 证书。
    # 没有证书就直接失败，不再写占位内容：占位内容不是证书，只会产出一个起不来的二进制。
    if [[ -z "$(ls preconfigs/embeded/tls/*.crt 2>/dev/null)" ]]; then
        if ! command -v openssl >/dev/null 2>&1; then
            log_error "$(_ NO_TLS_CERT)"
            return 1
        fi
        openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout preconfigs/embeded/tls/miaoko.key \
            -out preconfigs/embeded/tls/miaoko.crt \
            -days 3650 \
            -subj "/C=US/ST=State/L=City/O=MiaoSpeed/CN=miaospeed" 2>/dev/null || {
            log_error "$(_ NO_TLS_CERT)"
            return 1
        }
    fi

    if [[ ! -f "preconfigs/embeded/ca-certificates.crt" ]]; then
        if [[ -f /etc/ssl/certs/ca-certificates.crt ]]; then
            cp /etc/ssl/certs/ca-certificates.crt preconfigs/embeded/
        elif [[ -f /etc/pki/tls/certs/ca-bundle.crt ]]; then
            cp /etc/pki/tls/certs/ca-bundle.crt preconfigs/embeded/ca-certificates.crt
        elif [[ -f /etc/ssl/cert.pem ]]; then
            cp /etc/ssl/cert.pem preconfigs/embeded/ca-certificates.crt
        else
            touch preconfigs/embeded/ca-certificates.crt
        fi
    fi

    if [[ ! -f "engine/embeded/predefined.js" ]]; then
        cat > engine/embeded/predefined.js << 'JS_EOF'
function get(url) { return { body: "", status: 200 }; }
function safeStringify(obj) { return JSON.stringify(obj); }
function safeParse(str) { try { return JSON.parse(str); } catch(e) { return null; } }
function println(msg) { console.log(msg); }
JS_EOF
    fi

    if [[ ! -f "engine/embeded/default_geoip.js" ]]; then
        cat > engine/embeded/default_geoip.js << 'JS_EOF'
function handler(ip) { return { country: "Unknown", continent: "Unknown" }; }
JS_EOF
    fi

    if [[ ! -f "engine/embeded/default_ip.js" ]]; then
        cat > engine/embeded/default_ip.js << 'JS_EOF'
function ip_resolve_default() { return { localIP: "127.0.0.1", remoteIP: "127.0.0.1" }; }
JS_EOF
    fi
}

install_go() {
    if [[ -f /etc/debian_version ]]; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y golang git
    elif [[ -f /etc/redhat-release ]]; then
        if command -v dnf &>/dev/null; then
            dnf install -y golang git
        else
            yum install -y golang git
        fi
    elif command -v apk &>/dev/null; then
        apk add go git
    elif command -v pacman &>/dev/null; then
        pacman -Sy --noconfirm go git
    else
        log_error "Cannot install Go automatically. Please install Go 1.21+ manually."
        exit 1
    fi
}

#######################################
# Persistence Method Selection
#######################################
select_persistence_method() {
    local has_systemd=false
    local has_openrc=false
    local has_pm2=false
    local has_screen=false

    [[ "$INIT_SYSTEM" == "systemd" ]] && has_systemd=true
    [[ "$INIT_SYSTEM" == "openrc" ]] && has_openrc=true
    check_pm2 && has_pm2=true
    check_screen && has_screen=true

    echo ""
    log_menu "$(_ CHOOSE_PERSISTENCE)"
    echo ""

    local options=()
    if [[ "$has_systemd" == true ]]; then
        options+=("systemd")
    fi
    if [[ "$has_openrc" == true ]]; then
        options+=("openrc")
    fi
    options+=("screen")
    options+=("pm2")
    options+=("none")

    local option_num=1
    for opt in "${options[@]}"; do
        case $opt in
            systemd)
                echo "  $option_num) systemd ($(_ PERSIST_SYSTEMD))"
                ;;
            openrc)
                echo "  $option_num) OpenRC ($(_ PERSIST_OPENRC))"
                ;;
            screen)
                if [[ "$has_screen" == true ]]; then
                    echo "  $option_num) screen ($(_ PERSIST_SCREEN))"
                else
                    echo "  $option_num) screen ($(_ PERSIST_SCREEN)) ${YELLOW}$(_ SCREEN_NOT_FOUND)${NC}"
                fi
                ;;
            pm2)
                if [[ "$has_pm2" == true ]]; then
                    echo "  $option_num) PM2 ($(_ PERSIST_PM2))"
                else
                    echo "  $option_num) PM2 ($(_ PERSIST_PM2)) ${YELLOW}$(_ PM2_NOT_FOUND)${NC}"
                fi
                ;;
            none)
                echo "  $option_num) $(_ PERSIST_NOAUTO)"
                ;;
        esac
        ((option_num++))
    done
    echo "  0) $(_ MODE_EXIT)"
    echo ""

    read -p "$(_ ENTER_CHOICE) [0-$((option_num-1))]: " choice

    if [[ "$choice" == "0" ]]; then
        log_info "$(_ EXITING)"
        exit 0
    fi

    if [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -le "${#options[@]}" ]]; then
        PERSISTENCE_METHOD="${options[$((choice-1))]}"

        if [[ "$PERSISTENCE_METHOD" == "pm2" ]] && [[ "$has_pm2" == false ]]; then
            log_info "$(_ INSTALL_PM2)"
            install_pm2
        fi
    else
        log_error "$(_ INVALID_CHOICE)"
        select_persistence_method
        return
    fi
}

install_pm2() {
    if ! command -v npm &>/dev/null; then
        log_error "npm not found. Please install Node.js first:"
        echo "  curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -"
        echo "  sudo apt-get install -y nodejs"
        exit 1
    fi
    npm install -g pm2
}

#######################################
# Build Command Arguments (returns array)
#######################################
build_command_args() {
    local args=(
        "server"
        "-bind" "$CFG_BIND"
        "-token" "$CFG_TOKEN"
        "-path" "$CFG_PATH"
        "-allowip" "$CFG_ALLOWIP"
        "-connthread" "$CFG_CONTHREAD"
        "-tasklimit" "$CFG_TASKLIMIT"
    )
    [[ -n "$CFG_WHITELIST" ]] && args+=("-whitelist" "$CFG_WHITELIST")
    [[ "$CFG_NOSPEED" == true ]] && args+=("-nospeed")
    [[ "$CFG_IPV6" == true ]] && args+=("-ipv6")
    [[ "$CFG_MTLS" == true ]] && args+=("-mtls")
    [[ "$CFG_UPLOAD" == true ]] && args+=("-upload")
    [[ "$CFG_SPEEDLIMIT" != "0" ]] && args+=("-speedlimit" "$CFG_SPEEDLIMIT")
    [[ "$CFG_PAUSESECOND" != "0" ]] && args+=("-pausesecond" "$CFG_PAUSESECOND")
    [[ -n "$CFG_MMDB" ]] && args+=("-mmdb" "$CFG_MMDB")
    [[ -n "$CFG_CERT_PUB" ]] && args+=("-serverpublickey" "$CFG_CERT_PUB")
    [[ -n "$CFG_CERT_PRIV" ]] && args+=("-serverprivatekey" "$CFG_CERT_PRIV")
    [[ -n "$CFG_CLIENT_CA" ]] && args+=("-clientca" "$CFG_CLIENT_CA")

    # Return array via global variable
    COMMAND_ARGS=("${args[@]}")
}

# Get command args as a string (for compatibility with legacy code)
get_command_args_string() {
    build_command_args
    local args=()
    # Define backtick as a variable to avoid quoting issues
    local backtick='`'
    for arg in "${COMMAND_ARGS[@]}"; do
        # Properly quote arguments containing spaces or special characters
        if [[ "$arg" =~ [[:space:]]|\"|\'|\$|\\|${backtick}|\&|\||\;|\<|\>|\(|\) ]]; then
            args+=("\"${arg//\"/\\\"}\"")
        else
            args+=("$arg")
        fi
    done
    echo "${args[*]}"
}

#######################################
# Local Deployment
#######################################
deploy_local() {
    log_step "$(_ DEPLOY_LOCAL)"

    # Run wizard if token/path not set
    if [[ -z "$CFG_TOKEN" ]] || [[ -z "$CFG_PATH" ]] || [[ "$CFG_PATH" == "/" ]]; then
        config_wizard
    fi

    mkdir -p "$INSTALL_DIR"

    # Download or compile binary
    if [[ "$COMPILE_FROM_SOURCE" == true ]]; then
        compile_from_source
    else
        local version
        version=$(get_latest_version)

        if [[ -z "$version" ]]; then
            show_download_error "$ARCH_SUFFIX"
            exit 1
        fi

        log_info "$(_ LATEST_VERSION) $version"

        local downloaded=false
        for arch in "${ARCH_LIST[@]}"; do
            if [[ "$arch" != "unknown" ]]; then
                log_info "$(_ TRYING_ARCH) $arch"
                if download_binary "$version" "$arch" "$INSTALL_DIR/miaospeed"; then
                    downloaded=true
                    break
                fi
            fi
        done

        if [[ "$downloaded" == false ]]; then
            log_error "$(_ FAILED_DOWNLOAD) $ARCH_SUFFIX / $GOARCH"
            show_download_error "$ARCH_SUFFIX"
            exit 1
        fi
    fi

    # Create symlink in user bin
    mkdir -p "$HOME/.local/bin"
    ln -sf "$INSTALL_DIR/miaospeed" "$HOME/.local/bin/miaospeed" 2>/dev/null || true

    if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc" 2>/dev/null || true
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.zshrc" 2>/dev/null || true
    fi

    # Select persistence method if not specified
    if [[ -z "$PERSISTENCE_METHOD" ]]; then
        select_persistence_method
    fi

    # Save all params
    save_all_params
    save_config "persistence_method" "$PERSISTENCE_METHOD"

    install_persistence
    start_service

    print_local_summary
}

print_local_summary() {
    local port
    port=$(echo "$CFG_BIND" | cut -d: -f2)
    [[ -z "$port" ]] && port="8080"

    echo ""
    log_info "=================================="
    log_info "$(_ INSTALL_SUCCESS)"
    log_info "=================================="
    echo ""
    print_current_config
    echo ""

    echo "$(_ BINARY) $INSTALL_DIR/miaospeed"
    echo "$(_ USER_DIR) $INSTALL_DIR"
    echo ""

    echo "$(_ SERVICE_COMMANDS)"
    case $PERSISTENCE_METHOD in
        systemd)
            if [[ $EUID -eq 0 ]]; then
                echo "  systemctl start|stop|restart|status $SERVICE_NAME"
            else
                echo "  systemctl --user start|stop|restart|status $SERVICE_NAME"
            fi
            ;;
        openrc)
            echo "  /etc/init.d/$SERVICE_NAME start|stop|restart"
            ;;
        screen)
            echo "  $(_ SCREEN_START)"
            echo "  $(_ SCREEN_ATTACH)"
            ;;
        pm2)
            echo "  pm2 start|stop|restart|status miaospeed"
            echo "  pm2 logs miaospeed"
            ;;
        none)
            echo "  $INSTALL_DIR/start.sh"
            ;;
    esac

    echo ""
    echo "Management Commands:"
    echo "  $0 status    # Show service status"
    echo "  $0 stop      # Stop service"
    echo "  $0 start     # Start service"
    echo "  $0 restart   # Restart service"
    echo "  $0 config    # Edit configuration"
    echo "  $0 logs      # View logs"
    echo "  $0 uninstall # Uninstall MiaoSpeed"
    echo ""
}

#######################################
# Persistence Installation
#######################################
install_persistence() {
    log_step "$(_ INSTALL_SERVICE)"

    if [[ "$PERSISTENCE_METHOD" == "systemd" ]] || [[ "$PERSISTENCE_METHOD" == "openrc" ]]; then
        if [[ $EUID -ne 0 ]]; then
            log_warn "$(_ SYSTEM_SERVICE_NEEDS_ROOT)"
            log_info "$(_ NOT_ROOT)"
            if check_pm2; then
                PERSISTENCE_METHOD="pm2"
                log_info "$(_ USING_PM2)"
            elif check_screen; then
                PERSISTENCE_METHOD="screen"
                log_info "$(_ USING_SCREEN)"
            else
                PERSISTENCE_METHOD="none"
                log_info "$(_ NO_AUTO_CONFIG)"
            fi
        fi
    fi

    case $PERSISTENCE_METHOD in
        systemd)
            create_systemd_service
            if [[ $EUID -eq 0 ]]; then
                systemctl daemon-reload
                systemctl enable "$SERVICE_NAME"
                log_info "$(_ SERVICE_ENABLED) for systemd"
            else
                systemctl --user daemon-reload
                systemctl --user enable "$SERVICE_NAME"
                log_info "$(_ SERVICE_ENABLED) for systemd user"
            fi
            ;;
        openrc)
            create_openrc_service
            rc-update add "$SERVICE_NAME" default
            log_info "$(_ SERVICE_ENABLED) for OpenRC"
            ;;
        screen)
            create_screen_wrapper
            log_info "$(_ SCREEN_WRAPPER_CREATED)"
            ;;
        pm2)
            create_pm2_config
            log_info "$(_ PM2_CONFIG_CREATED)"
            ;;
        none)
            create_manual_start
            log_info "$(_ MANUAL_START_CREATED)"
            ;;
    esac
}

# Recreate service files (for config edit)
recreate_service_files() {
    case $PERSISTENCE_METHOD in
        systemd)
            create_systemd_service
            if [[ $EUID -eq 0 ]]; then
                systemctl daemon-reload
            else
                systemctl --user daemon-reload
            fi
            ;;
        openrc)
            create_openrc_service
            ;;
        screen)
            create_screen_wrapper
            ;;
        pm2)
            create_pm2_config
            ;;
        none)
            create_manual_start
            ;;
    esac
}

create_systemd_service() {
    local service_dir=""
    local exec_user="$USER"
    build_command_args

    if [[ $EUID -eq 0 ]]; then
        service_dir="/etc/systemd/system"
        exec_user="root"
    else
        mkdir -p "$HOME/.config/systemd/user"
        service_dir="$HOME/.config/systemd/user"
    fi

    # Build ExecStart line with proper array handling
    local exec_start="$INSTALL_DIR/miaospeed"
    for arg in "${COMMAND_ARGS[@]}"; do
        exec_start+=" \"${arg//\"/\\\"}\""
    done

    cat > "$service_dir/$SERVICE_NAME.service" << EOF
[Unit]
Description=MiaoSpeed Backend Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$exec_user
WorkingDirectory=$INSTALL_DIR
ExecStart=$exec_start

Restart=always
RestartSec=5s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=miaospeed

[Install]
WantedBy=default.target
EOF

    if [[ $EUID -ne 0 ]]; then
        loginctl enable-linger "$USER" 2>/dev/null || true
    fi

    log_info "systemd service created at $service_dir/$SERVICE_NAME.service"
}

create_openrc_service() {
    build_command_args

    # Build command_args string with proper quoting
    local cmd_args=""
    for arg in "${COMMAND_ARGS[@]}"; do
        cmd_args+=" \"${arg//\"/\\\"}\""
    done

    cat > "/etc/init.d/$SERVICE_NAME" << 'OPENRC_EOF'
#!/sbin/openrc-run

name="miaospeed"
description="MiaoSpeed Backend Server"
command="INSTALL_DIR_PLACEHOLDER"
command_args="COMMAND_ARGS_PLACEHOLDER"
command_background=true
pidfile="/var/run/$RC_SVCNAME.pid"
output_log="/var/log/miaospeed.log"
error_log="/var/log/miaospeed.error"

depend() {
    need net
    after firewall
}
OPENRC_EOF

    sed -i "s|INSTALL_DIR_PLACEHOLDER|$INSTALL_DIR/miaospeed|g" "/etc/init.d/$SERVICE_NAME"
    sed -i "s|COMMAND_ARGS_PLACEHOLDER|$cmd_args|g" "/etc/init.d/$SERVICE_NAME"

    chmod +x "/etc/init.d/$SERVICE_NAME"
    log_info "$(_ OPENRC_SERVICE_CREATED)"
}

create_screen_wrapper() {
    build_command_args

    # Build command string with proper quoting
    local cmd_string="$INSTALL_DIR/miaospeed"
    for arg in "${COMMAND_ARGS[@]}"; do
        cmd_string+=" \"${arg//\"/\\\"}\""
    done

    cat > "$INSTALL_DIR/start.sh" << EOF
#!/bin/bash
cd "$INSTALL_DIR" || exit 1
while true; do
    $cmd_string
    sleep 5
done
EOF
    chmod +x "$INSTALL_DIR/start.sh"

    (crontab -l 2>/dev/null | grep -v "miaospeed"; echo "@reboot screen -dmS miaospeed $INSTALL_DIR/start.sh") | crontab - 2>/dev/null || true

    log_info "$(_ SCREEN_WRAPPER_HINT) $INSTALL_DIR/start.sh"
}

create_pm2_config() {
    build_command_args

    # Build args array as JSON string
    local json_args="["
    local first=true
    for arg in "${COMMAND_ARGS[@]}"; do
        if [[ "$first" == true ]]; then
            first=false
        else
            json_args+=","
        fi
        # Escape JSON special characters
        local escaped_arg="${arg//\\/\\\\}"
        escaped_arg="${escaped_arg//\"/\\\"}"
        json_args+="\"$escaped_arg\""
    done
    json_args+="]"

    cat > "$INSTALL_DIR/pm2.config.json" << EOF
{
  "name": "$SERVICE_NAME",
  "script": "$INSTALL_DIR/miaospeed",
  "args": $json_args,
  "cwd": "$INSTALL_DIR",
  "autostart": true,
  "watch": false,
  "max_restarts": 10,
  "min_uptime": "10s",
  "restart_delay": 4000
}
EOF

    log_info "$(_ PM2_CONFIG_HINT) $INSTALL_DIR/pm2.config.json"
}

create_manual_start() {
    build_command_args

    # Build command string with proper quoting
    local cmd_string="$INSTALL_DIR/miaospeed"
    for arg in "${COMMAND_ARGS[@]}"; do
        cmd_string+=" \"${arg//\"/\\\"}\""
    done

    cat > "$INSTALL_DIR/start.sh" << EOF
#!/bin/bash
cd "$INSTALL_DIR" || exit 1
$cmd_string
EOF
    chmod +x "$INSTALL_DIR/start.sh"
    log_info "$(_ MANUAL_START_HINT) $INSTALL_DIR/start.sh"
}

start_service() {
    log_step "$(_ START_SERVICE)"

    case $PERSISTENCE_METHOD in
        systemd)
            if [[ $EUID -eq 0 ]]; then
                systemctl restart "$SERVICE_NAME"
                sleep 1
                systemctl status "$SERVICE_NAME" --no-pager || true
            else
                systemctl --user restart "$SERVICE_NAME"
                sleep 1
                systemctl --user status "$SERVICE_NAME" --no-pager || true
            fi
            ;;
        openrc)
            /etc/init.d/$SERVICE_NAME restart
            ;;
        screen)
            screen -S miaospeed -X quit 2>/dev/null || true
            sleep 1
            screen -dmS miaospeed "$INSTALL_DIR/start.sh"
            log_info "$(_ STARTED_SCREEN)"
            ;;
        pm2)
            pm2 stop "$SERVICE_NAME" 2>/dev/null || true
            pm2 delete "$SERVICE_NAME" 2>/dev/null || true
            pm2 start "$INSTALL_DIR/pm2.config.json"
            pm2 save
            log_info "$(_ STARTED_PM2)"
            ;;
        none)
            log_info "$(_ NO_AUTO_HINT) $INSTALL_DIR/start.sh"
            ;;
    esac
}

#######################################
# Docker Deployment
#######################################
deploy_docker() {
    log_step "$(_ DEPLOY_DOCKER)"

    if [[ -z "$CFG_TOKEN" ]] || [[ -z "$CFG_PATH" ]] || [[ "$CFG_PATH" == "/" ]]; then
        config_wizard
    fi

    local version
    version=$(get_latest_version)

    if [[ -z "$version" ]]; then
        log_error "Failed to fetch latest version from GitHub API"
        exit 1
    fi

    log_info "$(_ LATEST_VERSION) $version"

    # Build Docker command arguments
    local docker_args=""
    [[ -n "$CFG_TOKEN" ]] && docker_args="$docker_args -e TOKEN=$CFG_TOKEN"
    [[ -n "$CFG_BIND" ]] && docker_args="$docker_args -e BIND=$CFG_BIND"
    [[ -n "$CFG_PATH" ]] && docker_args="$docker_args -e PATH=$CFG_PATH"
    [[ -n "$CFG_ALLOWIP" ]] && docker_args="$docker_args -e ALLOWIP=$CFG_ALLOWIP"
    [[ -n "$CFG_WHITELIST" ]] && docker_args="$docker_args -e WHITELIST=$CFG_WHITELIST"
    [[ "$CFG_NOSPEED" == true ]] && docker_args="$docker_args -e NOSPEED=true"
    [[ "$CFG_IPV6" == true ]] && docker_args="$docker_args -e IPV6=true"
    [[ "$CFG_MTLS" == true ]] && docker_args="$docker_args -e MTLS=true"
    [[ "$CFG_UPLOAD" == true ]] && docker_args="$docker_args -e UPLOAD=true"
    [[ "$CFG_CONTHREAD" != "64" ]] && docker_args="$docker_args -e CONTHREAD=$CFG_CONTHREAD"
    [[ "$CFG_TASKLIMIT" != "1000" ]] && docker_args="$docker_args -e TASKLIMIT=$CFG_TASKLIMIT"
    [[ "$CFG_SPEEDLIMIT" != "0" ]] && docker_args="$docker_args -e SPEEDLIMIT=$CFG_SPEEDLIMIT"
    [[ "$CFG_PAUSESECOND" != "0" ]] && docker_args="$docker_args -e PAUSESECOND=$CFG_PAUSESECOND"
    [[ -n "$CFG_MMDB" ]] && docker_args="$docker_args -e MMDB=$CFG_MMDB"

    local port
    port=$(echo "$CFG_BIND" | cut -d: -f2)
    [[ -z "$port" ]] && port="8080"

    log_info "$(_ PULLING_DOCKER_IMAGE) ghcr.io/airportr/miaospeed:$version"
    if ! docker pull "ghcr.io/airportr/miaospeed:$version" 2>/dev/null; then
        log_info "$(_ TRYING_DOCKER_HUB)"
        if ! docker pull "airportr/miaospeed:$version" 2>/dev/null; then
            log_warn "Pre-built image not found. Building from source..."
            build_docker_image
            return 0
        fi
    fi

    if docker ps -a --format '{{.Names}}' | grep -q "^${SERVICE_NAME}$"; then
        log_info "$(_ REMOVING_CONTAINER)"
        docker rm -f "$SERVICE_NAME" 2>/dev/null || true
    fi

    log_info "$(_ STARTING_CONTAINER)"
    docker run -d \
        --name "$SERVICE_NAME" \
        --restart unless-stopped \
        -p "$port:8080" \
        $docker_args \
        "airportr/miaospeed:$version" || \
    docker run -d \
        --name "$SERVICE_NAME" \
        --restart unless-stopped \
        -p "$port:8080" \
        $docker_args \
        "ghcr.io/airportr/miaospeed:$version"

    # Save params
    PERSISTENCE_METHOD="docker"
    save_all_params

    print_docker_summary "$port"
}

build_docker_image() {
    log_info "$(_ BUILDING_DOCKER_IMAGE)"

    local work_dir="/tmp/miaospeed-docker"
    rm -rf "$work_dir"
    mkdir -p "$work_dir"

    git clone --depth 1 https://github.com/AirportR/miaospeed.git "$work_dir" || {
        log_error "Failed to clone repository"
        return 1
    }

    cd "$work_dir" || {
        log_error "Failed to change to directory: $work_dir"
        return 1
    }
    docker build -t miaospeed:latest .

    cd / || return 1
    rm -rf "$work_dir"

    local port
    port=$(echo "$CFG_BIND" | cut -d: -f2)
    [[ -z "$port" ]] && port="8080"

    docker run -d \
        --name "$SERVICE_NAME" \
        --restart unless-stopped \
        -p "$port:8080" \
        -e BIND="$CFG_BIND" \
        -e TOKEN="$CFG_TOKEN" \
        -e PATH="$CFG_PATH" \
        miaospeed:latest

    print_docker_summary "$port"
}

print_docker_summary() {
    local port="$1"
    echo ""
    log_info "=================================="
    log_info "$(_ DOCKER_DEPLOYED)"
    log_info "=================================="
    echo ""
    print_current_config
    echo ""
    echo "$(_ CONTAINER_NAME) $SERVICE_NAME"
    echo "$(_ PORT) $port"
    echo ""
    echo "$(_ DOCKER_COMMANDS)"
    echo "  docker logs $SERVICE_NAME      # View logs"
    echo "  docker stop $SERVICE_NAME      # Stop container"
    echo "  docker start $SERVICE_NAME     # Start container"
    echo "  docker restart $SERVICE_NAME   # Restart container"
    echo "  docker rm -f $SERVICE_NAME     # Remove container"
    echo ""
}

#######################################
# Service Management Functions
#######################################

# Generic service operation handler
# Usage: _service_op <operation> <method>
# operation: start/stop/restart
# method: pm2/systemd/openrc/screen/docker
_service_op() {
    local op="$1"
    local method="$2"

    case $method in
        pm2)
            if command -v pm2 &>/dev/null; then
                case $op in
                    start)   pm2 start "$SERVICE_NAME" 2>/dev/null || pm2 start "$INSTALL_DIR/pm2.config.json" 2>/dev/null ;;
                    stop)    pm2 stop "$SERVICE_NAME" 2>/dev/null ;;
                    restart) pm2 restart "$SERVICE_NAME" 2>/dev/null ;;
                esac
                return 0
            else
                log_warn "PM2 not found"
                return 1
            fi
            ;;
        systemd)
            local svc_file=""
            if [[ $EUID -eq 0 ]] && [[ -f "/etc/systemd/system/$SERVICE_NAME.service" ]]; then
                svc_file="/etc/systemd/system/$SERVICE_NAME.service"
            elif [[ -f "$HOME/.config/systemd/user/$SERVICE_NAME.service" ]]; then
                svc_file="$HOME/.config/systemd/user/$SERVICE_NAME.service"
            fi

            if [[ -n "$svc_file" ]]; then
                local systemctl_cmd="systemctl"
                [[ $EUID -ne 0 ]] && systemctl_cmd="systemctl --user"

                case $op in
                    start)   $systemctl_cmd start "$SERVICE_NAME" 2>/dev/null ;;
                    stop)    $systemctl_cmd stop "$SERVICE_NAME" 2>/dev/null ;;
                    restart) $systemctl_cmd restart "$SERVICE_NAME" 2>/dev/null ;;
                esac
                return 0
            else
                log_warn "systemd service not found"
                return 1
            fi
            ;;
        openrc)
            if [[ -f "/etc/init.d/$SERVICE_NAME" ]]; then
                /etc/init.d/$SERVICE_NAME $op 2>/dev/null
                return 0
            else
                log_warn "OpenRC service not found"
                return 1
            fi
            ;;
        screen)
            case $op in
                stop|restart)
                    screen -S miaospeed -X quit 2>/dev/null || true
                    [[ "$op" == "stop" ]] && return 0
                    ;&  # fall through for restart
                start)
                    if [[ -f "$INSTALL_DIR/start.sh" ]]; then
                        screen -dmS miaospeed "$INSTALL_DIR/start.sh"
                        return 0
                    else
                        log_warn "Start script not found"
                        return 1
                    fi
                    ;;
            esac
            ;;
        docker)
            if command -v docker &>/dev/null; then
                case $op in
                    start)   docker start "$SERVICE_NAME" 2>/dev/null ;;
                    stop)    docker stop "$SERVICE_NAME" 2>/dev/null ;;
                    restart) docker restart "$SERVICE_NAME" 2>/dev/null ;;
                esac
                return 0
            else
                log_warn "Docker not found"
                return 1
            fi
            ;;
        *)
            log_warn "No MiaoSpeed service configuration found"
            return 1
            ;;
    esac
}

detect_persistence_method() {
    if [[ -f "$PARAMS_FILE" ]]; then
        source "$PARAMS_FILE"
        echo "$PERSISTENCE_METHOD"
        return
    fi

    if [[ -f "$INSTALL_DIR/pm2.config.json" ]] || command -v pm2 &>/dev/null && pm2 list | grep -q "$SERVICE_NAME"; then
        echo "pm2"
    elif [[ -f "$HOME/.config/systemd/user/$SERVICE_NAME.service" ]] || [[ -f "/etc/systemd/system/$SERVICE_NAME.service" ]]; then
        echo "systemd"
    elif [[ -f "/etc/init.d/$SERVICE_NAME" ]]; then
        echo "openrc"
    elif screen -ls | grep -q "miaospeed"; then
        echo "screen"
    else
        echo "unknown"
    fi
}

stop_service() {
    log_step "$(_ STOPPING_SERVICE)"

    local method
    method=$(detect_persistence_method)

    if _service_op stop "$method"; then
        log_info "$(_ SERVICE_STOPPED)"
    fi
}

start_service_cmd() {
    log_step "Starting MiaoSpeed service..."

    local method
    method=$(detect_persistence_method)

    if _service_op start "$method"; then
        log_info "$(_ SERVICE_STARTED)"
    fi
}

restart_service() {
    log_step "Restarting MiaoSpeed service..."

    local method
    method=$(detect_persistence_method)

    if _service_op restart "$method"; then
        log_info "$(_ SERVICE_RESTARTED)"
    fi
}

show_status() {
    echo ""
    echo "=================================="
    echo "   MiaoSpeed Status"
    echo "=================================="
    echo ""

    local method
    method=$(detect_persistence_method)

    echo "Persistence Method: $method"
    echo ""

    case $method in
        pm2)
            if command -v pm2 &>/dev/null; then
                pm2 status "$SERVICE_NAME" 2>/dev/null || pm2 list | grep -E "(name|status|$SERVICE_NAME)"
            else
                echo "PM2 not found"
            fi
            ;;
        systemd)
            if [[ $EUID -eq 0 ]] && [[ -f "/etc/systemd/system/$SERVICE_NAME.service" ]]; then
                systemctl status "$SERVICE_NAME" --no-pager 2>/dev/null || echo "Service not running"
            elif [[ -f "$HOME/.config/systemd/user/$SERVICE_NAME.service" ]]; then
                systemctl --user status "$SERVICE_NAME" --no-pager 2>/dev/null || echo "Service not running"
            else
                echo "systemd service not found"
            fi
            ;;
        openrc)
            if [[ -f "/etc/init.d/$SERVICE_NAME" ]]; then
                /etc/init.d/$SERVICE_NAME status 2>/dev/null || echo "Service status unknown"
            else
                echo "OpenRC service not found"
            fi
            ;;
        screen)
            if screen -ls | grep -q "miaospeed"; then
                echo "Screen session: running"
                screen -ls | grep miaospeed
            else
                echo "Screen session: not running"
            fi
            ;;
        docker)
            if command -v docker &>/dev/null; then
                docker ps -a --filter "name=$SERVICE_NAME" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
            else
                echo "Docker not found"
            fi
            ;;
        *)
            echo "No MiaoSpeed service found"
            echo ""
            echo "Binary location: $INSTALL_DIR/miaospeed"
            [[ -f "$INSTALL_DIR/miaospeed" ]] && echo "Binary: exists" || echo "Binary: not found"
            ;;
    esac

    echo ""
}

is_systemd_usable() {
    if [[ "$INIT_SYSTEM" != "systemd" ]]; then
        return 1
    fi

    if systemctl --version &>/dev/null; then
        return 0
    fi

    return 1
}

#######################################
# Uninstall
#######################################
uninstall_miaospeed() {
    log_step "$(_ UNINSTALL)"

    local method
    method=$(detect_persistence_method)

    case $method in
        pm2)
            if command -v pm2 &>/dev/null; then
                log_info "$(_ STOPPING_PM2)"
                pm2 stop "$SERVICE_NAME" 2>/dev/null || true
                pm2 delete "$SERVICE_NAME" 2>/dev/null || true
            fi
            ;;
        systemd)
            if is_systemd_usable; then
                if [[ $EUID -eq 0 ]] && [[ -f "/etc/systemd/system/$SERVICE_NAME.service" ]]; then
                    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
                    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
                    rm -f "/etc/systemd/system/$SERVICE_NAME.service"
                    systemctl daemon-reload 2>/dev/null || true
                elif [[ -f "$HOME/.config/systemd/user/$SERVICE_NAME.service" ]]; then
                    systemctl --user stop "$SERVICE_NAME" 2>/dev/null || true
                    systemctl --user disable "$SERVICE_NAME" 2>/dev/null || true
                    rm -f "$HOME/.config/systemd/user/$SERVICE_NAME.service"
                    systemctl --user daemon-reload 2>/dev/null || true
                fi
            fi
            ;;
        openrc)
            if [[ -f "/etc/init.d/$SERVICE_NAME" ]]; then
                /etc/init.d/$SERVICE_NAME stop 2>/dev/null || true
                rc-update del "$SERVICE_NAME" 2>/dev/null || true
            fi
            ;;
        screen)
            screen -S miaospeed -X quit 2>/dev/null || true
            ;;
        docker)
            if command -v docker &>/dev/null; then
                docker rm -f "$SERVICE_NAME" 2>/dev/null || true
            fi
            ;;
    esac

    if is_systemd_usable && [[ $EUID -eq 0 ]]; then
        rm -f "/etc/systemd/system/$SERVICE_NAME.service"
        systemctl daemon-reload 2>/dev/null || true
    elif is_systemd_usable; then
        rm -f "$HOME/.config/systemd/user/$SERVICE_NAME.service"
        systemctl --user daemon-reload 2>/dev/null || true
    fi

    rm -f "/etc/init.d/$SERVICE_NAME" 2>/dev/null || true
    screen -S miaospeed -X quit 2>/dev/null || true

    rm -f "$HOME/.local/bin/$BINARY_NAME"
    rm -rf "$INSTALL_DIR"
    rm -f "$CONFIG_FILE" 2>/dev/null || true
    rm -f "$PARAMS_FILE" 2>/dev/null || true

    (crontab -l 2>/dev/null | grep -v "miaospeed") | crontab - 2>/dev/null || true

    log_info "$(_ UNINSTALL_SUCCESS)"
}

#######################################
# Interactive Menu
#######################################
show_menu() {
    echo ""
    echo "=================================="
    echo "   MiaoSpeed Manager"
    echo "=================================="
    echo ""
    echo "$(_ INFO) Detected system:"
    echo "  $(_ OS_INFO) $OS_PRETTY"
    echo "  $(_ ARCH_INFO) $ARCH"
    echo "  $(_ INIT_INFO) $INIT_SYSTEM"

    local lang_display="English"
    [[ "$LANG" == "zh" ]] && lang_display="中文"
    echo "  Language: $lang_display"
    echo ""

    local is_installed=false
    if [[ -f "$INSTALL_DIR/miaospeed" ]] || docker ps -a --format '{{.Names}}' | grep -q "^${SERVICE_NAME}$"; then
        is_installed=true
        echo -e "  ${GREEN}MiaoSpeed: installed${NC}"
    else
        echo -e "  ${RED}MiaoSpeed: not installed${NC}"
    fi
    echo ""

    local docker_available=false
    if check_docker; then
        local docker_version
        docker_version=$(docker --version 2>/dev/null)
        echo -e "  ${GREEN}$(_ DOCKER_INSTALLED)${NC} ($docker_version)"
        docker_available=true
    else
        echo -e "  ${RED}$(_ DOCKER_NOT_INSTALLED)${NC}"
    fi
    echo ""

    log_menu "$(_ SELECT_MODE)"
    echo "  1) $(_ MODE_LOCAL)"
    if [[ "$docker_available" == true ]]; then
        echo "  2) $(_ MODE_DOCKER)"
    else
        echo -e "  2) $(_ MODE_DOCKER) ${RED}($(_ DOCKER_NOT_INSTALLED))${NC}"
    fi
    echo "  3) $(_ MODE_SOURCE)"

    if [[ "$is_installed" == true ]]; then
        echo "  4) $(_ MODE_STATUS)"
        echo "  5) $(_ MODE_STOP)"
        echo "  6) $(_ MODE_START)"
        echo "  7) $(_ MODE_RESTART)"
        echo "  8) $(_ MODE_CONFIG)"
        echo "  9) $(_ MODE_LOGS)"
        echo " 10) $(_ MODE_ADVANCED)"
        echo " 11) $(_ MODE_IMPORT)"
        echo " 12) $(_ MODE_EXPORT)"
        echo " 13) $(_ MODE_UNINSTALL)"
    else
        echo "  4) $(_ MODE_IMPORT)"
        echo "  5) $(_ MODE_UNINSTALL)"
    fi
    echo "  0) $(_ MODE_LANGUAGE)"
    echo "  q) $(_ MODE_EXIT)"
    echo ""
}

interactive_mode() {
    while true; do
        show_menu
        local is_installed=false
        [[ -f "$INSTALL_DIR/miaospeed" ]] || docker ps -a --format '{{.Names}}' | grep -q "^${SERVICE_NAME}$" && is_installed=true

        if [[ "$is_installed" == true ]]; then
            read -p "$(_ ENTER_CHOICE) [0-13,q]: " choice
        else
            read -p "$(_ ENTER_CHOICE) [0-5,q]: " choice
        fi

        case $choice in
            1)
                DEPLOY_MODE="local"
                log_info "$(_ NOT_ROOT)"
                deploy_local
                read -p "$(_ PRESS_ENTER)"
                ;;
            2)
                if check_docker; then
                    DEPLOY_MODE="docker"
                    deploy_docker
                else
                    log_error "$(_ DOCKER_UNAVAILABLE)"
                    echo ""
                    echo "$(_ DOCKER_HELP)"
                fi
                read -p "$(_ PRESS_ENTER)"
                ;;
            3)
                COMPILE_FROM_SOURCE=true
                detect_os
                detect_init
                compile_from_source
                log_info "$(_ DOWNLOADED) $INSTALL_DIR/miaospeed"
                read -p "$(_ PRESS_ENTER)"
                ;;
            4)
                if [[ "$is_installed" == true ]]; then
                    show_status
                    read -p "$(_ PRESS_ENTER)"
                else
                    import_config
                    read -p "$(_ PRESS_ENTER)"
                fi
                ;;
            5)
                if [[ "$is_installed" == true ]]; then
                    stop_service
                    read -p "$(_ PRESS_ENTER)"
                else
                    UNINSTALL=true
                    detect_os
                    detect_init
                    uninstall_miaospeed
                    exit 0
                fi
                ;;
            6)
                if [[ "$is_installed" == true ]]; then
                    start_service_cmd
                    read -p "$(_ PRESS_ENTER)"
                else
                    log_error "$(_ INVALID_CHOICE)"
                    read -p "$(_ PRESS_ENTER)"
                fi
                ;;
            7)
                if [[ "$is_installed" == true ]]; then
                    restart_service
                    read -p "$(_ PRESS_ENTER)"
                else
                    log_error "$(_ INVALID_CHOICE)"
                    read -p "$(_ PRESS_ENTER)"
                fi
                ;;
            8)
                if [[ "$is_installed" == true ]]; then
                    config_edit_menu
                else
                    log_error "$(_ INVALID_CHOICE)"
                    read -p "$(_ PRESS_ENTER)"
                fi
                ;;
            9)
                if [[ "$is_installed" == true ]]; then
                    view_logs
                else
                    log_error "$(_ INVALID_CHOICE)"
                    read -p "$(_ PRESS_ENTER)"
                fi
                ;;
            10)
                if [[ "$is_installed" == true ]]; then
                    config_wizard
                    save_all_params
                    recreate_service_files
                    if confirm_yes_no "$(_ CONFIG_EDIT_RESTART)"; then
                        restart_service
                    fi
                else
                    log_error "$(_ INVALID_CHOICE)"
                    read -p "$(_ PRESS_ENTER)"
                fi
                ;;
            11)
                if [[ "$is_installed" == true ]]; then
                    import_config
                    save_all_params
                    if [[ -f "$PARAMS_FILE" ]]; then
                        recreate_service_files
                        if confirm_yes_no "$(_ CONFIG_EDIT_RESTART)"; then
                            restart_service
                        fi
                    fi
                else
                    log_error "$(_ INVALID_CHOICE)"
                fi
                read -p "$(_ PRESS_ENTER)"
                ;;
            12)
                if [[ "$is_installed" == true ]]; then
                    export_config
                else
                    log_error "$(_ INVALID_CHOICE)"
                fi
                read -p "$(_ PRESS_ENTER)"
                ;;
            13)
                if [[ "$is_installed" == true ]]; then
                    UNINSTALL=true
                    uninstall_miaospeed
                    exit 0
                else
                    log_error "$(_ INVALID_CHOICE)"
                    read -p "$(_ PRESS_ENTER)"
                fi
                ;;
            0)
                switch_language
                ;;
            q|Q)
                log_info "$(_ EXITING)"
                exit 0
                ;;
            *)
                log_error "$(_ INVALID_CHOICE)"
                read -p "$(_ PRESS_ENTER)"
                ;;
        esac
    done
}

#######################################
# Main
#######################################
main() {
    parse_args "$@"

    case "$COMMAND" in
        stop|start|restart|status|config|logs|uninstall)
            # Use saved language
            ;;
        *)
            if [[ "$LANG_FROM_CONFIG" == false ]]; then
                select_language
            fi
            ;;
    esac

    case "$COMMAND" in
        stop)
            stop_service
            exit 0
            ;;
        start)
            start_service_cmd
            exit 0
            ;;
        restart)
            restart_service
            exit 0
            ;;
        status)
            detect_os
            detect_init
            show_status
            exit 0
            ;;
        config)
            detect_os
            detect_init
            load_all_params
            config_edit_menu
            exit 0
            ;;
        logs)
            detect_os
            detect_init
            view_logs
            exit 0
            ;;
        uninstall)
            detect_os
            detect_init
            uninstall_miaospeed
            exit 0
            ;;
    esac

    detect_os
    detect_init

    if [[ -n "$DEPLOY_MODE" ]]; then
        if [[ -z "$CFG_TOKEN" ]] || [[ -z "$CFG_PATH" ]] || [[ "$CFG_PATH" == "/" ]]; then
            config_wizard
        fi

        if [[ "$DEPLOY_MODE" == "docker" ]]; then
            if check_docker; then
                deploy_docker
            else
                log_error "$(_ DOCKER_UNAVAILABLE)"
                echo ""
                echo "$(_ DOCKER_HELP)"
                exit 1
            fi
        else
            if [[ -z "$PERSISTENCE_METHOD" ]]; then
                select_persistence_method
            fi
            deploy_local
        fi
    else
        interactive_mode
    fi
}

main "$@"

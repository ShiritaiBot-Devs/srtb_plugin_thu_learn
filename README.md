# thu_learn · 网络学堂 OneLearn 插件

ShiritaiBot 的清华网络学堂插件：通过 stdio JSON 与学校适配端（`bridge.py`）通信，为主对话提供课程、作业、公告、课件等只读查询工具，以及登录、作业附件下载等能力。

## 功能

- `courses` / `notices` / `homework` / `files`：课程、公告、作业、课件查询
- `homework_detail` / `homework_attachments`：作业说明、评语与附件列表
- `download` / `download_homework_attachment`：附件下载到插件数据目录
- 登录基于持久化会话复用，需要短信验证时向用户索取验证码；凭据保存在插件配置中（加密），不出现在代码与仓库里

## 安装

将本仓库内容放到主框架的插件目录：

```
src/shiritaibot/plugin/thu_learn/
├── main.py
├── client.py
├── bridge.py
└── plugin.toml
```

框架重启后生效。插件配置里可填写学号、密码，并可选开启作业轮询（`poll`，间隔 `poll_seconds`，首次同步仅建立基线）。

## 许可

AGPL-3.0，与主框架一致。

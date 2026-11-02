"""THU adapter plugin: school-specific implementation stays outside plugin core."""

import sys
from pathlib import Path

from shiritaibot.plugin_api import OneLearnPlugin, PublicError, schema


class Entry(OneLearnPlugin):
    async def start(self):
        if not self.context.settings.get("command"):
            self.context.settings["command"] = [
                sys.executable,
                str(Path(__file__).parent / "bridge.py"),
            ]
        await super().start()
        self.context.register_tool(
            "thu_learn_login",
            "登录清华网络学堂或复用已有会话，账号密码从插件配置读取。"
            "需要短信验证时，向用户索取验证码后调用 thu_learn_verify_sms，不要反复登录。"
            "仅在用户明确要求重发短信时设置 resend_sms=true。仅限主人私聊。",
            schema({"resend_sms": {"type": "boolean", "default": False}}),
            self.login,
            risk="sensitive",
            timeout=240,
        )
        self.context.register_tool(
            "thu_learn_verify_sms",
            "提交当前用户提供的 6 位短信验证码，完成网络学堂登录。"
            "不得猜测、复述验证码或自动重试错误验证码；成功后继续原查询。仅限主人私聊。",
            schema({"code": {"type": "string", "pattern": r"^[0-9]{6}$"}}, ["code"]),
            self.verify_sms,
            risk="sensitive",
            timeout=240,
        )

    @staticmethod
    def require_private_owner(ctx):
        if not ctx.owner or ctx.mode != "agent" or ctx.group or ctx.background:
            raise PublicError("网络学堂登录仅限主人私聊或 WebUI 对话，后台任务不能发起验证")

    async def login(self, ctx, args):
        self.require_private_owner(ctx)
        return await self.invoke("login", {"resend": args.get("resend_sms", False)})

    async def verify_sms(self, ctx, args):
        self.require_private_owner(ctx)
        return await self.invoke("verify_sms", {"code": args["code"]})

"""Read-only Web Learning client based on thu-learn-lib and the official SSO UI."""

import base64
import hashlib
import html
import json
import re
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, quote, urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from gmssl.sm2 import CryptSM2

LEARN = "https://learn.tsinghua.edu.cn"
ID = "https://id.tsinghua.edu.cn"
LOGIN = ID + "/do/off/ui/auth/login/form/bb5df85216504820be7bba2b0ae1535b/0"
HOME = LEARN + "/f/wlxt/index/course/student/"
DOUBLE = ID + "/b/doubleAuth/login"


class LearnError(Exception):
    """Expose only a sanitized status and message to the tool caller."""

    def __init__(self, status: str, message: str):
        super().__init__(message)
        self.status = status


class LearnClient:
    """Synchronous client; the plugin serializes all access in a worker thread."""

    def __init__(self, config: dict, data_dir: Path, temp_dir: Path):
        self.config = config
        self.data_dir = data_dir
        self.temp_dir = temp_dir
        self.state_path = data_dir / "session.json"
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0", "Referer": HOME})
        self.session.max_redirects = 8
        self.account = hashlib.sha256(config.get("username", "").encode()).hexdigest()
        self.state = {
            "account": self.account,
            "fingerprint": config.get("fingerprint") or uuid.uuid4().hex,
            "finger_gen_print3": "",
            "pending": None,
            "login_after": 0,
            "network_after": 0,
        }
        self.csrf = ""
        self.cache = {}
        self.homework_index = {}
        self.last_request = 0.0
        if self.state_path.exists():
            try:
                saved = json.loads(self.state_path.read_text(encoding="utf-8"))
                if saved.get("account") == self.account and (
                    not config.get("fingerprint")
                    or config["fingerprint"] == saved.get("fingerprint")
                ):
                    cookies = saved.pop("cookies", [])
                    self.state.update(saved)
                    for cookie in cookies:
                        self.session.cookies.set_cookie(requests.cookies.create_cookie(**cookie))
            except (ValueError, TypeError, KeyError, OSError):
                self.session.cookies.clear()

    def save(self):
        """Atomically persist cookies and device state without passwords.

        Raises:
            OSError: If the private data directory cannot be written.
        """
        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.data_dir.chmod(0o700)
        state = dict(self.state)
        state["cookies"] = [
            {
                "name": c.name,
                "value": c.value,
                "domain": c.domain,
                "path": c.path,
                "secure": c.secure,
                "expires": c.expires,
                "rest": c._rest,
            }
            for c in self.session.cookies
        ]
        target = self.state_path.with_suffix(".tmp")
        with target.open("w", encoding="utf-8") as stream:
            target.chmod(0o600)
            json.dump(state, stream, ensure_ascii=False)
        target.replace(self.state_path)
        self.state_path.chmod(0o600)

    def request(self, method: str, url: str, **kwargs):
        """Perform a bounded, rate-limited request to an official host.

        Args:
            method: HTTP method.
            url: Official SSO or learning URL.
            **kwargs: Requests arguments, excluding timeout and redirects.

        Returns:
            An open response; streaming callers must close it.

        Raises:
            LearnError: On network failure, cooldown, or an unexpected redirect.
        """
        if time.time() < self.state.get("network_after", 0):
            raise LearnError("cooldown", "站点请求冷却中，请稍后再试。")
        for _ in range(9):
            parsed = urlparse(url)
            if parsed.scheme != "https" or parsed.hostname not in {
                "learn.tsinghua.edu.cn",
                "id.tsinghua.edu.cn",
            }:
                raise LearnError("unexpected_redirect", "站点重定向到未支持的地址，已停止。")
            interval = max(1.0, float(self.config.get("request_interval", 2)))
            time.sleep(max(0, self.last_request + interval - time.monotonic()))
            self.last_request = time.monotonic()
            try:
                response = self.session.request(
                    method, url, timeout=(10, 30), allow_redirects=False, **kwargs
                )
            except requests.RequestException:
                self.state["network_after"] = time.time() + 60
                self.save()
                raise LearnError(
                    "network_error", "无法连接学校站点，请检查校园网/VPN；未自动重试。"
                ) from None
            if response.status_code == 429 or response.status_code >= 500:
                response.close()
                self.state["network_after"] = time.time() + 300
                self.save()
                raise LearnError("cooldown", "学校站点限流或暂时不可用，暂停请求 5 分钟。")
            if response.status_code in (301, 302, 303, 307, 308):
                url = urljoin(url, response.headers.get("Location", ""))
                response.close()
                kwargs.pop("params", None)
                if response.status_code in (301, 302, 303):
                    method = "GET"
                    kwargs.pop("data", None)
                continue
            response.encoding = "utf-8"
            return response
        raise LearnError("unexpected_redirect", "站点重定向次数过多，已停止。")

    def authenticate(self, owner: str, resend: bool = False):
        """Reuse cookies or log in once, yielding immediately when SMS is needed.

        Args:
            owner: Calling session and sender, binding the SMS challenge.
            resend: Explicitly request another SMS after the cooldown.

        Returns:
            A login status dictionary on success.

        Raises:
            LearnError: When credentials, SMS, CAPTCHA, or manual intervention is needed.
        """
        pending = self.state.get("pending")
        if pending and resend and time.time() > pending["expires"] + 300:
            if pending["owner"] != owner:
                raise LearnError("verification_pending_elsewhere", "请由原发起者重新登录。")
            self.state["pending"] = None
            self.save()
            pending = None
        if pending:
            if pending["owner"] != owner:
                raise LearnError(
                    "verification_pending_elsewhere",
                    "已有其他用户发起登录验证，请由原发起者完成。",
                )
            if not resend:
                status = (
                    "verification_required"
                    if time.time() < pending["expires"]
                    else "verification_expired"
                )
                raise LearnError(
                    status,
                    "需要短信验证码。请向用户索取验证码并调用 thu_learn_verify_sms；过期后由用户明确要求 thu_learn_login(resend_sms=true)。",
                )
            if time.time() < pending["sent_at"] + 60:
                raise LearnError("cooldown", "短信发送间隔至少 60 秒，请勿重复请求。")
            with self.request("POST", DOUBLE, data={"action": "SEND_CODE", "type": "mobile"}) as r:
                result = r.json()
            if result.get("result") != "success" or result.get("object", {}).get("flow") != "SENT":
                raise LearnError("verification_failed", "短信重发未成功，请稍后重新登录。")
            pending.update(sent_at=time.time(), expires=time.time() + 180, attempts=0)
            self.save()
            raise LearnError("verification_required", "已重发短信验证码，请用户提供 6 位验证码。")
        with self.request("GET", HOME) as response:
            match = re.search(r"[?&]_csrf=([^\s\"'&<>]+)", response.text)
            if match and urlparse(response.url).hostname == "learn.tsinghua.edu.cn":
                self.csrf = html.unescape(match[1])
                self.save()
                return {"status": "authenticated", "session_reused": True}
        if time.time() < self.state.get("login_after", 0):
            raise LearnError("cooldown", "登录失败后的冷却期尚未结束，请稍后再试。")
        if not self.config.get("username") or not self.config.get("password"):
            raise LearnError("not_configured", "请在插件配置中填写 SSO 用户名和密码。")
        self.state["login_after"] = time.time() + 300
        self.save()
        with self.request("GET", LOGIN) as response:
            page = response.text
        form = {
            "fingerPrint": self.state["fingerprint"],
            "fingerGenPrint": self.config.get("finger_gen_print", ""),
            "fingerGenPrint3": self.config.get("finger_gen_print3")
            or self.state.get("finger_gen_print3", ""),
        }
        if "checkSingle" in page:
            form["i_rememberme"] = "on"
            endpoint = "/do/off/ui/auth/login/checkSingle"
        else:
            soup = BeautifulSoup(page, "html.parser")
            captcha = soup.select_one("#c_code")
            if captcha and "hidden" not in captcha.get("class", []):
                raise LearnError(
                    "captcha_required",
                    "SSO 要求图形验证码，请在官方网页完成验证后再试。",
                )
            key_node = soup.select_one("#sm2publicKey")
            if not key_node:
                raise LearnError("login_changed", "无法识别 SSO 登录页面，已停止登录。")
            key = key_node.get_text(strip=True)
            cipher = CryptSM2(private_key="", public_key="", mode=1)
            # Avoid gmssl's lstrip('04'), which can corrupt valid key coordinates.
            cipher.public_key = key[2:] if key.startswith("04") else key
            form.update(
                i_user=self.config["username"],
                i_pass="04" + cipher.encrypt(self.config["password"].encode()).hex(),
                singleLogin="on",
                deviceName="AstrBot",
                i_captcha="",
            )
            endpoint = "/do/off/ui/auth/login/check"
        with self.request("POST", ID + endpoint, data=form) as response:
            page = response.text
        if "二次认证" in page:
            with self.request("POST", DOUBLE, data={"action": "FIND_APPROACHES"}) as response:
                result = response.json()
            if result.get("result") != "success" or not result.get("object", {}).get("phone"):
                raise LearnError(
                    "manual_verification_required",
                    "SSO 当前未提供短信验证，请在官方网页处理。",
                )
            with self.request(
                "POST", DOUBLE, data={"action": "SEND_CODE", "type": "mobile"}
            ) as response:
                result = response.json()
            if result.get("result") != "success" or result.get("object", {}).get("flow") != "SENT":
                raise LearnError("verification_failed", "短信发送失败；未自动重试。")
            self.state["pending"] = {
                "owner": owner,
                "sent_at": time.time(),
                "expires": time.time() + 180,
                "attempts": 0,
            }
            self.save()
            raise LearnError(
                "verification_required",
                "已发送短信验证码，请向当前用户索取 6 位验证码，再调用 thu_learn_verify_sms；不要反复调用登录。",
            )
        self.finish_login(page)
        return {"status": "authenticated", "session_reused": False}

    def finish_login(self, page: str):
        """Follow the SSO ticket and verify the learning session.

        Args:
            page: HTML containing the official ticket link.

        Raises:
            LearnError: If the ticket or authenticated CSRF token is absent.
        """
        soup = BeautifulSoup(page, "html.parser")
        link = next(
            (
                a["href"]
                for a in soup.select("a[href]")
                if "ticket=" in a["href"]
                and urlparse(a["href"]).hostname == "learn.tsinghua.edu.cn"
            ),
            None,
        )
        if not link:
            # The post-SMS redirect can have an empty href. Obtain one SSO ticket
            # through the existing authenticated identity session, without a password.
            with self.request("GET", LOGIN) as response:
                single = "checkSingle" in response.text
            if single:
                with self.request(
                    "POST",
                    ID + "/do/off/ui/auth/login/checkSingle",
                    data={
                        "i_rememberme": "on",
                        "fingerPrint": self.state["fingerprint"],
                        "fingerGenPrint": self.config.get("finger_gen_print", ""),
                        "fingerGenPrint3": self.state.get("finger_gen_print3", ""),
                    },
                ) as response:
                    soup = BeautifulSoup(response.text, "html.parser")
                link = next(
                    (
                        a["href"]
                        for a in soup.select("a[href]")
                        if "ticket=" in a["href"]
                        and urlparse(a["href"]).hostname == "learn.tsinghua.edu.cn"
                    ),
                    None,
                )
        if not link:
            raise LearnError(
                "login_failed",
                "SSO 未返回网络学堂票据，请检查凭据或在官方网页处理验证；已暂停自动登录 5 分钟。",
            )
        with self.request("GET", link):
            pass
        with self.request("GET", HOME) as response:
            match = re.search(r"[?&]_csrf=([^\s\"'&<>]+)", response.text)
        if not match:
            raise LearnError("login_failed", "SSO 跳转后仍未建立网络学堂会话。")
        self.csrf = html.unescape(match[1])
        self.state.update(pending=None, login_after=0)
        self.cache.clear()
        self.save()

    def verify_sms(self, owner: str, code: str):
        """Submit one SMS code and optionally trust the device for 180 days.

        Args:
            owner: Session and sender that initiated login.
            code: Six-digit code, never persisted or returned.

        Returns:
            Authentication and trust-device status.

        Raises:
            LearnError: On an absent, expired, or rejected challenge.
        """
        pending = self.state.get("pending")
        if not pending or pending.get("owner") != owner:
            raise LearnError("no_pending_verification", "当前用户在此会话没有待完成的短信验证。")
        if time.time() > pending["expires"] or pending["attempts"] >= 3:
            raise LearnError(
                "verification_expired",
                "验证码已过期或已尝试 3 次；请用户明确要求重发短信。",
            )
        if not re.fullmatch(r"[0-9]{6}", code):
            raise LearnError("invalid_argument", "验证码必须为 6 位数字。")
        pending["attempts"] += 1
        self.save()
        with self.request(
            "POST", DOUBLE, data={"action": "VERITY_CODE", "vericode": code}
        ) as response:
            result = response.json()
        obj = result.get("object") or {}
        if result.get("result") != "success" or obj.get("flow") != "VERIFIED":
            raise LearnError(
                "verification_failed", "验证码未通过，请确认最新验证码；不会自动重试。"
            )
        trusted = False
        if self.config.get("trust_device", True):
            with self.request(
                "POST",
                ID + "/b/doubleAuth/personal/saveFinger",
                data={
                    "fingerprint": self.state["fingerprint"],
                    "deviceName": "AstrBot",
                    "radioVal": "是",
                    "singleLogin": "yes",
                },
            ) as response:
                trust = response.json()
            trusted = trust.get("result") == "success"
            if trusted and isinstance(trust.get("object"), str):
                self.state["finger_gen_print3"] = trust["object"]
        self.state["pending"] = None
        self.save()
        redirect = urljoin(ID, obj.get("redirectUrl", ""))
        with self.request("POST" if obj.get("type") == "self" else "GET", redirect) as response:
            page = response.text
        self.finish_login(page)
        return {
            "status": "authenticated",
            "trusted_device": trusted,
            "trust_days": 180 if trusted else 0,
        }

    def api(
        self,
        owner: str,
        path: str,
        data: dict | None = None,
        params: dict | None = None,
        page: bool = False,
    ):
        """Read an API response with a TTL cache and at most one re-login.

        Args:
            owner: Calling session and sender.
            path: Verified learning API path.
            data: Optional POST form.
            params: Optional query parameters.
            page: Return a validated homework HTML page instead of JSON.

        Returns:
            Parsed JSON with a validated success marker.

        Raises:
            LearnError: On login, API, or schema failures.
        """
        key = json.dumps([path, data, params, page], sort_keys=True)
        cached = self.cache.get(key)
        if cached and cached[0] > time.monotonic():
            return cached[1]
        if not self.csrf:
            self.authenticate(owner)
        for attempt in range(2):
            with self.request(
                "POST" if data is not None else "GET",
                LEARN + path,
                data=data,
                params={**(params or {}), "_csrf": self.csrf},
            ) as response:
                expired = response.status_code in (401, 403) or any(
                    x in response.url for x in ("login_timeout", "/f/login", "id.tsinghua.edu.cn")
                )
                if not expired:
                    if response.status_code != 200:
                        raise LearnError("api_error", "网络学堂接口返回异常状态。")
                    if page:
                        result = response.text
                        if not BeautifulSoup(result, "html.parser").select(
                            "div.list.fujian.clearfix"
                        ):
                            raise LearnError(
                                "invalid_response",
                                "作业详情页结构无法识别，未当作无附件。",
                            )
                    else:
                        try:
                            result = response.json()
                        except ValueError:
                            raise LearnError(
                                "invalid_response",
                                "网络学堂返回非 JSON 页面，未当作空列表。",
                            ) from None
                        if not isinstance(result, dict) or not (
                            result.get("result") == "success" or result.get("message") == "success"
                        ):
                            raise LearnError("api_error", "网络学堂接口未返回成功标记。")
                    ttl = max(0, int(self.config.get("cache_ttl", 120)))
                    if len(self.cache) >= 256:
                        self.cache.clear()
                    self.cache[key] = (time.monotonic() + ttl, result)
                    self.save()
                    return result
            self.csrf = ""
            self.cache.clear()
            if attempt == 0:
                self.authenticate(owner)
        raise LearnError("session_expired", "重连后会话仍不可用，已停止重试。")

    def page_list(self, owner: str, path: str, course_id: str):
        """Read all DataTables pages rather than silently truncate results.

        Args:
            owner: Calling session and sender.
            path: Verified page-list API path.
            course_id: Course identifier.

        Returns:
            All rows returned by the server.

        Raises:
            LearnError: On an inconsistent or unbounded response.
        """
        rows = []
        for start in range(0, 10000, 200):
            fields = [
                {"name": "wlkcid", "value": course_id},
                {"name": "iDisplayStart", "value": start},
                {"name": "iDisplayLength", "value": 200},
            ]
            result = self.api(owner, path, data={"aoData": json.dumps(fields)})
            obj = result.get("object")
            if not isinstance(obj, dict) or not isinstance(obj.get("aaData"), list):
                raise LearnError("invalid_response", "列表响应结构已变化。")
            batch = obj["aaData"]
            rows.extend(batch)
            total = int(obj.get("iTotalDisplayRecords", obj.get("iTotalRecords", len(rows))))
            if len(rows) >= total:
                return rows
            if not batch or int(obj.get("iDisplayStart", start)) != start:
                raise LearnError("pagination_failed", "服务器未按要求分页，无法保证结果完整。")
        raise LearnError("too_many_results", "数据量超出查询上限，请缩小范围。")

    def courses(self, owner: str):
        """Read the current semester and its student courses.

        Args:
            owner: Calling session and sender.

        Returns:
            Current semester and course summaries.
        """
        term = self.api(owner, "/b/kc/zhjw_v_code_xnxq/getCurrentAndNextSemester")["result"]
        result = self.api(
            owner,
            "/b/wlxt/kc/v_wlkc_xs_xkb_kcb_extend/student/loadCourseBySemesterId/"
            + quote(term["id"], safe="")
            + "/zh",
        )
        return {
            "semester": term["id"],
            "semester_name": term.get("xnxqmc", ""),
            "courses": [
                {
                    "course_id": c["wlkcid"],
                    "name": html.unescape(c.get("kcm") or c.get("zywkcm") or ""),
                    "teacher": c.get("jsm", ""),
                    "semester": term["id"],
                }
                for c in result["resultList"]
            ],
        }

    def notices(self, owner: str, course_id: str):
        """Read current and expired notices including decoded body text.

        Args:
            owner: Calling session and sender.
            course_id: Course identifier.

        Returns:
            Notice summaries and bodies.
        """
        rows = []
        for kind in ("Wgq", "Ygq"):
            rows.extend(
                self.page_list(
                    owner,
                    "/b/wlxt/kcgg/wlkc_ggb/student/pageListXsby" + kind,
                    course_id,
                )
            )
        return [
            {
                "notice_id": n["ggid"],
                "title": html.unescape(n.get("bt", "")),
                "time": n.get("fbsjStr") or n.get("fbsj"),
                "body": BeautifulSoup(
                    html.unescape(base64.b64decode(n.get("ggnr") or "").decode("utf-8")),
                    "html.parser",
                ).get_text("\n", strip=True),
            }
            for n in rows
        ]

    def homework(self, owner: str, course_id: str = ""):
        """Read only unsubmitted homework, retaining overdue assignments.

        Args:
            owner: Calling session and sender.
            course_id: Optional course, otherwise all current semester courses.

        Returns:
            Homework with deadlines and explicit submission status.
        """
        courses = self.courses(owner)["courses"]
        if course_id:
            courses = [c for c in courses if c["course_id"] == course_id]
            if not courses:
                raise LearnError("course_not_found", "当前学期没有此课程。")
        result = []
        for course in courses:
            rows = self.page_list(owner, "/b/wlxt/kczy/zy/student/zyListWj", course["course_id"])
            result.extend(
                {
                    "course_id": course["course_id"],
                    "course": course["name"],
                    "homework_id": h["zyid"],
                    "student_homework_id": h["xszyid"],
                    "title": html.unescape(h.get("bt", "")),
                    "deadline": h.get("jzsj"),
                    "late_deadline": h.get("bjjzsj"),
                    "submitted": False,
                    "status": "未提交",
                }
                for h in rows
            )
        for item in result:
            self.homework_index[item["homework_id"]] = (
                item["course_id"],
                item["student_homework_id"],
            )
            for field in ("deadline", "late_deadline"):
                value = item[field]
                if isinstance(value, (int, float)):
                    item[field] = datetime.fromtimestamp(
                        value / 1000, timezone(timedelta(hours=8))
                    ).isoformat()
        return sorted(result, key=lambda h: str(h["deadline"] or ""))

    def files(self, owner: str, course_id: str):
        """List course files and categories using the uncapped category endpoint.

        Args:
            owner: Calling session and sender.
            course_id: Course identifier.

        Returns:
            File summaries including category and server file identifiers.

        Raises:
            LearnError: If the server omits categories or truncates the fallback list.
        """
        categories = self.api(
            owner,
            "/b/wlxt/kj/wlkc_kjflb/student/pageList",
            params={"wlkcid": course_id, "rows": 10000},
        )["object"]
        cats = categories["rows"]
        if int(categories.get("records", len(cats))) > len(cats):
            raise LearnError("too_many_results", "课件分类未返回完整结果。")
        files = {}
        for c in cats:
            result = self.api(
                owner,
                "/b/wlxt/kj/wlkc_kjxxb/student/kjxxb/"
                + quote(course_id, safe="")
                + "/"
                + quote(c["kjflid"], safe=""),
            )["object"]
            for f in result:
                files[f[7]] = {
                    "file_id": f[7],
                    "title": html.unescape(f[1]),
                    "description": html.unescape(f[5] or ""),
                    "size_bytes": f[9],
                    "type": f[13],
                    "uploaded_at": f[6],
                    "category_id": c["kjflid"],
                    "category": html.unescape(c["bt"]),
                }
        recent = self.api(
            owner,
            "/b/wlxt/kj/wlkc_kjxxb/student/kjxxbByWlkcidAndSizeForStudent",
            params={"wlkcid": course_id, "size": 200},
        )["object"]
        if len(recent) >= 200 and not cats:
            raise LearnError("possibly_truncated", "课件达到 200 条且无分类，无法保证列表完整。")
        for f in recent:
            files.setdefault(
                f["wjid"],
                {
                    "file_id": f["wjid"],
                    "title": html.unescape(f["bt"]),
                    "description": html.unescape(f.get("ms") or ""),
                    "size_bytes": f.get("wjdx"),
                    "type": f.get("wjlx"),
                    "uploaded_at": f.get("scsj"),
                    "category_id": f.get("kjflid"),
                    "category": "未分类",
                },
            )
        return list(files.values())

    def download(self, owner: str, course_id: str, file_id: str):
        """Download a listed file to a private temporary directory.

        Args:
            owner: Calling session and sender.
            course_id: Course containing the file.
            file_id: Server file ID, never an arbitrary URL or local path.

        Returns:
            Download path and display filename.

        Raises:
            LearnError: On missing files, size limits, or an expired session.
        """
        item = next((f for f in self.files(owner, course_id) if f["file_id"] == file_id), None)
        if not item:
            raise LearnError("file_not_found", "该文件不在此课程的课件列表中。")
        return self.download_resource(
            owner,
            item,
            "/b/wlxt/kj/wlkc_kjxxb/student/downloadFile",
            {"sfgk": 0, "wjid": file_id},
        )

    def _resolve_homework(self, owner: str, homework_id: str):
        """Map a base zyid to (course_id, xszyid), scanning the three status lists."""
        location = self.homework_index.get(homework_id)
        if location:
            return location
        courses = self.courses(owner)["courses"]
        # Resolve zyid -> xszyid using the real three status lists. Search
        # pending work first, then submitted and graded work across courses.
        for status in ("zyListWj", "zyListYjwg", "zyListYpg"):
            for course in courses:
                for row in self.page_list(
                    owner, "/b/wlxt/kczy/zy/student/" + status, course["course_id"]
                ):
                    self.homework_index[row["zyid"]] = (
                        course["course_id"],
                        row["xszyid"],
                    )
                location = self.homework_index.get(homework_id)
                if location:
                    return location
        raise LearnError(
            "homework_not_found",
            "当前学期没有找到此作业，请使用作业列表返回的 homework_id。",
        )

    def _parse_attachments(self, soup, course_id: str):
        """Parse the four attachment blocks of a viewCj page into download entries."""
        attachments = {}
        roles = ("homework", "answer", "submission", "grading")
        for index, block in enumerate(soup.select("div.list.fujian.clearfix")):
            for anchor in block.select("a[href]"):
                href = urlparse(urljoin(LEARN, anchor["href"]))
                if href.hostname != "learn.tsinghua.edu.cn" or href.scheme != "https":
                    raise LearnError("invalid_response", "作业附件链接指向非学堂站点。")
                query = parse_qs(href.query)
                nested = query.get("downloadUrl", [""])[0]
                if not nested:
                    if "/downloadFile/" not in href.path:
                        continue
                    nested = anchor["href"]
                download = urlparse(urljoin(LEARN, nested))
                prefix = "/b/wlxt/kczy/zy/student/downloadFile/" + course_id + "/"
                if (
                    download.scheme != "https"
                    or download.hostname != "learn.tsinghua.edu.cn"
                    or not download.path.startswith(prefix)
                ):
                    raise LearnError("invalid_response", "作业附件下载地址与课程不匹配。")
                attachment_id = download.path[len(prefix) :]
                if (
                    not attachment_id
                    or "/" in attachment_id
                    or query.get("fileId", [attachment_id])[0] != attachment_id
                ):
                    raise LearnError("invalid_response", "作业附件 ID 与下载地址不匹配。")
                if attachment_id in attachments:
                    continue
                title = anchor.get_text(" ", strip=True)
                size_node = block.select_one('.fl > span[class^="color"]')
                size_text = size_node.get_text(strip=True) if size_node else ""
                size = re.search(r"([0-9]+(?:\.[0-9]+)?)\s*([KMGT]?)(?:i?B)?", size_text, re.I)
                size_bytes = (
                    int(float(size[1]) * 1024 ** " KMGT".index(size[2].upper() or " "))
                    if size
                    else None
                )
                attachments[attachment_id] = {
                    "file_id": attachment_id,
                    "title": title,
                    "size": size_text or None,
                    "size_bytes": size_bytes,
                    "type": Path(title).suffix.lstrip(".").lower() or "unknown",
                    "role": roles[index] if index < len(roles) else "other",
                    "_download_path": download.path,
                }
        return list(attachments.values())

    def _labeled(self, soup, label: str):
        """Return the value text following a label node like 完成方式, or None."""
        node = soup.find(string=re.compile(rf"^\s*{re.escape(label)}\s*$"))
        if node is None:
            return None
        sibling = node.parent.find_next_sibling()
        return sibling.get_text(" ", strip=True) or None if sibling else None

    def homework_detail(self, owner: str, homework_id: str):
        """Full assignment detail: description, mode, review state and attachments.

        Args:
            owner: Calling session and sender.
            homework_id: Base zyid returned by the homework list.

        Returns:
            Description/mode/review fields plus the same attachment entries as
            homework_attachments; missing values stay None so callers can tell
            "empty on the page" apart from "unknown structure".
        """
        course_id, student_id = self._resolve_homework(owner, homework_id)
        # Same viewCj page as attachments; api() caches it, so one fetch is shared.
        page = self.api(
            owner,
            "/f/wlxt/kczy/zy/student/viewCj",
            params={"wlkcid": course_id, "xszyid": student_id},
            page=True,
        )
        soup = BeautifulSoup(page, "html.parser")
        zysm = soup.select_one("#zysm")
        review = {
            "teacher": self._labeled(soup, "批阅老师"),
            "time": self._labeled(soup, "批阅时间"),
            "grade": self._labeled(soup, "成绩"),
            "comment": self._labeled(soup, "评语"),
        }
        return {
            "course_id": course_id,
            "homework_id": homework_id,
            "student_homework_id": student_id,
            "description": zysm.get_text("\n", strip=True) or None if zysm else None,
            "publish_target": self._labeled(soup, "发布对象"),
            "completion_mode": self._labeled(soup, "完成方式"),
            "submit_time": self._labeled(soup, "提交日期"),
            "review": {k: v for k, v in review.items() if v},
            "attachments": self._parse_attachments(soup, course_id),
        }

    def homework_attachments(self, owner: str, homework_id: str):
        """Resolve a base homework ID and parse its actual attachment links.

        Args:
            owner: Calling session and sender.
            homework_id: Base zyid returned by the homework list.

        Returns:
            Attachment metadata and internal validated download paths.

        Raises:
            LearnError: If the homework is absent or page/link structure changes.
        """
        course_id, student_id = self._resolve_homework(owner, homework_id)
        # /b/wlxt/kczy/zy/student/detail only returns the assignment body.
        # As in thu-learn-lib.parseHomeworkAtUrl, fetch viewCj and read the
        # openNewWindow link's nested downloadUrl from div.list.fujian.clearfix.
        # Live-verified: /b/wlxt/kczy/zy/student/downloadFile/{wlkcid}/{fileId}.
        page = self.api(
            owner,
            "/f/wlxt/kczy/zy/student/viewCj",
            params={"wlkcid": course_id, "xszyid": student_id},
            page=True,
        )
        soup = BeautifulSoup(page, "html.parser")
        return self._parse_attachments(soup, course_id)

    def download_homework_attachment(self, owner: str, homework_id: str, attachment_id: str):
        """Download only an attachment enumerated for the specified homework.

        Args:
            owner: Calling session and sender.
            homework_id: Base homework ID.
            attachment_id: ID returned by homework_attachments.

        Returns:
            A local file path and display name.

        Raises:
            LearnError: If the attachment is absent or the download fails.
        """
        item = next(
            (
                a
                for a in self.homework_attachments(owner, homework_id)
                if a["file_id"] == attachment_id
            ),
            None,
        )
        if not item:
            raise LearnError(
                "attachment_not_found",
                "该附件不属于此作业或已被移除，请重新查询附件列表。",
            )
        return self.download_resource(owner, item, item["_download_path"], {})

    def download_resource(self, owner: str, item: dict, path: str, params: dict):
        """Stream a validated resource with size limits and one bounded retry.

        Args:
            owner: Calling session and sender.
            item: Listed file metadata, never caller-supplied.
            path: Validated official download path.
            params: Download parameters without the changing CSRF token.

        Returns:
            A local file path and display name.

        Raises:
            LearnError: On size limits, expired sessions, or transfer failure.
        """
        limit = max(1, int(self.config.get("max_download_mb", 50))) * 1024 * 1024
        if int(item.get("size_bytes") or 0) > limit:
            raise LearnError("file_too_large", "文件超过配置的下载大小上限。")
        name = (
            re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", item["title"]).strip(" .")[:150] or "course_file"
        )
        extension = re.sub(r"[^A-Za-z0-9]", "", item.get("type") or "")[:12]
        if extension and not name.lower().endswith("." + extension.lower()):
            name += "." + extension
        self.temp_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        folder = self.temp_dir / uuid.uuid4().hex
        folder.mkdir(mode=0o700)
        target = folder / name
        started = time.monotonic()
        try:
            for attempt in range(2):
                try:
                    with self.request(
                        "GET",
                        LEARN + path,
                        params={**params, "_csrf": self.csrf},
                        stream=True,
                    ) as response:
                        expired = response.status_code in (401, 403) or any(
                            marker in response.url
                            for marker in (
                                "login_timeout",
                                "/f/login",
                                "id.tsinghua.edu.cn",
                            )
                        )
                        if not expired:
                            if response.status_code != 200:
                                raise LearnError(
                                    "download_failed",
                                    "文件接口返回错误，未自动重复请求。",
                                )
                            if (
                                "text/html" in response.headers.get("Content-Type", "")
                                and "attachment"
                                not in response.headers.get("Content-Disposition", "").lower()
                            ):
                                raise LearnError(
                                    "download_failed",
                                    "文件接口返回 HTML 页面，未作为文件发送。",
                                )
                            declared_size = int(response.headers.get("Content-Length", 0))
                            if declared_size > limit:
                                raise LearnError("file_too_large", "文件超过下载大小上限。")
                            size = 0
                            with target.open("wb") as stream:
                                target.chmod(0o600)
                                for chunk in response.iter_content(65536):
                                    size += len(chunk)
                                    if size > limit or time.monotonic() - started > 180:
                                        raise LearnError(
                                            "download_limit",
                                            "下载超过大小或时间上限，已删除残留。",
                                        )
                                    stream.write(chunk)
                            if (
                                declared_size
                                and not response.headers.get("Content-Encoding")
                                and size != declared_size
                            ):
                                raise requests.exceptions.ChunkedEncodingError(
                                    "Incomplete transfer"
                                )
                            if size == 0:
                                raise LearnError("download_failed", "下载结果为空，未发送文件。")
                            self.save()
                            return target, name
                    self.csrf = ""
                    self.cache.clear()
                    if attempt == 0:
                        self.authenticate(owner)
                except requests.RequestException:
                    target.unlink(missing_ok=True)
                    if attempt == 0 and time.monotonic() - started < 180:
                        # Retry an interrupted read once, under the same limiter.
                        # Connection failures and 429/5xx are already cooldown errors.
                        continue
                    raise LearnError(
                        "download_failed",
                        "文件传输失败，重试一次后仍未成功；已删除残留。",
                    ) from None
            raise LearnError("session_expired", "重连后仍不能下载文件。")
        except BaseException:
            target.unlink(missing_ok=True)
            folder.rmdir()
            raise

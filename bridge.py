"""OneLearn v0 transport subset: one JSON request on stdin, one JSON response.

This separate compatibility process runs the existing synchronous THU client.
No school credentials or OTPs are logged or passed as command-line arguments.
"""

import json
import sys
from pathlib import Path

from client import LearnClient, LearnError


def main():
    request = json.load(sys.stdin)
    root = Path(request["data_dir"])
    client = LearnClient(request["config"], root, root / "downloads")
    operation, params, owner = request["operation"], request.get("params", {}), request["owner"]
    methods = {
        "login": (client.authenticate, [owner, bool(params.get("resend", False))]),
        "verify_sms": (client.verify_sms, [owner, params.get("code", "")]),
        "courses": (client.courses, [owner]),
        "notices": (client.notices, [owner, params.get("course_id", "")]),
        "homework": (client.homework, [owner, params.get("course_id", "")]),
        "files": (client.files, [owner, params.get("course_id", "")]),
        "homework_attachments": (
            client.homework_attachments,
            [owner, params.get("homework_id", "")],
        ),
        "homework_detail": (
            client.homework_detail,
            [owner, params.get("homework_id", "")],
        ),
        "download": (
            client.download,
            [owner, params.get("course_id", ""), params.get("file_id", "")],
        ),
        "download_homework_attachment": (
            client.download_homework_attachment,
            [
                owner,
                params.get("homework_id", ""),
                params.get("file_id") or params.get("attachment_id", ""),
            ],
        ),
    }
    try:
        method, args = methods[operation]
        data = method(*args)
        if operation.startswith("download"):
            data = {"path": str(data[0]), "name": data[1]}
        print(json.dumps({"ok": True, "data": data}, ensure_ascii=False, default=str))
    except LearnError as exc:
        print(
            json.dumps({"ok": False, "status": exc.status, "message": str(exc)}, ensure_ascii=False)
        )
    except Exception as exc:
        print(json.dumps({"ok": False, "status": "adapter_error", "message": type(exc).__name__}))
    finally:
        client.session.close()


if __name__ == "__main__":
    main()

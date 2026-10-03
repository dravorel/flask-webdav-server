import base64
import hashlib
import hmac
import mimetypes
import os
import shutil
import tempfile
from email.utils import formatdate
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit
from xml.sax.saxutils import escape

from dotenv import load_dotenv
from flask import Flask, request, Response, send_file

load_dotenv()

app = Flask(__name__)

# ==========================================================
# Configuration
# ==========================================================

USERNAME = os.environ["USERNAME"]
PASSWORD = os.environ["PASSWORD"]

ROOT_DIR = Path(__file__).parent / "storage"
ROOT_DIR.mkdir(parents=True, exist_ok=True)


# ==========================================================
# Authentication
# ==========================================================


def check_auth() -> bool:
    """
    Проверяет HTTP Basic Authentication.
    """

    auth = request.headers.get("Authorization", "")

    if not auth.startswith("Basic "):
        return False

    try:
        decoded = base64.b64decode(auth[6:], validate=True).decode("utf-8")
        username, password = decoded.split(":", 1)
        return hmac.compare_digest(username, USERNAME) and hmac.compare_digest(
            password, PASSWORD
        )

    except (ValueError, UnicodeDecodeError):
        return False


def unauthorized() -> Response:
    """
    Возвращает HTTP-ответ с кодом 401 Unauthorized.
    """

    return Response(
        "Authentication required",
        401,
        headers={"WWW-Authenticate": 'Basic realm="WebDAV"'},
    )


# ==========================================================
# Safe path handling
# ==========================================================


def get_path(url_path: str) -> Path | None:
    """
    Преобразует URL-путь в путь файловой системы с защитой от выхода за ROOT_DIR.
    """

    url_path = unquote(url_path).lstrip("/")

    if "\x00" in url_path:
        return None

    path = (ROOT_DIR / url_path).resolve()

    try:
        path.relative_to(ROOT_DIR.resolve())
    except ValueError:
        return None

    return path


def href(path: Path) -> str:
    """
    Преобразует путь файловой системы в URL WebDAV.
    """

    relative = path.relative_to(ROOT_DIR).as_posix()

    if not relative:
        return "/"

    encoded = "/".join(quote(part, safe="") for part in relative.split("/"))

    return "/" + encoded + ("/" if path.is_dir() else "")


# ==========================================================
# ETag
# ==========================================================


def get_etag(path: Path) -> str:
    """
    Вычисляет ETag файла или директории на основе её содержимого или метаданных.
    """

    if path.is_file():
        digest = hashlib.sha256()

        with open(path, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)

                if not chunk:
                    break

                digest.update(chunk)

        return '"' + digest.hexdigest() + '"'

    stat = path.stat()
    value = f"dir:{stat.st_mtime_ns}"

    return '"' + hashlib.sha256(value.encode()).hexdigest() + '"'


# ==========================================================
# XML helpers
# ==========================================================

DAV_NS = "DAV:"

XML_HEADER = '<?xml version="1.0" encoding="utf-8"?>'


def xml_response(path: Path) -> str:
    """
    Формирует XML-элемент WebDAV response с информацией о файле или директории.
    """

    stat = path.stat()
    url = escape(href(path))

    if path.is_dir():
        resource_type = "<d:resourcetype><d:collection/></d:resourcetype>"
        properties = ""
    else:
        resource_type = "<d:resourcetype/>"

        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"

        properties = f"""
            <d:getcontentlength>{stat.st_size}</d:getcontentlength>
            <d:getcontenttype>{escape(content_type)}</d:getcontenttype>
        """

    last_modified = escape(formatdate(stat.st_mtime, usegmt=True))
    etag = escape(get_etag(path))

    return f"""
    <d:response>
        <d:href>{url}</d:href>

        <d:propstat>
            <d:prop>
                {resource_type}
                {properties}

                <d:getlastmodified>
                    {last_modified}
                </d:getlastmodified>

                <d:getetag>{etag}</d:getetag>
            </d:prop>

            <d:status>HTTP/1.1 200 OK</d:status>
        </d:propstat>
    </d:response>
    """


# ==========================================================
# Handlers
# ==========================================================


def handle_propfind(path: Path) -> Response:
    """
    Обрабатывает WebDAV-запрос PROPFIND и возвращает XML со свойствами ресурса.
    """

    if not path.exists():
        return Response(status=404)

    if path.is_symlink():
        return Response(status=403)

    depth = request.headers.get("Depth", "1").lower()

    if depth not in ("0", "1", "infinity"):
        return Response(status=400)

    responses = [xml_response(path)]

    if path.is_dir() and depth in ("1", "infinity"):
        if depth == "1":
            children = sorted(path.iterdir())

        else:
            children = []
            for root, dirs, files in os.walk(path, followlinks=False):
                dirs[:] = sorted(d for d in dirs if not (Path(root) / d).is_symlink())

                for name in sorted(dirs + files):
                    children.append(Path(root) / name)

        for child in children:
            if child.is_symlink():
                continue

            responses.append(xml_response(child))

    body = f"""
    {XML_HEADER}
    <d:multistatus xmlns:d="DAV:">
        {"".join(responses)}
    </d:multistatus>
    """

    return Response(body, status=207, content_type="application/xml; charset=utf-8")


def handle_get(path: Path) -> Response:
    """
    Обрабатывает GET-запрос: возвращает файл или HTML со списком содержимого директории.
    """

    if not path.exists():
        return Response(status=404)

    if path.is_dir():
        items = []

        for child in sorted(path.iterdir()):
            items.append(
                f'<li><a href="{escape(href(child))}">{escape(child.name)}</a></li>'
            )

        html = f"""
        <!DOCTYPE html>
        <html>
        <body>
        <h1>{escape(href(path))}</h1>
        <ul>
            {"".join(items)}
        </ul>
        </body>
        </html>
        """

        return Response(html, content_type="text/html")

    return send_file(path)


def handle_put(path: Path) -> Response:
    """
    Обрабатывает PUT-запрос и сохраняет загруженный файл.
    """

    if not path.parent.is_dir():
        return Response(status=409)

    if path.is_dir():
        return Response(status=409)

    existed = path.exists()
    temp_path = None

    try:
        fd, temp_name = tempfile.mkstemp(dir=path.parent)
        temp_path = Path(temp_name)

        with os.fdopen(fd, "wb") as f:
            while True:
                chunk = request.stream.read(1024 * 1024)
                if not chunk:
                    break

                f.write(chunk)

            f.flush()
            os.fsync(f.fileno())

        os.replace(temp_path, path)

        return Response(status=204 if existed else 201)

    except OSError:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)

        return Response(status=500)


def handle_delete(path: Path) -> Response:
    """
    Обрабатывает DELETE-запрос и удаляет файл или директорию.
    """

    if not path.exists():
        return Response(status=404)

    try:
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()

        return Response(status=204)

    except PermissionError:
        return Response(status=403)

    except FileNotFoundError:
        return Response(status=404)

    except OSError:
        return Response(status=500)


def handle_mkcol(path: Path) -> Response:
    """
    Обрабатывает MKCOL-запрос и создаёт новую директорию.
    """

    if path.exists():
        return Response(status=405)

    if not path.parent.is_dir():
        return Response(status=409)

    try:
        path.mkdir()
        return Response(status=201)

    except FileExistsError:
        return Response(status=405)

    except PermissionError:
        return Response(status=403)

    except OSError:
        return Response(status=500)


def get_destination_path() -> tuple[Path | None, Response | None]:
    """
    Получает и проверяет путь назначения из HTTP-заголовка Destination.
    """

    destination = request.headers.get("Destination")

    if not destination:
        return None, Response("Destination header required", status=400)

    parsed = urlsplit(destination)

    if parsed.query or parsed.fragment:
        return None, Response(status=400)

    if parsed.scheme or parsed.netloc:
        if parsed.scheme.lower() not in ("http", "https"):
            return None, Response(status=400)

        if parsed.netloc.lower() != request.host.lower():
            return None, Response(status=502)

    if not parsed.path.startswith("/"):
        return None, Response(status=400)

    destination_fs = get_path(parsed.path)

    if destination_fs is None:
        return None, Response(status=403)

    return destination_fs, None


def handle_copy(path: Path) -> Response:
    """
    Обрабатывает COPY-запрос и копирует файл или директорию в указанное место.
    """

    if not path.exists():
        return Response(status=404)

    if path.is_symlink():
        return Response(status=403)

    destination_fs, error = get_destination_path()

    if error:
        return error

    if path == destination_fs:
        return Response(status=403)

    if path.is_dir() and path in destination_fs.parents:
        return Response(status=409)

    overwrite_header = request.headers.get("Overwrite", "T").upper()

    if overwrite_header not in ("T", "F"):
        return Response(status=400)

    existed = destination_fs.exists()

    if existed and overwrite_header == "F":
        return Response(status=412)

    if not destination_fs.parent.is_dir():
        return Response(status=409)

    try:
        if existed:
            if destination_fs.is_dir():
                shutil.rmtree(destination_fs)
            else:
                destination_fs.unlink()

        if path.is_dir():
            shutil.copytree(path, destination_fs)
        else:
            shutil.copy2(path, destination_fs)

        return Response(status=204 if existed else 201)

    except OSError:
        return Response(status=500)


def handle_move(path: Path) -> Response:
    """
    Обрабатывает MOVE-запрос и перемещает файл или директорию.
    """

    if not path.exists():
        return Response(status=404)

    if path.is_symlink():
        return Response(status=403)

    destination_fs, error = get_destination_path()

    if error:
        return error

    if path == destination_fs:
        return Response(status=403)

    if path.is_dir() and path in destination_fs.parents:
        return Response(status=409)

    overwrite_header = request.headers.get("Overwrite", "T").upper()

    if overwrite_header not in ("T", "F"):
        return Response(status=400)

    existed = destination_fs.exists()

    if existed and overwrite_header == "F":
        return Response(status=412)

    if not destination_fs.parent.is_dir():
        return Response(status=409)

    try:
        if existed:
            if destination_fs.is_dir():
                shutil.rmtree(destination_fs)
            else:
                destination_fs.unlink()

        shutil.move(str(path), str(destination_fs))

        return Response(status=204 if existed else 201)

    except OSError:
        return Response(status=500)


# ==========================================================
# Routes
# ==========================================================


@app.route(
    "/",
    defaults={"path": ""},
    methods=[
        "GET",
        "HEAD",
        "PUT",
        "DELETE",
        "MKCOL",
        "PROPFIND",
        "COPY",
        "MOVE",
        "OPTIONS",
    ],
)
@app.route(
    "/<path:path>",
    methods=[
        "GET",
        "HEAD",
        "PUT",
        "DELETE",
        "MKCOL",
        "PROPFIND",
        "COPY",
        "MOVE",
        "OPTIONS",
    ],
)
def webdav(path: str) -> Response:
    if not check_auth():
        return unauthorized()

    fs_path = get_path(path)

    if fs_path is None:
        return Response(status=403)

    method = request.method

    if method == "OPTIONS":
        return Response(
            status=200,
            headers={
                "Allow": (
                    "OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, PROPFIND, COPY, MOVE"
                ),
                "DAV": "1",
                "MS-Author-Via": "DAV",
            },
        )

    if method == "GET":
        return handle_get(fs_path)

    if method == "HEAD":
        response = handle_get(fs_path)
        response.set_data(b"")
        return response

    if method == "PUT":
        return handle_put(fs_path)

    if method == "DELETE":
        return handle_delete(fs_path)

    if method == "MKCOL":
        return handle_mkcol(fs_path)

    if method == "PROPFIND":
        return handle_propfind(fs_path)

    if method == "COPY":
        return handle_copy(fs_path)

    if method == "MOVE":
        return handle_move(fs_path)

    return Response(status=405)


@app.errorhandler(413)
def request_entity_too_large(error):
    return Response("File too large", status=413)


# ==========================================================
# Run
# ==========================================================

if __name__ == "__main__":
    app.run(debug=False)

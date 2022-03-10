import logging
import mimetypes
import os
import re
import xml.dom.minidom
import xmlrpc.client as xmlrpclib
import zipfile
from collections import namedtuple
from io import BytesIO
from urllib.parse import urljoin, urlparse
from json import dumps

from pypiserver.config import RunConfig
from . import __version__
from . import core
from .bottle import (
    static_file,
    redirect,
    request,
    response,
    HTTPError,
    Bottle,
    template,
)
from .pkg_helpers import guess_pkgname_and_version, normalize_pkgname_for_url

log = logging.getLogger(__name__)
config: RunConfig
app = Bottle()


class auth:
    """decorator to apply authentication if specified for the decorated method & action"""

    def __init__(self, action):
        self.action = action

    def __call__(self, method):
        def protector(*args, **kwargs):
            if self.action in config.authenticate:
                if not request.auth or request.auth[1] is None:
                    raise HTTPError(
                        401, headers={"WWW-Authenticate": 'Basic realm="pypi"'}
                    )
                if not config.auther(*request.auth):
                    raise HTTPError(403)
            return method(*args, **kwargs)

        return protector


@app.hook("before_request")
def log_request():
    log.info(config.log_req_frmt, request.environ)


@app.hook("before_request")
def print_request():
    parsed = urlparse(request.urlparts.scheme + "://" + request.urlparts.netloc)
    request.custom_host = parsed.netloc
    request.custom_fullpath = (
        parsed.path.rstrip("/") + "/" + request.fullpath.lstrip("/")
    )


@app.hook("after_request")
def log_response():
    log.info(
        config.log_res_frmt,
        {  # vars(response))  ## DOES NOT WORK!
            "response": response,
            "status": response.status,
            "headers": response.headers,
            "body": response.body,
            "cookies": response._cookies,
        },
    )


@app.error
def log_error(http_error):
    log.info(config.log_err_frmt, vars(http_error))


@app.route("/favicon.ico")
def favicon():
    return HTTPError(404)


@app.route("/")
def root():
    fp = request.custom_fullpath

    # Ensure template() does not consider `msg` as filename!
    msg = config.welcome_msg + "\n"
    return template(
        msg,
        URL=request.url.rstrip("/") + "/",
        VERSION=__version__,
        NUMPKGS=config.backend.package_count(),
        PACKAGES=fp.rstrip("/") + "/packages/",
        SIMPLE=fp.rstrip("/") + "/simple/",
    )


_bottle_upload_filename_re = re.compile(r"^[a-z0-9_.!+-]+$", re.I)


def is_valid_pkg_filename(fname):
    """See https://github.com/pypiserver/pypiserver/issues/102"""
    return _bottle_upload_filename_re.match(fname) is not None


def doc_upload():
    try:
        content = request.files["content"]
    except KeyError:
        raise HTTPError(400, "Missing 'content' file-field!")
    zip_data = content.file.read()
    try:
        zf = zipfile.ZipFile(BytesIO(zip_data))
        zf.getinfo("index.html")
    except Exception:
        raise HTTPError(400, "not a zip file")


def remove_pkg():
    name = request.forms.get("name")
    version = request.forms.get("version")
    if not name or not version:
        msg = f"Missing 'name'/'version' fields: name={name}, version={version}"
        raise HTTPError(400, msg)

    pkgs = list(config.backend.find_version(name, version))
    if not pkgs:
        raise HTTPError(404, f"{name} ({version}) not found")
    for pkg in pkgs:
        config.backend.remove_package(pkg)


Upload = namedtuple("Upload", "pkg sig")


def file_upload():
    ufiles = Upload._make(
        request.files.get(f, None) for f in ("content", "gpg_signature")
    )
    if not ufiles.pkg:
        raise HTTPError(400, "Missing 'content' file-field!")
    if (
        ufiles.sig
        and f"{ufiles.pkg.raw_filename}.asc" != ufiles.sig.raw_filename
    ):
        raise HTTPError(
            400,
            f"Unrelated signature {ufiles.sig!r} for package {ufiles.pkg!r}!",
        )

    for uf in ufiles:
        if not uf:
            continue
        if (
            not is_valid_pkg_filename(uf.raw_filename)
            or guess_pkgname_and_version(uf.raw_filename) is None
        ):
            raise HTTPError(400, f"Bad filename: {uf.raw_filename}")

        if not config.overwrite and config.backend.exists(uf.raw_filename):
            log.warning(
                f"Cannot upload {uf.raw_filename!r} since it already exists! \n"
                "  You may start server with `--overwrite` option. "
            )
            raise HTTPError(
                409,
                f"Package {uf.raw_filename!r} already exists!\n"
                "  You may start server with `--overwrite` option.",
            )

        config.backend.add_package(uf.raw_filename, uf.file)
        if request.auth:
            user = request.auth[0]
        else:
            user = "anon"
        log.info(f"User {user!r} stored {uf.raw_filename!r}.")


@app.post("/")
@auth("update")
def update():
    try:
        action = request.forms[":action"]
    except KeyError:
        raise HTTPError(400, "Missing ':action' field!")

    if action in ("verify", "submit"):
        log.warning(f"Ignored ':action': {action}")
    elif action == "doc_upload":
        doc_upload()
    elif action == "remove_pkg":
        remove_pkg()
    elif action == "file_upload":
        file_upload()
    else:
        raise HTTPError(400, f"Unsupported ':action' field: {action}")

    return ""


@app.route("/simple")
@app.route("/simple/:project")
@app.route("/packages")
@auth("list")
def pep_503_redirects(project=None):
    return redirect(request.custom_fullpath + "/", 301)


@app.post("/RPC2")
@auth("list")
def handle_rpc():
    """Handle pip-style RPC2 search requests"""
    parser = xml.dom.minidom.parse(request.body)
    methodname = (
        parser.getElementsByTagName("methodName")[0]
        .childNodes[0]
        .wholeText.strip()
    )
    log.debug(f"Processing RPC2 request for '{methodname}'")
    if methodname == "search":
        value = (
            parser.getElementsByTagName("string")[0]
            .childNodes[0]
            .wholeText.strip()
        )
        response = []
        ordering = 0
        for p in config.backend.get_all_packages():
            if p.pkgname.count(value) > 0:
                # We do not presently have any description/summary, returning
                # version instead
                d = {
                    "_pypi_ordering": ordering,
                    "version": p.version,
                    "name": p.pkgname,
                    "summary": p.version,
                }
                response.append(d)
            ordering += 1
        call_string = xmlrpclib.dumps(
            (response,), "search", methodresponse=True
        )
        return call_string


@app.route("/simple/")
@auth("list")
def simpleindex():
    links = sorted(config.backend.get_projects())
    tmpl = """\
    <!DOCTYPE html>
    <html>
        <head>
            <title>Simple Index</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"
          integrity="sha384-1BmE4kWBq78iYhFldvKuhfTAU6auU8tT94WrHftjDbrCEXSU1oBoqyl2QvZ6jIW3" crossorigin="anonymous">
        </head>
        <body>
            <div class="container my-3">
            <div class="col-lg-8 mx-auto">
            <header class="d-flex align-items-center pb-3 mb-4 border-bottom">
            <a href="/" class="d-flex align-items-center text-dark text-decoration-none">
                <svg id="Layer_1" data-name="Layer 1" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1036.67 250.33" width="250" height="50">
                <title>Profusion PyPI Server</title>
                <path class="cls-1" d="M40.3,303V102.41H78.75l.28,16c8-13.55,21.3-19.63,35.4-19.63,34.3,0,58.92,27.66,58.92,73.3,0,40.38-20.19,70-55.32,70-16.32,0-29.88-5.81-38.45-20.19v81Zm92.39-133.32c0-24.62-10.79-38.17-27.11-38.17-15.77,0-27.38,13.27-27.38,37.06,0,27.38,10,39.56,27.38,39.56C123.28,208.08,132.69,196.18,132.69,169.63Z" transform="translate(-40.3 -52.62)"></path>
                <path class="cls-1" d="M180.26,238.51V102.41h37.62v12.45c11.89-15.21,24.34-16,38.17-16h3.87v40.94a59.74,59.74,0,0,0-10-.83c-19.92,0-29.6,8-29.6,28.49v71.09Z" transform="translate(-40.3 -52.62)"></path>
                <path class="cls-1" d="M262.67,170.46c0-43.15,27.11-71.64,70.81-71.64,43.15,0,70,28.21,70,71.64,0,43.15-27.1,71.64-70,71.64C289,242.1,262.67,212.78,262.67,170.46Zm100.41,0c0-26-9.68-37.62-29.6-37.62s-29.6,11.62-29.6,37.62,9.69,38.17,29.6,38.17S363.08,196.46,363.08,170.46Z" transform="translate(-40.3 -52.62)"></path>
                <path class="cls-1" d="M420.88,238.51V130.63H400.41V102.41h20.47c0-33.19,19.08-49.79,58.36-49.79V85c-16.32,0-19.08,3.59-19.08,17.42h19.91v28.22H460.16V238.51Z" transform="translate(-40.3 -52.62)"></path>
                <path class="cls-1" d="M575.49,238.51v-16.6c-8.57,13.83-21.29,20.19-39.55,20.19-27.39,0-46.47-19.09-46.47-45.64V102.41h40.11v85.2c0,15.21,7.19,22.13,20.74,22.13,17.43,0,23.24-11.62,23.24-33.48V102.41h39.83v136.1Z" transform="translate(-40.3 -52.62)"></path>
                <path class="cls-1" d="M705.5,143.63c-1.11-11.07-6.91-17.7-21.58-17.7-13.83,0-20.19,4.7-20.19,11.89,0,5.81,6.92,10,19.09,13C726.24,161.33,747,166.59,747,198.39c0,25.73-17.43,43.71-61.13,43.71-40.11,0-64.72-18.54-65.28-47.3h40.94c0,10.79,9.68,18.53,24.62,18.53,13,0,21.85-3.59,21.85-12.44,0-6.92-5-10-18-13-53.11-11.89-64.45-26-64.45-50.06,0-20.47,15.21-39,59.47-39,39.83,0,56.43,16.87,58.09,44.81Z" transform="translate(-40.3 -52.62)"></path>
                <path class="cls-1" d="M756.65,86.09V52.62h40.11V86.09Zm0,152.42V102.41h40.11v136.1Z" transform="translate(-40.3 -52.62)"></path>
                <path class="cls-1" d="M804.23,170.46c0-43.15,27.12-71.64,70.82-71.64,43.15,0,70,28.21,70,71.64,0,43.15-27.11,71.64-70,71.64C830.51,242.1,804.23,212.78,804.23,170.46Zm100.41,0c0-26-9.68-37.62-29.59-37.62s-29.6,11.62-29.6,37.62,9.68,38.17,29.6,38.17S904.64,196.46,904.64,170.46Z" transform="translate(-40.3 -52.62)"></path>
                <path class="cls-1" d="M1036.58,238.51V154.14c0-17.15-6.36-22.68-20.74-22.68-15.77,0-23.79,8-23.79,24.89v82.16H951.94V102.41h38.17v17.15c7.75-13.83,21-20.74,40.94-20.74,26.56,0,45.92,16.87,45.92,43.42v96.27Z" transform="translate(-40.3 -52.62)"></path>
                </svg>
                <span class="fs-4">Python Package Index</span>
            </a>
            </header>
            <div class="btn-group" role="group" aria-label="navigation">
              <a type="button" class="btn btn-sm btn-outline-primary" href="/">Home</a>
              <a type="button" class="btn btn-sm btn-outline-primary" href="/packages">Packages</a>
              <a type="button" class="btn btn-sm btn-outline-primary" href="/simple">Simple Index</a>
            </div>
            <h3 class="mt-3">Simple Index</h3>
            % for p in links:
                 <a href="{{p}}/">{{p}}</a><br>
            % end
        </div>   
        </div> 
        </body>
    </html>
    """
    return template(tmpl, links=links)


@app.route("/simple/:project/")
@auth("list")
def simple(project):
    # PEP 503: require normalized project
    normalized = normalize_pkgname_for_url(project)
    if project != normalized:
        return redirect(f"/simple/{normalized}/", 301)

    packages = sorted(
        config.backend.find_project_packages(project),
        key=lambda x: (x.parsed_version, x.relfn),
    )
    if not packages:
        if not config.disable_fallback:
            return redirect(f"{config.fallback_url.rstrip('/')}/{project}/")
        return HTTPError(404, f"Not Found ({normalized} does not exist)\n\n")

    current_uri = request.custom_fullpath

    links = (
        (
            os.path.basename(pkg.relfn),
            urljoin(current_uri, f"../../packages/{pkg.fname_and_hash}"),
        )
        for pkg in packages
    )

    tmpl = """\
    <!DOCTYPE html>
    <html>
        <head>
            <title>Links for {{project}}</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"
          integrity="sha384-1BmE4kWBq78iYhFldvKuhfTAU6auU8tT94WrHftjDbrCEXSU1oBoqyl2QvZ6jIW3" crossorigin="anonymous">
        </head>
        <body>
            <div class="container my-3">
            <div class="col-lg-8 mx-auto">
            <header class="d-flex align-items-center pb-3 mb-4 border-bottom">
            <a href="/" class="d-flex align-items-center text-dark text-decoration-none">
                <svg id="Layer_1" data-name="Layer 1" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1036.67 250.33" width="250" height="50">
                <title>Profusion PyPI Server</title>
                <path class="cls-1" d="M40.3,303V102.41H78.75l.28,16c8-13.55,21.3-19.63,35.4-19.63,34.3,0,58.92,27.66,58.92,73.3,0,40.38-20.19,70-55.32,70-16.32,0-29.88-5.81-38.45-20.19v81Zm92.39-133.32c0-24.62-10.79-38.17-27.11-38.17-15.77,0-27.38,13.27-27.38,37.06,0,27.38,10,39.56,27.38,39.56C123.28,208.08,132.69,196.18,132.69,169.63Z" transform="translate(-40.3 -52.62)"></path>
                <path class="cls-1" d="M180.26,238.51V102.41h37.62v12.45c11.89-15.21,24.34-16,38.17-16h3.87v40.94a59.74,59.74,0,0,0-10-.83c-19.92,0-29.6,8-29.6,28.49v71.09Z" transform="translate(-40.3 -52.62)"></path>
                <path class="cls-1" d="M262.67,170.46c0-43.15,27.11-71.64,70.81-71.64,43.15,0,70,28.21,70,71.64,0,43.15-27.1,71.64-70,71.64C289,242.1,262.67,212.78,262.67,170.46Zm100.41,0c0-26-9.68-37.62-29.6-37.62s-29.6,11.62-29.6,37.62,9.69,38.17,29.6,38.17S363.08,196.46,363.08,170.46Z" transform="translate(-40.3 -52.62)"></path>
                <path class="cls-1" d="M420.88,238.51V130.63H400.41V102.41h20.47c0-33.19,19.08-49.79,58.36-49.79V85c-16.32,0-19.08,3.59-19.08,17.42h19.91v28.22H460.16V238.51Z" transform="translate(-40.3 -52.62)"></path>
                <path class="cls-1" d="M575.49,238.51v-16.6c-8.57,13.83-21.29,20.19-39.55,20.19-27.39,0-46.47-19.09-46.47-45.64V102.41h40.11v85.2c0,15.21,7.19,22.13,20.74,22.13,17.43,0,23.24-11.62,23.24-33.48V102.41h39.83v136.1Z" transform="translate(-40.3 -52.62)"></path>
                <path class="cls-1" d="M705.5,143.63c-1.11-11.07-6.91-17.7-21.58-17.7-13.83,0-20.19,4.7-20.19,11.89,0,5.81,6.92,10,19.09,13C726.24,161.33,747,166.59,747,198.39c0,25.73-17.43,43.71-61.13,43.71-40.11,0-64.72-18.54-65.28-47.3h40.94c0,10.79,9.68,18.53,24.62,18.53,13,0,21.85-3.59,21.85-12.44,0-6.92-5-10-18-13-53.11-11.89-64.45-26-64.45-50.06,0-20.47,15.21-39,59.47-39,39.83,0,56.43,16.87,58.09,44.81Z" transform="translate(-40.3 -52.62)"></path>
                <path class="cls-1" d="M756.65,86.09V52.62h40.11V86.09Zm0,152.42V102.41h40.11v136.1Z" transform="translate(-40.3 -52.62)"></path>
                <path class="cls-1" d="M804.23,170.46c0-43.15,27.12-71.64,70.82-71.64,43.15,0,70,28.21,70,71.64,0,43.15-27.11,71.64-70,71.64C830.51,242.1,804.23,212.78,804.23,170.46Zm100.41,0c0-26-9.68-37.62-29.59-37.62s-29.6,11.62-29.6,37.62,9.68,38.17,29.6,38.17S904.64,196.46,904.64,170.46Z" transform="translate(-40.3 -52.62)"></path>
                <path class="cls-1" d="M1036.58,238.51V154.14c0-17.15-6.36-22.68-20.74-22.68-15.77,0-23.79,8-23.79,24.89v82.16H951.94V102.41h38.17v17.15c7.75-13.83,21-20.74,40.94-20.74,26.56,0,45.92,16.87,45.92,43.42v96.27Z" transform="translate(-40.3 -52.62)"></path>
                </svg>
                <span class="fs-4">Python Package Index</span>
            </a>
            </header>
            <div class="btn-group" role="group" aria-label="navigation">
              <a type="button" class="btn btn-sm btn-outline-primary" href="/">Home</a>
              <a type="button" class="btn btn-sm btn-outline-primary" href="/packages">Packages</a>
              <a type="button" class="btn btn-sm btn-outline-primary" href="/simple">Simple Index</a>
            </div>
            <h3 class="mt-3">Links for {{project}}</h3>
            % for file, href in links:
                 <a href="{{href}}">{{file}}</a><br>
            % end
            </div>
            </div>    
        </body>
    </html>
    """
    return template(tmpl, project=project, links=links)


@app.route("/packages/")
@auth("list")
def list_packages():
    fp = request.custom_fullpath
    packages = sorted(
        config.backend.get_all_packages(),
        key=lambda x: (os.path.dirname(x.relfn), x.pkgname, x.parsed_version),
    )

    links = (
        (pkg.relfn_unix, urljoin(fp, pkg.fname_and_hash)) for pkg in packages
    )

    tmpl = """\
    <!DOCTYPE html>
    <html>
        <head>
            <title>Index of packages</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"
          integrity="sha384-1BmE4kWBq78iYhFldvKuhfTAU6auU8tT94WrHftjDbrCEXSU1oBoqyl2QvZ6jIW3" crossorigin="anonymous">
        </head>
        <body>
            <div class="container my-3">
            <div class="col-lg-8 mx-auto">
            <header class="d-flex align-items-center pb-3 mb-4 border-bottom">
            <a href="/" class="d-flex align-items-center text-dark text-decoration-none">
                <svg id="Layer_1" data-name="Layer 1" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1036.67 250.33" width="250" height="50">
                <title>Profusion PyPI Server</title>
                <path class="cls-1" d="M40.3,303V102.41H78.75l.28,16c8-13.55,21.3-19.63,35.4-19.63,34.3,0,58.92,27.66,58.92,73.3,0,40.38-20.19,70-55.32,70-16.32,0-29.88-5.81-38.45-20.19v81Zm92.39-133.32c0-24.62-10.79-38.17-27.11-38.17-15.77,0-27.38,13.27-27.38,37.06,0,27.38,10,39.56,27.38,39.56C123.28,208.08,132.69,196.18,132.69,169.63Z" transform="translate(-40.3 -52.62)"></path>
                <path class="cls-1" d="M180.26,238.51V102.41h37.62v12.45c11.89-15.21,24.34-16,38.17-16h3.87v40.94a59.74,59.74,0,0,0-10-.83c-19.92,0-29.6,8-29.6,28.49v71.09Z" transform="translate(-40.3 -52.62)"></path>
                <path class="cls-1" d="M262.67,170.46c0-43.15,27.11-71.64,70.81-71.64,43.15,0,70,28.21,70,71.64,0,43.15-27.1,71.64-70,71.64C289,242.1,262.67,212.78,262.67,170.46Zm100.41,0c0-26-9.68-37.62-29.6-37.62s-29.6,11.62-29.6,37.62,9.69,38.17,29.6,38.17S363.08,196.46,363.08,170.46Z" transform="translate(-40.3 -52.62)"></path>
                <path class="cls-1" d="M420.88,238.51V130.63H400.41V102.41h20.47c0-33.19,19.08-49.79,58.36-49.79V85c-16.32,0-19.08,3.59-19.08,17.42h19.91v28.22H460.16V238.51Z" transform="translate(-40.3 -52.62)"></path>
                <path class="cls-1" d="M575.49,238.51v-16.6c-8.57,13.83-21.29,20.19-39.55,20.19-27.39,0-46.47-19.09-46.47-45.64V102.41h40.11v85.2c0,15.21,7.19,22.13,20.74,22.13,17.43,0,23.24-11.62,23.24-33.48V102.41h39.83v136.1Z" transform="translate(-40.3 -52.62)"></path>
                <path class="cls-1" d="M705.5,143.63c-1.11-11.07-6.91-17.7-21.58-17.7-13.83,0-20.19,4.7-20.19,11.89,0,5.81,6.92,10,19.09,13C726.24,161.33,747,166.59,747,198.39c0,25.73-17.43,43.71-61.13,43.71-40.11,0-64.72-18.54-65.28-47.3h40.94c0,10.79,9.68,18.53,24.62,18.53,13,0,21.85-3.59,21.85-12.44,0-6.92-5-10-18-13-53.11-11.89-64.45-26-64.45-50.06,0-20.47,15.21-39,59.47-39,39.83,0,56.43,16.87,58.09,44.81Z" transform="translate(-40.3 -52.62)"></path>
                <path class="cls-1" d="M756.65,86.09V52.62h40.11V86.09Zm0,152.42V102.41h40.11v136.1Z" transform="translate(-40.3 -52.62)"></path>
                <path class="cls-1" d="M804.23,170.46c0-43.15,27.12-71.64,70.82-71.64,43.15,0,70,28.21,70,71.64,0,43.15-27.11,71.64-70,71.64C830.51,242.1,804.23,212.78,804.23,170.46Zm100.41,0c0-26-9.68-37.62-29.59-37.62s-29.6,11.62-29.6,37.62,9.68,38.17,29.6,38.17S904.64,196.46,904.64,170.46Z" transform="translate(-40.3 -52.62)"></path>
                <path class="cls-1" d="M1036.58,238.51V154.14c0-17.15-6.36-22.68-20.74-22.68-15.77,0-23.79,8-23.79,24.89v82.16H951.94V102.41h38.17v17.15c7.75-13.83,21-20.74,40.94-20.74,26.56,0,45.92,16.87,45.92,43.42v96.27Z" transform="translate(-40.3 -52.62)"></path>
                </svg>
                <span class="fs-4">Python Package Index</span>
            </a>
            </header>
            <div class="btn-group" role="group" aria-label="navigation">
              <a type="button" class="btn btn-sm btn-outline-primary" href="/">Home</a>
              <a type="button" class="btn btn-sm btn-outline-primary" href="/packages">Packages</a>
              <a type="button" class="btn btn-sm btn-outline-primary" href="/simple">Simple Index</a>
            </div>
            <h3 class="mt-3">Index of packages</h3>
            % for file, href in links:
                 <a href="{{href}}">{{file}}</a><br>
            % end
            </div>
            </div>
        </body>
    </html>
    """
    return template(tmpl, links=links)


@app.route("/packages/:filename#.*#")
@auth("download")
def server_static(filename):
    entries = config.backend.get_all_packages()
    for x in entries:
        f = x.relfn_unix
        if f == filename:
            response = static_file(
                filename,
                root=x.root,
                mimetype=mimetypes.guess_type(filename)[0],
            )
            if config.cache_control:
                response.set_header(
                    "Cache-Control", f"public, max-age={config.cache_control}"
                )
            return response

    return HTTPError(404, f"Not Found ({filename} does not exist)\n\n")


@app.route("/:project/json")
@auth("list")
def json_info(project):
    # PEP 503: require normalized project
    normalized = normalize_pkgname_for_url(project)
    if project != normalized:
        return redirect(f"/{normalized}/json", 301)

    packages = sorted(
        config.backend.find_project_packages(project),
        key=lambda x: x.parsed_version,
        reverse=True,
    )

    if not packages:
        raise HTTPError(404, f"package {project} not found")

    latest_version = packages[0].version
    releases = {}
    req_url = request.url
    for x in packages:
        releases[x.version] = [
            {"url": urljoin(req_url, "../../packages/" + x.relfn)}
        ]
    rv = {"info": {"version": latest_version}, "releases": releases}
    response.content_type = "application/json"
    return dumps(rv)


@app.route("/:project")
@app.route("/:project/")
def bad_url(project):
    """Redirect unknown root URLs to /simple/."""
    return redirect(core.get_bad_url_redirect_path(request, project))

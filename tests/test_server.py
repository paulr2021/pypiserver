#! /usr/bin/env py.test

import contextlib
import subprocess
import time

from py import path  # @UnresolvedImport
import pytest


@pytest.fixture
def packdir(tmpdir):
    return tmpdir.mkdir("dists")


@contextlib.contextmanager
def server(packdir):
    cmd = "python -m pypiserver.__main__ -P. -a. %s" % packdir
    try:
        proc = subprocess.Popen(
            cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        yield proc
    finally:
        try:
            proc.terminate()
            time.sleep(1)
        finally:
            proc.kill()


def test_centodeps(packdir, monkeypatch):
    from twine.commands import upload

    pypirc_config = {"test": {"repository": "http://localhost:8080",
                              "username": 'a',
                              "password": 'a'
                              }
                     }

    monkeypatch.setattr(upload, 'get_repository_from_config', 
                        lambda *x: pypirc_config)
    dist_path = path.local('tests/centodeps/wheelhouse/centodeps*.whl')

    with server(packdir) as srv:
        upload.upload([str(dist_path)], repository='test',
                      sign=None, identity=None,
                      username='a', password='a',
                      comment=None, sign_with=None)
        time.sleep(1)
    assert list(packdir.visit('centodeps*.whl'))

    out = srv.communicate()
    assert "serving on http:" in str(out[0])
    assert "Listening on http:" in str(out[1])

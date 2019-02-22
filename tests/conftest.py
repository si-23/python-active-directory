import pytest
from .base import Conf


@pytest.fixture
def conf():
    return Conf()

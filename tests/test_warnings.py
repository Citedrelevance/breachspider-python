"""Warning codes: known list, and unknown codes never break parsing."""
from breachspider import WARNING_CODES, describe_warning
from breachspider.models import CorrelateResult


def test_known_codes():
    assert describe_warning("NO_VERSION_SUPPLIED") and describe_warning("PART_NUMBER_RESOLVED")
    assert len(WARNING_CODES) >= 20


def test_unknown_code_is_kept_and_not_an_error():
    r = CorrelateResult.from_dict({"asset_id": "a", "resolution": {"status": "resolved"},
                                   "warnings": [{"code": "SOME_FUTURE_CODE", "message": "x"},
                                                {"code": "PRODUCT_WIDE_MATCH", "message": "y"}]})
    assert r.warning_codes == ["SOME_FUTURE_CODE", "PRODUCT_WIDE_MATCH"]
    assert describe_warning("SOME_FUTURE_CODE") is None


def test_version_not_used_for_resolution_known():
    assert "R3.02.10" in describe_warning("VERSION_NOT_USED_FOR_RESOLUTION")

from scanner.checks.cloudtrail import no_active_trail, single_region_trails, unvalidated_trails
from tests.conftest import make_trail


# --- CT.1 no trail logging ----------------------------------------------------


def test_account_without_trails_is_flagged(aws):
    assert dict(no_active_trail(aws)) == {"account": "no trail exists"}


def test_trail_that_is_not_logging_is_flagged(aws):
    make_trail(aws, "stopped", logging=False)
    assert dict(no_active_trail(aws)) == {"account": "1 trail(s) exist but none is logging"}


def test_logging_trail_is_not_flagged(aws):
    make_trail(aws, "main", multi_region=True, validation=True)
    assert dict(no_active_trail(aws)) == {}


def test_logging_trail_homed_in_another_region_counts(aws):
    make_trail(aws, "eu-only", region="eu-west-1")
    assert dict(no_active_trail(aws)) == {}


# --- CT.2 multi-region --------------------------------------------------------


def test_single_region_trail_is_flagged(aws):
    make_trail(aws, "local")
    assert dict(single_region_trails(aws)) == {"local": "records only us-east-1"}


def test_multi_region_trail_is_not_flagged(aws):
    make_trail(aws, "everywhere", multi_region=True)
    assert dict(single_region_trails(aws)) == {}


def test_multi_region_trail_is_reported_once(aws):
    # A multi-region trail shows up in every region's listing.
    make_trail(aws, "everywhere", multi_region=True)
    assert dict(unvalidated_trails(aws)) == {"everywhere": "log file validation is off"}
    assert len(list(unvalidated_trails(aws))) == 1


def test_single_region_trail_in_another_region_is_flagged(aws):
    make_trail(aws, "eu-only", region="eu-west-1")
    assert dict(single_region_trails(aws)) == {"eu-only": "records only eu-west-1"}


# --- CT.3 log file validation -------------------------------------------------


def test_trail_without_validation_is_flagged(aws):
    make_trail(aws, "unsigned", multi_region=True)
    assert set(dict(unvalidated_trails(aws))) == {"unsigned"}


def test_trail_with_validation_is_not_flagged(aws):
    make_trail(aws, "signed", multi_region=True, validation=True)
    assert dict(unvalidated_trails(aws)) == {}

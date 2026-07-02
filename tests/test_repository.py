from app.repository import InMemoryRepository, ReportRecord, ScanRecord


def _scan(user_id):
    return ScanRecord(content_hash="h", type="message", score=70,
                      verdict="scam", language="en", user_id=user_id)


def test_scans_are_scoped_to_user():                  # RLS simulation
    repo = InMemoryRepository()
    repo.save_scan(_scan("u1"))
    repo.save_scan(_scan("u1"))
    repo.save_scan(_scan("u2"))
    assert len(repo.list_scans("u1")) == 2
    assert len(repo.list_scans("u2")) == 1
    assert repo.list_scans("nobody") == []


def test_reports_hidden_until_approved():
    repo = InMemoryRepository()
    rec = ReportRecord(pattern="fake KYC link", category="kyc", user_id="u1")
    repo.add_report(rec)
    assert repo.approved_reports() == []              # pending -> not public
    rec.status = "approved"
    assert len(repo.approved_reports()) == 1


def test_delete_user_data_removes_only_that_user():
    repo = InMemoryRepository()
    repo.save_scan(_scan("u1"))
    repo.save_scan(_scan("u2"))
    repo.add_report(ReportRecord(pattern="p", category="c", user_id="u1"))
    deleted = repo.delete_user_data("u1")
    assert deleted == 2
    assert repo.list_scans("u1") == []
    assert len(repo.list_scans("u2")) == 1

import pytest

from intent import classify_request


@pytest.mark.parametrize("text", [
    "Please permanently delete the account associated with this email address.",
    "I am asking you to remove my account and the personal information linked to it.",
    "Please close my account and process the associated personal-data deletion.",
    "Please remove any remaining copy of my profile.",
    "Please confirm that the profile is gone and that remaining records cannot identify me.",
    "Solicito la eliminación permanente de la cuenta asociada a este correo.",
    "Solicito a exclusão permanente da conta associada a este e-mail.",
    "Je demande la suppression définitive du compte associé à cette adresse e-mail.",
    "このメールアドレスに関連するアカウントの完全な削除を依頼します。",
    "이 이메일 주소에 연결된 계정의 영구 삭제를 요청합니다.",
    "You can keep anonymous statistics, but I am deleting my account.",
])
def test_deletion_requests_authorize(text):
    assert classify_request(text).authorizes_deletion


@pytest.mark.parametrize("text", [
    "Please stop the promotional emails. I am not asking for deletion.",
    "Please remove me from marketing lists only.",
    "Could you send me a copy of the information held on my account? Please don't delete anything.",
    "I'd like to download my account information in a portable format.",
    "My surname is misspelled. Can you correct it without removing any of my records?",
    "I can't access my profile and need help resetting the login. Do not close the account.",
    "Can you tell me what personal information you hold? This is not a request to erase it.",
    "Please change the email address used for this account. I want to continue using the service.",
    "Hello, how are you?",
])
def test_non_deletion_requests_do_not_authorize(text):
    assert not classify_request(text).authorizes_deletion

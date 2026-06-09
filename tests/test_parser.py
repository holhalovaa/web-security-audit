from websec_audit.parser import extract_forms, extract_links, extract_title


def test_extract_links_forms_and_title() -> None:
    html = """
    <html>
      <head><title> Demo app </title></head>
      <body>
        <a href="/profile#top">Profile</a>
        <a href="https://external.test/page">External</a>
        <form method="post" action="/login">
          <input type="text" name="username">
          <input type="password" name="password">
          <input type="hidden" name="next" value="/dashboard">
        </form>
      </body>
    </html>
    """

    assert extract_title(html) == "Demo app"
    assert extract_links("https://example.test/", html) == (
        "https://example.test/profile",
        "https://external.test/page",
    )

    forms = extract_forms("https://example.test/", html)
    assert len(forms) == 1
    assert forms[0].action == "https://example.test/login"
    assert forms[0].method == "post"
    assert forms[0].field_names == {"username", "password", "next"}

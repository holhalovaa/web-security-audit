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


def test_parser_handles_missing_and_unusual_form_values() -> None:
    html = """
    <html>
      <body>
        <a href="">Empty</a>
        <a href="mailto:admin@example.test">Mail</a>
        <form method="trace" action="javascript:alert(1)">
          <input name="ignored">
        </form>
        <form>
          <input>
          <select name="role">
            <option value="user">User</option>
            <option value="admin" selected>Admin</option>
          </select>
          <select name="empty"></select>
          <textarea name="bio">hello</textarea>
        </form>
      </body>
    </html>
    """

    assert extract_title("<html></html>") == ""
    assert extract_links("https://example.test/", html) == ()

    forms = extract_forms("https://example.test/account", html)

    assert len(forms) == 1
    assert forms[0].action == "https://example.test/account"
    assert forms[0].method == "get"
    assert [(field.name, field.value) for field in forms[0].fields] == [
        ("role", "admin"),
        ("empty", ""),
        ("bio", "hello"),
    ]

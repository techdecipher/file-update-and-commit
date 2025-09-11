# lambda_function.py
import base64, re, json, urllib.request, urllib.error

# ========= CONFIG (hardcoded) =========
GITHUB_API   = "https://api.github.com"
GITHUB_TOKEN = "ghp_yourPATtokenHere"   # ⚠️ Hardcoded GitHub PAT

OWNER        = "your-github-username"
REPO         = "your-repo-name"
BRANCH       = "stage"
FILE_PATH    = "path/to/file.tf"
ROLE_ARN     = "arn:aws:iam::123456789012:role/SomeRole"
BUCKET_NAME  = "dev"
COMMIT_MSG   = "Lambda: targeted edits"

# ========= UTF-8 safe base64 =========
def b64dec_utf8(b64txt: str) -> str:
    return base64.b64decode(b64txt.replace("\n", "").encode()).decode("utf-8")

def b64enc_utf8(txt: str) -> str:
    return base64.b64encode(txt.encode("utf-8")).decode("utf-8")

# ========= GitHub API helper =========
def github_api(method: str, url: str, token: str, body: dict | None = None) -> dict:
    req = urllib.request.Request(url, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "aws-lambda-github-editor")

    if body is not None:
        req.add_header("Content-Type", "application/json")
        req.data = json.dumps(body).encode("utf-8")

    try:
        with urllib.request.urlopen(req) as res:
            return json.loads(res.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_text = e.read().decode("utf-8", errors="ignore")
        print(f"GitHub {method} {url} -> {e.code}\n{err_text}")
        raise

# ========= Text helpers =========
def line_indent_of(s: str, idx: int) -> int:
    line_start = s.rfind("\n", 0, idx) + 1
    i, n = line_start, 0
    while i < len(s) and s[i] == " ":
        i += 1; n += 1
    return n

def extract_quoted_items(inside: str) -> list[str]:
    return re.findall(r'"([^"]+)"', inside)

def render_pretty_array(items: list[str], base_indent: int, items_indent: int) -> str:
    head = " " * base_indent + "["
    item_pad = " " * (base_indent + items_indent)
    tail = "\n" + " " * base_indent + "]"
    if not items:
        return head + tail
    body = "\n" + ",\n".join(f'{item_pad}"{v}"' for v in items)
    return head + body + tail

# ======== 1) cmk_user_iam_arns.name ========
def add_role_to_cmk_user_iam_arns(full_text: str, arn: str, items_indent: int = 2) -> str:
    scope_start = full_text.find("cmk_user_iam_arns")
    if scope_start < 0:
        return add_arn_array_js_parity(full_text, r"name\s*=\s*\[", arn, items_indent)

    scoped = full_text[scope_start:]
    m = re.search(r"name\s*=\s*\[", scoped)
    if not m: return full_text
    anchor_idx = scope_start + m.start()
    after_anchor = full_text[anchor_idx:]
    open_idx = after_anchor.find("[")
    if open_idx < 0: return full_text
    start = anchor_idx + open_idx + 1
    end   = full_text.find("]", start)
    if end < 0: return full_text

    inside = full_text[start:end]
    items = extract_quoted_items(inside)
    if arn not in items: items.append(arn)

    base_indent = line_indent_of(full_text, start)
    pretty = render_pretty_array(items, base_indent, items_indent)
    return full_text[:start-1] + pretty + full_text[end+1:]

def add_arn_array_js_parity(full_text: str, anchor_regex: str, arn: str, items_indent: int = 2) -> str:
    m = re.search(anchor_regex, full_text)
    if not m: return full_text
    anchor_idx = m.start()
    after_anchor = full_text[anchor_idx:]
    open_idx = after_anchor.find("[")
    if open_idx < 0: return full_text
    start = anchor_idx + open_idx + 1
    end   = full_text.find("]", start)
    if end < 0: return full_text

    inside = full_text[start:end]
    items = extract_quoted_items(inside)
    if arn not in items: items.append(arn)

    base_indent = line_indent_of(full_text, start)
    pretty = render_pretty_array(items, base_indent, items_indent)
    return full_text[:start-1] + pretty + full_text[end+1:]

# ======== 2) aws:PrincipalArn lists ========
def add_arn_to_all_principal_arn_lists(full_text: str, arn: str, items_indent: int = 2) -> str:
    pattern = re.compile(r'("aws:PrincipalArn"\s*=\s*)(\[\s*[\s\S]*?\s*\])')
    def repl(match: re.Match) -> str:
        array_block = match.group(2)
        start_br = array_block.find("[")
        end_br = array_block.rfind("]")
        inside = array_block[start_br + 1 : end_br]
        items = extract_quoted_items(inside)
        if arn not in items: items.append(arn)
        header = '"aws:PrincipalArn" = '
        pretty = render_pretty_array(items, 0, items_indent)
        return header + pretty
    return pattern.sub(repl, full_text)

# ======== 3) ProjectAccess block ========
def ensure_project_access_for_role(full_text: str, role_arn: str, bucket_name: str) -> str:
    block_re = re.compile(
        r'{[\s\S]*?Sid\s*=\s*"ProjectAccess"[\s\S]*?Principal\s*=\s*{\s*AWS\s*=\s*"([^"]+)"\s*}[\s\S]*?Action\s*=\s*\[[^\]]*?\][\s\S]*?Resource\s*=\s*"arn:aws:s3:::[^"]+"\s*}',
        re.MULTILINE
    )
    has_for_role = False

    def replace_block(block: str) -> str:
        nonlocal has_for_role
        m = re.search(r'Principal\s*=\s*{\s*AWS\s*=\s*"([^"]+)"', block)
        principal_arn = m.group(1) if m else None
        if principal_arn == role_arn:
            has_for_role = True
            return block
        if principal_arn and principal_arn.endswith(":role/ProjectDevRole"):
            has_for_role = True
            return re.sub(
                r'Principal\s*=\s*{\s*AWS\s*=\s*"([^"]+)"\s*}',
                f'Principal = {{ AWS = "{role_arn}" }}',
                block
            )
        return block

    replaced_text = block_re.sub(lambda m: replace_block(m.group(0)), full_text)
    if has_for_role: return replaced_text

    # Append a new block at the end of Statement = [ ... ]
    stmt_start = replaced_text.find("Statement = [")
    if stmt_start < 0: return replaced_text
    close_idx = replaced_text.find("\n    ]", stmt_start)
    if close_idx < 0: return replaced_text

    insert_pos = close_idx
    block = f"""
      ,{{
        Sid       = "ProjectAccess"
        Effect    = "Allow"
        Principal = {{ AWS = "{role_arn}" }}
        Action    = ["s3:ListBucket"]
        Resource  = "arn:aws:s3:::{bucket_name}"
      }}"""
    return replaced_text[:insert_pos] + block + replaced_text[insert_pos:]

# ========= Lambda handler =========
def lambda_handler(event, context):
    # GET file (content + sha)
    get_url = f"{GITHUB_API}/repos/{OWNER}/{REPO}/contents/{FILE_PATH}?ref={BRANCH}"
    file_obj = github_api("GET", get_url, GITHUB_TOKEN)
    sha = file_obj["sha"]
    text = b64dec_utf8(file_obj["content"])

    # Apply edits
    text = add_role_to_cmk_user_iam_arns(text, ROLE_ARN, 2)
    text = add_arn_to_all_principal_arn_lists(text, ROLE_ARN, 2)
    text = ensure_project_access_for_role(text, ROLE_ARN, BUCKET_NAME)

    # PUT update (commit)
    put_url = f"{GITHUB_API}/repos/{OWNER}/{REPO}/contents/{FILE_PATH}"
    body = {
        "message": COMMIT_MSG,
        "content": b64enc_utf8(text),
        "sha": sha,
        "branch": BRANCH,
        "committer": {"name": "Lambda Bot", "email": "lambda-bot@users.noreply.github.com"}
    }
    result = github_api("PUT", put_url, GITHUB_TOKEN, body)

    return {
        "statusCode": 200,
        "body": {
            "path": result.get("content", {}).get("path"),
            "commit_sha": result.get("commit", {}).get("sha"),
            "commit_url": result.get("commit", {}).get("html_url")
        }
    }

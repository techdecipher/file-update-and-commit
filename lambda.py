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
        r'{[\s\S]*?Sid\s*=\s*"ProjectAccess"[\s\S]*?Principal\s*=\s*{\s*AWS\s*=\s*"([^"]+)"\s*}[\s\S]*?Action\s*=\s*\[[^\]]*?\][\s\S]*?Resource\s*=\s*"arn:aws:s3:*

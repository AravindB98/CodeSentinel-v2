# Language-Specific Vulnerability Patterns
# Format: PATTERN_ID|||TITLE|||LANGUAGE|||BODY

PY-01|||Python SQL Injection via f-string|||python|||Any SQL query constructed using an f-string with a user-controlled value is vulnerable to SQL injection. Example red flag: cursor.execute(f"SELECT * FROM users WHERE id = {user_id}"). The fix is always the parameterized form: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,)) for psycopg2 or similar placeholder syntax for sqlite3 (?) and MySQL (%s). String formatting (".format()") and string concatenation are equivalent red flags. CWE-89.

PY-02|||Python pickle.loads on Untrusted Data|||python|||pickle.loads on any data that came from a network request, file upload, cookie, or any user-controlled source is a remote code execution vulnerability. The pickle format is a Python virtual machine program that can invoke arbitrary functions during deserialization. Replace with JSON and an explicit schema, or use signed tokens via itsdangerous.URLSafeSerializer if you need to round-trip application state. CWE-502.

PY-03|||Python subprocess shell=True with user input|||python|||subprocess.Popen, subprocess.run, os.system with shell=True and any user-controlled argument is OS command injection. Fix: pass the command as a list of arguments (shell=False is the default when passing a list), and validate the user input against an allow-list if it is part of the command structure. CWE-78.

PY-04|||Python eval or exec on Untrusted Input|||python|||eval, exec, and compile on any user-derived string is code injection. Python has no safe sandboxing built in; AST-based restriction is hard to get right. Replace with explicit parsing, an allow-list of operations, or a library like simpleeval for arithmetic. CWE-94.

PY-05|||Python Hardcoded Secret|||python|||A literal API key, password, or token in source code is a credential leak even if the repository is private. Load from environment variables (os.environ), a .env file read via python-dotenv, or a secrets manager. Add a .gitignore entry for any env file. If a credential has ever been committed, rotate it. CWE-798.

PY-06|||Python requests with verify=False|||python|||requests.get(url, verify=False) or any HTTP call that disables TLS verification is a man-in-the-middle vulnerability. Fix: remove verify=False, or pass verify=/path/to/ca-bundle.crt if you need a custom CA. CWE-295.

PY-07|||Python yaml.load without SafeLoader|||python|||yaml.load(data) without a Loader argument is deprecated and unsafe; it can invoke arbitrary Python constructors. Use yaml.safe_load(data) or yaml.load(data, Loader=yaml.SafeLoader). CWE-502.

PY-08|||Python MD5 or SHA1 for Security|||python|||hashlib.md5() or hashlib.sha1() used for password hashing, token generation, or any security-relevant purpose is a broken algorithm choice. For passwords use bcrypt, argon2, or scrypt via the passlib library. For other integrity use SHA-256 or SHA-3. MD5 is acceptable only for non-security use such as cache keys. CWE-327.

JS-01|||JavaScript eval on User Input|||javascript|||eval() on any string derived from user input is code injection. Same applies to new Function() and setTimeout with a string first argument. Replace with explicit parsing. CWE-94.

JS-02|||JavaScript SQL Injection via Template Literal|||javascript|||db.query(`SELECT * FROM users WHERE id = ${userId}`) is SQL injection. Use parameterized queries: db.query("SELECT * FROM users WHERE id = ?", [userId]) or the equivalent in your driver. CWE-89.

JS-03|||JavaScript Prototype Pollution|||javascript|||Mass-assignment of user input into an object via Object.assign, spread operator, or lodash.merge without field filtering can pollute Object.prototype with attacker-controlled values. Fix: use an allow-list of expected fields, or use Map instead of plain objects for dynamic key-value stores. CWE-915.

JS-04|||JavaScript innerHTML with User Content|||javascript|||element.innerHTML = userContent is XSS. Fix: use textContent for plain text, or DOMPurify.sanitize for HTML that must preserve formatting. In React, {userContent} inside JSX is auto-escaped and safe; dangerouslySetInnerHTML re-introduces the risk. CWE-79.

JS-05|||Node.js child_process.exec with User Input|||javascript|||exec and execSync pass their argument to a shell. User input in the command string is OS command injection. Use execFile or spawn with an argument array and validate inputs. CWE-78.

JAVA-01|||Java JDBC String Concatenation|||java|||Statement stmt = con.createStatement(); stmt.executeQuery("SELECT * FROM users WHERE id = " + userId) is SQL injection. Use PreparedStatement with placeholders. CWE-89.

JAVA-02|||Java ObjectInputStream on Untrusted Input|||java|||new ObjectInputStream(input).readObject() on data from an untrusted source is remote code execution via Java deserialization gadgets. Switch to JSON with a well-defined schema (Jackson with a limited object mapper), or sign and verify serialized objects. CWE-502.

JAVA-03|||Java Runtime.exec with String|||java|||Runtime.getRuntime().exec(userString) tokenizes on whitespace and is vulnerable to injection if user input is embedded. Use ProcessBuilder with an explicit argument list. CWE-78.

JAVA-04|||Java XXE in Default XML Parsers|||java|||DocumentBuilderFactory and SAXParserFactory in their default configuration allow external entities, enabling XXE attacks. Explicitly disable: factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true). CWE-611.

PY-09|||Python Flask Debug Mode in Production|||python|||app.run(debug=True) enables the Werkzeug interactive debugger, which exposes a PIN-protected console that can execute arbitrary Python in the server process. Never enable debug mode in production; gate it behind an environment variable that is false by default. CWE-489.

JS-06|||JavaScript Prototype Pollution via Object.assign|||javascript|||Object.assign({}, req.body) or recursive merges of untrusted JSON can write to __proto__ and pollute Object.prototype, leading to denial of service or remote code execution downstream. Validate and allow-list keys, reject __proto__/constructor/prototype, or use a null-prototype object. CWE-1321.

JS-07|||JavaScript Hardcoded Secret|||javascript|||A literal apiKey, token, secret, or password assigned in source (including front-end bundles) is a credential leak. Load from environment variables or a secrets manager and rotate anything committed. CWE-798.

GO-01|||Go SQL Injection via Sprintf|||go|||db.Query(fmt.Sprintf("SELECT * FROM t WHERE id = %s", id)) or string concatenation in a query is SQL injection. Use parameterized queries with placeholders: db.Query("SELECT * FROM t WHERE id = $1", id). CWE-89.

GO-02|||Go Command Injection via exec.Command shell|||go|||exec.Command("sh", "-c", userInput) or exec.Command("bash", ...) runs input through a shell. Invoke the target binary directly with explicit arguments and never pass a shell. CWE-78.

GO-03|||Go TLS InsecureSkipVerify|||go|||tls.Config{InsecureSkipVerify: true} disables certificate validation and enables man-in-the-middle attacks. Never set it in production; configure a proper RootCAs pool if a custom CA is required. CWE-295.

GO-04|||Go Weak Hash MD5 or SHA1|||go|||md5.New() or sha1.New() for passwords, tokens, or integrity in a security context is a broken algorithm choice. Use crypto/sha256 or stronger; for passwords use bcrypt or argon2. CWE-327.

RB-01|||Ruby Command Injection via Interpolation|||ruby|||system("cmd #{params[:x]}"), backticks, %x(), and exec with interpolated user input are OS command injection. Pass arguments as an array (system("cmd", arg)) and never interpolate untrusted input into a shell string. CWE-78.

RB-02|||Ruby eval on Untrusted Input|||ruby|||eval, instance_eval, class_eval, and send with user-controlled strings are code injection. Replace with explicit dispatch over an allow-list of permitted methods. CWE-94.

RB-03|||Ruby YAML.load Deserialization|||ruby|||YAML.load(user_input) can instantiate arbitrary Ruby objects and lead to remote code execution. Use YAML.safe_load with an explicit permitted-classes list. CWE-502.

PHP-01|||PHP SQL Injection from Superglobal|||php|||mysqli_query($c, "... " . $_GET['id']) or any query built from $_GET/$_POST/$_REQUEST is SQL injection. Use prepared statements with bound parameters via PDO or mysqli. CWE-89.

PHP-02|||PHP Command Injection from Request|||php|||system, exec, shell_exec, passthru, and popen called with $_GET/$_POST data are OS command injection. Avoid shells; if unavoidable, use escapeshellarg on every argument. CWE-78.

PHP-03|||PHP eval on Dynamic Input|||php|||eval($userControlled) executes arbitrary PHP. There is no safe way to eval untrusted input; restructure the logic to avoid it. CWE-94.

PHP-04|||PHP File Inclusion from Request|||php|||include/require with a path from $_GET/$_POST enables local and remote file inclusion and code execution. Use a fixed allow-list mapping request values to known file paths. CWE-98.

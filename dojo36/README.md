# Chaining SQL injection (CWE-89) and  filters bypass to get OS command injection (CWE-78) with octal encoding

## DESCRIPTION

In this dojo, two vulnerabilities are chained together to achieve OS command injection on the remote server :
- **SQL injection ([CWE-89](https://cwe.mitre.org/data/definitions/89.html)) :** user input used in an SQL query is not sanitized properly, allowing the user to control the output at a certain level.
- **OS command injection ([CWE-78](https://cwe.mitre.org/data/definitions/78.html)) :** user input used in an OS command is not sanitized properly, allowing the user to execute arbitrary command on the OS of the remote server.

Chained together, those two vulnerabilities allow an attacker to gain remote code execution (RCE) on the server, which could later lead to information disclosure and denial of service.
## EXPLOITATION

This dojo consist of a web application allowing us to check if a domain or an IP address is alive using the `ping` command.

### 1. Code analysis

The application use python to process user input and execute commands. The database used is a SQLite one (we can know this by checking the `import` in the code).
To better understand it, we need to follow the user input through the code to see where it's processed.

**User input :**
```python
# User input
cmd = unquote("<USER_INPUT>")
token = unquote("<USER_INPUT>")

# Get user that holds the given token
r = cursor.execute('SELECT username FROM users WHERE token LIKE ?', (token,))
try:
    user = r.fetchone()[0]
except:
    user = "test"

command = Command(cmd, user)
try:
    result = command.Run()
except Exception as e:
    result = f'command was not executed, error : {e}'
```

In this first part, we can see :
- The server try to find the user related to the token with give him with the parameter `token` using a SQL `LIKE` filter (this is important, we'll comeback later).
- If no user is found, the server fallback to the `"test"` user.
- It then try to run the commands with the given `cmd` parameter and the selected user. To better understand how to find the vulnerability, we will focus on the `Run()` method of the class `Command` 

**Command sanitization and execution :**
```python
def Run(self):
	if self.user == "dev":
		cmd_sanitize = self.PreProd_Sanitize(self.command)
	else:
		cmd_sanitize = self.Prod_Sanitize(self.command)

	# At the moment we don't have internet access.
	# We should only ping localhost to avoid server timeout
	result = subprocess.run(["/bin/ash", "-c", f"ping -c 1 {cmd_sanitize}"], capture_output=True, text=True)
	if result.returncode == 0:
		return result.stdout
	else:
		return result.stderr

def Prod_Sanitize(self, s:str) -> str:
	return shlex.quote(s)

def PreProd_Sanitize(self, s:str) -> str:
	"""My homemade secure sanitize function"""
	if not s:
		return "''"
	if re.search(r'[a-zA-Z_*^@%+=:,./-]', s) is None:
		return s
	return "'" + s.replace("'", "'\"'\"'") + "'" 
```

This is where it get interesting :
- We can see the server does not sanitize the command the same way depending on the user :
	- if the user is `"dev"`, the server use an homemade function using regex matching
	- else it use the well known function [`shlex.quote()`](https://docs.python.org/3/library/shlex.html#shlex.quote).
- Once the command has been sanitized, it then run it using `subprocess.run` as a shell command and return the output to display it on the web page. The shell command is :
```sh
ping -c 1 <user_input>
```

If we take a closer look at the homemade sanitization function, we can find the error design in the regex pattern :
```python
if not s:
	return "''"
if re.search(r'[a-zA-Z_*^@%+=:,./-]', s) is None:
	return s
return "'" + s.replace("'", "'\"'\"'") + "'" 
```
If you never used regex, it's powerful tool used to match pattern in strings.
This particular regex try to match any of the following characters : `a-zA-Z_*^@%+=:,./-`.
If none of the specified characters are found, the function return the input **not modified**. Else it add single quote `'` at start and end of the command, which would cancel any command injection attempt.
So if we could find a way to execute commands without using any of the characters in the regex pattern, we could achieve command injection/

We now see the path we need to follow to get OS command injection :
- Find a way to access the user `"dev"` in order to use the homemade sanitization function
- Find a way to execute shell commands without using letters and all the characters in the regex.

### 2. SQL injection to access user "dev"

In order to access the user `"dev"`, we first need a way to find out what user is being used. The easiest way to do that is to find a payload that would not be quoted if the function used is the homemade one. 
For example the following command `;1234` would not be matched by the regex as it doesn't contains any of the characters  `a-zA-Z_*^@%+=:,./-`.
And the final command would look like :
```shell
ping -c 1 ;1234 # use ; to chain shell commands
```
So if we get an error about the `1234` not found, that means we successfully accessed the `"dev"` user.

To access another user, we need to focus on the `token parameter`.
For reminder, the query executed is :
```sql
SELECT username FROM users WHERE token LIKE '<token>'
```
The server use prepared statements using placeholder `?`, which mean is not vulnerable to SQL injection (we cannot escape the quotes).
However, we are in a `LIKE` statement, meaning we can inject specials characters that would be interpreted by the `LIKE` operator.

If we follow the [documentation](https://www.sqlitetutorial.net/sqlite-like/), we can find this interesting information :

>SQLite provides two wildcards for constructing patterns. They are percent sign % and underscore _ :
>
> 1. The percent sign % wildcard matches any sequence of zero or more characters.
> 2. The underscore _ wildcard matches any single character.

Now if take a look back to the code, we see that in case of error, the server default to the `"test"` user (the one we are trying to avoid) :
```python
try:
    user = r.fetchone()[0]
except:
    user = "test"
```

So, we can guess that the `"test"` user doesn't have a token in the database, meaning we need to try to match any non-empty token. 
This can be done in a `LIKE` query with the pattern `_%` :
- `_` : the first character must not be empty
- `%` : anything else after the first character

So let's try using `token=_%` and `cmd=;1234` :

**First, with the test user :**
![](dojo36/img/ywh-1.png)
*We get a "bad address" error, which is expected as it's used with ping*

**Now with the special token :**
![](dojo36/img/ywh-2.png)
*We get the "1234: not found", meaning we successfully access the "dev" user and the server tried to execute our command*

So now that we have accessed the `"dev"` user, we need to find a way to execute shell commands without using letters...

### 3. Octal encoding to get command injection

if we take a look at shell escape sequences, we find that bash and other shells accept [ANSI-C quoting](https://www.baeldung.com/linux/bash-escape-characters#3-ansi-c-combinations). Meaning we can use shell command using encoding like `hex` or `octal`.
`hex` encoding use the letter `x`, so this would be flagged by the regex.
However, `octal` encoding use the following pattern :
> \nnn : the eight-bit character whose value is the octal value nnn (one to three octal digits) 

So if we convert `whoami` to base 8 (octal), we get : `\167\150\157\141\155\151`
And by using `$''` encapsulation, we should get the result of the `whoami` command :

![](dojo36/img/ywh-3.png)

We can automate the process of payload creation using a simple python script :
```python
payload = input("> ")
encoded = [oct(ord(c)) for c in payload]
epayload = "".join(encoded).replace('0o','\\').replace('\\40','\' $\'')
print(f"$'{epayload}'")
```
![](dojo36/img/ywh-4.png)

*Spaces must be replaced by real spaces and not the octal representation of space*

And this payload only use numbers, `$`,`'` and `\`, it doesn't match any of the characters of the regex function (`a-zA-Z_*^@%+=:,./-`).

So let's try to get the result of the `id` command :
![](dojo36/img/ywh-5.png)

And it worked ! We successfully bypassed the filters and gained OS command injection on the server.
## POC

By linking the SQL filters injection and the octal encoding to bypass the sanitization function, we are able to execute commands on the server and read the flag :

**1. First, encode the command :**

![](dojo36/img/ywh-6.png)
```sh
$'\143\141\164' $'\57\164\155\160\57\146\154\141\147\56\164\170\164'
```
**2. Then, using the right token filters (`_%`) and the payload, read the content of the flag :**
![](dojo36/img/ywh-7.png)

> Flag : `FLAG{W3lc0me_T0_Th3_Oth3r_S1de!}`

## RISKS

This kind of vulnerability is often very critical, as it can lead to total server compromise. With direct access to the server file system, an attacker can retrieve other users data and manipulate services, which could lead to information disclosure and denial of service.

In this case, an attacker could retrieve the content of the database and delete files to stop the services, or add information stealing code to the application.

## REMEDIATION

The protect against this vulnerability, the following measures should be followed :
- Don't use `LIKE` operator, but exact matching with `=`. That way only a user with the full and exact token can access the `"dev"` user.
- If you must use `LIKE`, filter out any token using characters like `%` or `_` to avoid filters injection.
- Regarding sanitization, defaulting to the function `shlex.quote()` would be enough to invalid command injection attempts.
- if you must use regex, also filters out characters like `$;{}\`, which are never used in a domain name of IP address, and would cancel any attempt to shell encoding. 

As always, thanks to Owne and Brumens for the fun challenge, and see you in the next one.

#### #YesWeRHackers
## REFERENCES

- https://cwe.mitre.org/data/definitions/89.html
- https://cwe.mitre.org/data/definitions/78.html
- https://docs.python.org/3/library/shlex.html#shlex.quote
- https://www.sqlitetutorial.net/sqlite-like/
- https://www.baeldung.com/linux/bash-escape-characters#3-ansi-c-combinations
- https://www.gnu.org/software/bash/manual/html_node/ANSI_002dC-Quoting.html
- https://github.com/welchbj/ctf/blob/master/docs/injections.md#bypassing-extreme-character-blacklists

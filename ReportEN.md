<div dir="ltr">

# Four Security Vulnerabilities Report

Peace be upon you and the mercy of Allah and His blessings.

In this report, I will discuss the most important part where website vulnerabilities usually occur, which is **user input**. In other words, what the user sends to you and how you handle their message. From an initial perspective, the topic may seem simple, but it's more dangerous than you might expect. Let me give you an example to clarify the picture.

There is a login page that requires two elements to access the account privileges. The first element is the unique identifier that distinguishes the user such as (National ID, unique username, anything that cannot be duplicated), and the password that allows you to access the user's privileges. This is the visible part to the user. As for the hidden part, it is the **dangerous zone** that gives approval or rejection. Well, if the verification process was simple, taking the user's values and comparing them with the values in the database, you might not see anything dangerous. But what you don't see is that the verification can be bypassed, or it could be worse, such as retrieving information that you don't want to appear, and there are many examples of this.

This is considered a somewhat simple example. But in other cases, such as relying on data sent to the user after logging in, called **session identifiers (cookies)**, and these identifiers' function is to remind the website of the user's identity and permissions, and the user can easily change them. This is a dangerous point and I will address it later.

Now we've taken examples of problems that can occur due to relying on user input. So now I'll build a simple website about a digital library where books are reserved. Just a simple website with an even simpler idea. We have two types of users: first, the book beneficiary, and second, the library administrator who organizes reservations for all users. Anyone can view the books, but only those with an account can make reservations. Anyone can view only their own reservations, and anyone can create a regular account and log in normally. This is generally the website's functions.

Now we have four vulnerabilities that I'll explain with practical application on each one from the digital library website, which are as follows:

---

## The Four Vulnerabilities

1. Authentication system flaw
2. SQL injection vulnerability
3. Cross-Site Scripting (XSS) vulnerability
4. Cookie manipulation

---

## 1. Authentication System Flaw

First, the vulnerability is bypassing the verification process. Before we get into the vulnerability, let me explain the concept of authentication, which is the process of verifying a person. It has several methods, the most famous of which is through username and password (which is implemented in the application), using biometric markers (such as facial recognition and others), and another method using a phone call, and many others. The information is verified from the user database.

To exploit or break the authentication process, there are many methods, including brute force (choosing a username and trying many passwords), also eavesdropping on the HTTP protocol, and also through SQL command injection, which we will use in this vulnerability, and there are other methods.

### Exploitation Process via SQL Command Injection

Initially, we enter the main page and search for the login page.

![Screenshot showing the login page](photo/the%201.png)

Now we inject the command:

```sql
' OR 1=1 --
```

This command's task is to bypass the password verification process. We must know the name of one of the users, and the most famous user is `admin`. In the password field, anything works because we will bypass it.

![Screenshot showing command injection](photo/the%202.png)

And now I'm in the admin account (system administrator) with all his privileges.

### Root Cause

The cause of this vulnerability is that there is no filtering of user input and not using prepared statements, especially in this code:

```javascript
const TheRseultFROMsql = db.prepare(`SELECT * FROM users WHERE username = '${req.body.username}' AND password_hash = '${req.body.password}'`).get()
```

### Solution

The solution is to use this code:

```javascript
const sqlStatmentToGetINFO = db.prepare("SELECT * FROM users WHERE username = ?")
const TheRseultFROMsql = sqlStatmentToGetINFO.get(req.body.username)
```

And then verify the password separately.

**Summary of protection from this vulnerability:** Distribute verification operations and ensure that user inputs are free from any control codes.

---

## 2. SQL Injection Vulnerability

Second, SQL command injection. First, what is SQL? It's a query language for databases. With this language, you can build tables, delete tables, modify tables, add data, delete data, as well as modify data, and it can display data.

Now the exploitation process depends on the type of variable, whether it's a number, text, or boolean value (true or false). These are the values sent to the query. To exploit this step, we must send commands outside the variable. In text variables, it's done by adding a single quote (`'`), and in numbers, it's done by adding a space.

### Practical Application

In the application I developed, I exploit the vulnerability at a simple point, which is retrieving all reservations for all people without using admin (administrator) privileges.

First, we enter the books page because it has a search field. We try to guess the table name.

It became clear that the table name is `reservations`.

Now we inject this query:

```sql
A' AND 1=0 UNION SELECT NULL AS A, NULL AS c, NULL AS f, * FROM reservations --
```

![Screenshot showing injection](photo/the%203.png)

![Screenshot showing results](photo/the%204.png)

And this is the response. As you notice, all the data from the reservations table is now in my hands, from dates, status, quantity, and the requester's ID.

### Root Cause

In this vulnerability, the attacker exploited SQL query operations due to lack of input filtering and executing them directly:

```javascript
const sqlstatment_return_info_of_book = db.prepare(`SELECT * FROM books WHERE title LIKE '%${req.params.query}%'`).all()
```

### Solution

First, use code to filter inputs, use prepared statements, and don't send variables directly:

```javascript
if (typeof req.params.query !== "string") req.params.query = ""
req.params.query = sanitizeHTML(req.params.query.trim(), {allowedTags: [], allowedAttributes: {}})
if (!req.params.query) errors.push("you must add query")

const sqlstatment_return_info_of_book = db.prepare("SELECT * FROM books WHERE title LIKE ?")
const result_theinfo_of_book = sqlstatment_return_info_of_book.all(`%${req.params.query}%`)
if(!result_theinfo_of_book) errors.push("not found the book")
```

---

## 3. Cross-Site Scripting (XSS) Vulnerability

Third, XSS vulnerability is injecting malicious scripts (such as JavaScript) that are executed in the victim's browser. It has three basic types: stored, reflected, and DOM-based. In this report, I'll talk about reflected XSS for its speed and clarity, which is injecting JavaScript code that is displayed immediately.

### Practical Application

Now I'll apply a very simple exploitation operation, which is displaying an alert on the screen, which is definitive proof of the vulnerability's existence. The goal is to execute the `alert` command. But first, we must find a field in the application through which I can send any normal value and then apply it to the page, such as a name or search operation, and we will find what we need on the books page.

![Screenshot showing search field](photo/the%205.png)

![Screenshot showing the page](photo/the%206.png)

Now I found the best place to verify the vulnerability's existence. Then we inject this command:

```html
p' --"><img src="x" onerror="alert('Adel almquti')">
```

Then press the search button.

![Screenshot showing alert](photo/the%207.png)

This is strong evidence of the vulnerability's existence. The cause of its occurrence has more than one way. Some ways are due to the back-end, and another cause is due to the front-end. As for the website's problem, it's due to both parts. How?

Let me tell you: because the website takes the inputs and sends them to the server, and the server returns the inputs and results, and only what the server sent is displayed.

There are websites that display inputs immediately without returning from the server, and this is not recommended from a security perspective.

### Solution

So to close this vulnerability in my website, first filter and sanitize inputs from any scripts or malicious code and encode the outputs. The best way is to use this code:

```javascript
if (typeof req.params.query !== "string") req.params.query = ""
req.params.query = sanitizeHTML(req.params.query.trim(), {allowedTags: [], allowedAttributes: {}})
```

---

## 4. Cookie Manipulation

The last vulnerability is manipulating session cookies. Before I explain the vulnerability, let me explain what cookies are and what their benefit is. Cookies are data automatically given to users, and they are information that distinguishes each user and contains information specific to the user such as the ID and other things. One of their most important benefits is that the website doesn't forget the user. Meaning, if the user logs out, their temporary data is not deleted if they log in again, such as cart items and others.

As for the vulnerability, it focuses on changing sensitive data or stealing complete cookies from important people (such as the system administrator). The change process focuses on important variables such as (`is_admin`, `ID`, `userName`, and others).

### Practical Application

To apply it on the website, open Burp Suite program and go to the login request.

![Screenshot showing Burp Suite](photo/the%208.png)

![Screenshot showing request](photo/the%209.png)

After the login process, we notice the cookie value, and it contains sensitive values, the first of which is `userid`. It's so obvious it doesn't even need decoding.

![Screenshot showing cookie values](photo/the%2010.png)

Now we just change the `userid` value and set it to zero, and I will get all admin privileges. This is due to relying on cookie values, and originally this is considered a value from the user, so you should never rely on these values.

![Screenshot showing admin access](photo/the%2011.png)

### Root Cause

The main reason for this problem is that cookie signing was not done. (Signing means that the values in the cookies will not change except from the server only.) For signing, there are simple steps which is using JWT, and this is the dedicated code to solve this vulnerability. It's important to verify values from the server side and never rely on cookies for sensitive data.

```javascript
const bigValueToken = jwt.sign({
    exp: Math.floor(Date.now() / 1000) + 60 * 24 * 60,
    userid: user.id,
    username: user.username
}, process.env.JWTSSS)

res.cookie("webisTheBest", bigValueToken, {
    httpOnly: true,
    secure: true,
    sameSite: "strict", // defense against CSRF attack
    maxAge: 1000 * 60 * 60 * 24
})
```

### Cookie Security Attributes

Regarding sending cookies, it has several values:

| Attribute | Value | Purpose |
|-----------|-------|---------|
| `httpOnly` | `true` | Protects from cookie theft via XSS vulnerability |
| `secure` | `true` | Cookies are sent only if HTTPS protocol is used |
| `sameSite` | `"strict"` | Protects from CSRF vulnerability which I didn't address in this report |
| `maxAge` | 1000 * 60 * 60 * 24 | Determines the cookie's lifetime |

---

## Conclusion

These four vulnerabilities represent critical security issues that arise from improper handling of user input. Protecting against them requires proper input validation, using prepared statements, and following security best practices.

</div>
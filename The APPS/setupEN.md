# Running the Website as Required

First, you need to know that it's not necessary to download many libraries - the process is very simple.

You currently have two websites: one with vulnerabilities and another with the vulnerabilities patched.

## Downloading the Vulnerable Version

If you need to test the vulnerabilities, you can download it using this command:

```bash
git clone https://github.com/adel511CY/Digital-Library/The%20APPS/web%20vulnerability
```

## Downloading the Secured Version

For the application secured from the four vulnerabilities, use this code:

```bash
git clone https://github.com/adel511CY/Digital-Library/The%20APPS/web
```

---

## Installation Steps

After these steps, enter the folder either "web%20vulnerability" or "web" or both if you downloaded them both, using the command:

```bash
cd web%20vulnerability
```

OR

```bash
cd web
```

### Important: Setting File Permissions

There's a very important point which is giving some permissions to the files using these commands:

```bash
chown -R $USER:$USER .
```

```bash
chmod -R 755 .
```

### Installing Dependencies

Then execute the following command:

```bash
npm install
```

---

## Additional Steps for Secured Application

Now, if you downloaded the secured application, you must follow some steps as follows:

1. Create a file named `.env`
2. Then add the following variable: `JWTSSS="any value you like"`

---

## Running the Website

Now the method to run the website is as follows using the following command:

```bash
node server
```

Now you can go to:

```
http://localhost:3000/
```
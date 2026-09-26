# Please read this before moving on

This is a **simple, step-by-step guide** to this project. Every step is written in plain words.
You do not need to know anything about programming to follow it, just a terminal and about ten
minutes.

If you only do one thing, do **Part 1**. It gets the app running on your screen.

---

## What this project is

It is a **web app for controlling remote computers**, built by a team, where more than one company
uses it at the same time.

Imagine two companies, Acme and Globex. They both use this same app. Each has its own machines
(laptops, servers, phones), its own people, and its own rules. **Acme must never see Globex's
machines. Not one machine. Not one name.** Keeping those two worlds apart is the main job of this
project, and almost everything here exists to protect that.

Each company has **people with different levels of access**. Someone might be able to see every
machine, someone might only be allowed to watch, someone might be able to do anything at all. The
app decides what each person is allowed to do, every single time they click something.

---

## What you need first

| What | Why | How to check |
|---|---|---|
| **Node.js version 22** | The program is written in JavaScript, and Node.js is what runs it. | Open a terminal and type `node -v`. If it says `v22` or higher, you are ready. |
| **A terminal** | The window where you type commands. On a Mac use Terminal; on Windows use PowerShell. |, |
| **About 10 minutes** | Mostly waiting for things to install. |, |

If `node -v` says something lower than 22, or says "command not found", you need to install
Node.js from [nodejs.org](https://nodejs.org) first.

---

# Part 1, Get it running

You type each line into your terminal, one at a time, and press Enter after each one.

### Step 1, Go into the project folder

```sh
cd remoteops
```

### Step 2, Install the pieces it needs

```sh
npm install
```

This downloads the parts the program needs. It takes a minute or two. You may see a lot of text
scroll past, that is normal, and it is supposed to look busy.

### Step 3, Load the sample data

```sh
npm run db:reset
```

The app comes with a pretend company full of pretend machines and people, so you have something to
look at. This step loads that pretend data.

You should see a list of things and their counts, ending with a few lines that tell you sample
sign-in details. **You did it right if you see the words `organizations=3` and `users=8`.**

### Step 4, Start the app

```sh
npm run dev
```

**The app is now running. Leave this window open**, closing it stops the app. You should see a line
that says `RemoteOps on http://localhost:8080`.

### Step 5, Open it in your browser

Go to this address in your web browser:

```
http://localhost:8080
```

You should see a sign-in form. **Stop here if you just want to look around**, the next part tells
you how to sign in.

---

# Part 2, Sign in

Every sample account uses the same password: **`demo1234`**

| Email to type | Password | Who they are | What they can do |
|---|---|---|---|
| `owner@acme.test` | `demo1234` | Acme's owner | Everything in Acme |
| `admin@acme.test` | `demo1234` | Acme's admin | Almost everything in Acme |
| `viewer@acme.test` | `demo1234` | Acme's viewer | Look only. Cannot change anything |
| `dana@example.test` | `demo1234` | Belongs to **both** companies | Owner in Acme, viewer in Globex |
| `sam@example.test` | `demo1234` | Belongs to **both** companies | Operator in Acme, auditor in Globex |
| `owner@globex.test` | `demo1234` | Globex's owner | Everything in Globex |

**Try this first, because it is the most interesting thing in the app:**

1. Sign in as `dana@example.test` / `demo1234`.
2. Look at the top of the screen. Dana is in **two** companies.
3. Switch between Acme and Globex. **Everything on the screen changes**, because the two companies
   have completely different people and machines.

Then sign in as `viewer@acme.test` and notice how **much less there is to click**. That is not
cosmetic, the buttons a viewer cannot use are not just hidden, the app also refuses to do the work
if you ask it directly. Hiding a button is a convenience. Refusing the work is the protection.

---

# Part 3, Check that it works

Four commands. Each one checks something different. Run them in your terminal (press `Ctrl+C` first
if the app is still running in that window, or use a second terminal window).

### 1. Does the program do what it is supposed to?

```sh
npm run check
```

This runs **551 checks** against the whole program.

**You did it right if the last line says `ALL PASS`** and every group says `0 failed`.

### 2. Is it safe from someone attacking it?

```sh
npm run audit
```

This pretends to be a **hacker** and tries 139 different attacks, such as:

- signing in without a password
- trying to read another company's data
- sneaking a dangerous command into a search box
- guessing passwords over and over
- looking for secret keys that should not be published

**You did it right if it says `AUDIT CLEAN`.**

### 3. Can someone steal a login by guessing?

```sh
npm run pentest
```

This is a smaller, nastier version of the same idea. It attacks the part of the app that decides who
you are.

**You did it right if it says `no breach`**, which means none of its attacks worked.

### 4. Does the screen actually work?

```sh
npm run build
npx playwright test
```

This opens a real web browser and pretends to be a person clicking through the app, 38 times. It
checks that buttons are there, that the right buttons are hidden, and that a wrong password shows a
friendly message.

**You did it right if it says `38 passed`.**

> **One note:** the first time you run this, it may stop and say the browser is missing. If so, run
> `npx playwright install chromium` once, then try again. If that download fails (it sometimes does
> on slow or blocked networks), the rest of this document still works, only this one check is
> affected.

---

# Part 4, Running it "for real"

Part 1 runs in **development mode**, which is a helper mode. It is fine for looking around, but it
is not safe to put on the internet.

For the real thing, the app insists on **three secret codes**. What a secret code is: a long random
string that only your server knows. It is like the combination to a safe. Someone who does not have
it cannot get in.

The app **refuses to start** without them. That is on purpose, it is much safer to fail to start
than to start with a guessable secret.

```sh
export JWT_SECRET=$(node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))")
export APP_HASH_KEY=$(node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))")
export PASSWORD_PEPPER=$(node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))")

npm run db:reset
npm run build
npm start
```

> **Keep the same three values if you come back later.** The lines above make a brand-new random
> secret each time you run them. That is right the first time. But if you run them **again** on a
> machine that already has sample data, the pepper will be different, the old passwords will stop
> matching, and nobody will be able to sign in. Either keep the three values somewhere safe, or run
> `npm run db:reset` again straight after, as shown above.

What each one is for, in one line each:

| Secret | What it protects |
|---|---|
| `JWT_SECRET` | The "you are logged in" tickets the app hands out |
| `APP_HASH_KEY` | The saved sign-in tokens |
| `PASSWORD_PEPPER` | Passwords. It is mixed in **before** the password is scrambled, so if someone steals the database, **the stolen passwords cannot be guessed at all** |

> **Keep the pepper safe.** If you lose it, nobody can sign in any more, and there is no way to
> recover it. Write it down somewhere safe, the same place you keep the other two.

---

# What's in the folder

Here is the whole project, explained.

### The parts you will use

| Folder or file | What it is |
|---|---|
| `web/` | The screen you look at. |
| `server/` | The part that makes decisions. Nobody sees this, it sits behind the screen. |
| `db/` | The shape of the data, and the list of what people are allowed to do. |
| `seed/` | The pretend companies, people and machines. |
| `scripts/` | The tools that check the app works. |
| `tests/` | The checks that drive a real browser. |
| `dist/` | The finished, built version of the screen. Made by `npm run build`. |

### The documents

| File | What it is for |
|---|---|
| **`START-HERE.md`** (this file) | Plain instructions. You are here. |
| `README.md` | The task as it was originally handed over. |
| `LAUNCH-GATE.md` | **A safety report.** Says what is protected, how it was tested, and what is *not* finished. Read this if you want to judge the work. |
| `BUILD-LOG.md` | A diary of every problem found and fixed, in order. |
| `DECISIONS.md` | Every choice that could reasonably have gone another way, and why it went this way. |
| `BRIEF.md`, `PERMISSIONS.md`, `AUTH-DATA-MODEL.md`, `UI-INVENTORY.md`, `WORKFLOW.md` | The task's own instructions. These were **not changed**. |

---

# How the main ideas work

You can skip this part if you just want to run the app. But it is short, and it explains why the
project is built the way it is.

### 1. The app always knows which company you are in

When you sign in, the app gives you a small **ticket** that says which company you are working in.
**The company comes from that ticket, never from the web address you typed.**

This is the important bit. If the company always came from the address bar, a person could simply
type someone else's company name into the address and be let in. Because it comes from the ticket
instead, the app is saying "you said you are in Acme, so we will only ever show you Acme", and if you
ask about Globex, the app answers as if Globex **does not exist**.

The app answers "nothing here" rather than "you are not allowed". That is deliberate: saying "you are
not allowed" would confirm that the thing you asked about is real.

### 2. People have roles

| Role | What they can do |
|---|---|
| `owner` | Everything. The person in charge. |
| `admin` | Nearly everything (18 of the 19 powers). |
| `reviewer` | A special extra role this project adds: look at 4 powers, including one special power. |
| `operator` | Work on machines: connect to them, run things, transfer files. 7 powers. |
| `auditor` | Read-only, plus the right to read the activity log. 5 powers. |
| `viewer` | Look only. 4 powers. |

The exact list lives in the database, not in the code. That is on purpose: if the list were written
into the program, there would be two copies of the rules, and they would eventually disagree.

Each role also has a **rank** (a number). A higher rank can change a lower rank's access, but not the
other way round. So an `admin` can promote a `viewer`, but an `admin` can never change an `owner`.
That rule is checked in one place, so every button that changes someone's access obeys it.

### 3. Permissions

There are 20 specific powers, like `device:terminal` ("open a terminal on a machine") and
`org:delete` ("delete the company"). Each role is given a set of them.

Two things can hand someone a power that their role does not have:

- **A grant**, someone with permission gives one person one extra power, optionally for one machine
  only, optionally with an end date.
- **A refusal**, someone takes a power away. A refusal always wins. This is checked first.

### 4. Sessions

If you press "connect to machine", the app records a **session**. A session has a time limit set by
your company's settings, and it is recorded in the log.

When someone's access changes, their sessions are **not** thrown away, but the app bumps a number
called a "version" on their account, and their old ticket stops working **the very next time they
click something**. So a change takes effect immediately, not whenever their ticket happens to expire.

### 5. The activity log

Every decision that changes access, and every refusal, is written to a list that **cannot be edited
or deleted**, the database itself refuses. So if something goes wrong, there is a record, and
nobody can quietly tidy it away.

---

# If something goes wrong

| What you see | What it means | What to do |
|---|---|---|
| `command not found: npm` | Node.js is not installed, or not in your path. | Install Node.js 22 from [nodejs.org](https://nodejs.org), then close and reopen the terminal. |
| `EADDRINUSE: address already in use :::8080` | The app is already running in another window. | That is fine, just open `http://localhost:8080`. Or find the other window and stop it with `Ctrl+C`. |
| `JWT_SECRET must be set when NODE_ENV=production` | You tried to run the real version without the three secret codes. | Do Part 4, or just use `npm run dev` instead. |
| `PASSWORD_PEPPER must be set...` | Same thing, the pepper is missing. | Do Part 4. |
| `password hashes reference pepper id "...", which is not configured` | The sample data was **created with a different pepper** than the one you are now running with. This only happens if you created the data twice with two different peppers, for example if you had one pepper set, made the data, then changed the pepper. | Create the data again with the pepper you are using: run `npm run db:reset` again **after** setting the three secrets. |
| `no such table: users` | The sample data was never loaded. | Run `npm run db:reset`. |
| A test says `0 failed` but you expected a failure | The tests are checking the *fixed* version. To see a real failure, break something on purpose and run the check again. | Not a problem, that is the tests working. |

---

# What is **not** finished

Being straight with you about this, because a list of loose ends is more useful than a claim of
perfection. The full version is in `LAUNCH-GATE.md`.

1. **There is no online alerting.** The activity log records everything, but nothing is watching it
   and nobody would get an email if something odd happened.
2. **There is no separate "test" copy of the app** out on the internet, and no automated system that
   runs the checks on every change. Everything runs when you run it, by hand.
3. **The security settings are not applied in development mode.** They are applied in the real
   version, which is the one that matters, but the setting is not being tested in day-to-day use.
4. **Three of the downloaded libraries are a major version behind.** No known security problem
   affects them; it is housekeeping, not a risk.
5. **Nobody has tested restoring the database from a backup after a real problem.** Rebuilding it
   from scratch is tested; recovering real data is not, because there is no backup process yet.

---

# The quickest possible version

If you read nothing else, do this:

```sh
cd remoteops
npm install
npm run db:reset
npm run dev
```

Then open **http://localhost:8080** and sign in as `owner@acme.test` with the password `demo1234`.

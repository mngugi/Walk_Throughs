
# Ethical Hacking — Chapter Notes

## Introduction

**Overview** · 2 min read

This chapter covers the mindset behind ethical hacking. You will learn to:
- Question what a system shows you
- Understand where the legal line sits
- Read a web page's source with tools your browser already has

It ends with a **skills assessment**.

### Structure

This chapter has **nine sections**:
- Each section covers one topic
- Each walks through one concrete example
- Closes with one practical question to check the idea stuck

Along the way you pick up the words professionals use, such as:
- `flag`
- `reconnaissance`
- `responsible disclosure`

> **In section 6** you capture your first flag, hidden on purpose in this very page's source.

---

## Requirements

| Item | Detail |
|------|--------|
| **You need** | A browser. Nothing to install. |
| **Difficulty** | No technical knowledge required |
| **Safety** | Every exercise uses your own browser, this page and fictional `.example` hosts. You touch nothing you do not own. |

---

## What You Will Learn

- The questioning mindset
- The line between hacking and crime
- How to read what a page hides

---

## Key Concepts

### Hacking (on this platform)

On this platform, **hacking** means *authorized testing*:
- You practise on targets that exist to be attacked
- You have permission before you start

### The Golden Rule

> The rule for this chapter is the one every professional follows: **you only test what you are invited to test.**

---

## Practical Skills Covered

1. **Read a page's source code**
2. **Open developer tools**
3. **Search a page for a word**

---

## Vocabulary

| Term | Meaning |
|------|---------|
| `flag` | A hidden string captured as proof of completion |
| `reconnaissance` | Information gathering before testing |
| `responsible disclosure` | Reporting vulnerabilities ethically to the owner |

---

## Summary

- Ethical hacking = authorized testing with permission
- Use only tools you already have (your browser)
- Stay legal: test only what you're invited to test
- Section 6 contains your first hidden flag in the page source

---

# What Ethical Hacking Is

**Lesson** · 3 min read

This section defines ethical hacking, shows where the legal line sits, and covers four words you will meet throughout this course.

---

## The Mindset

**Ethical hacking** means testing a system for weaknesses **with its owner's permission**, so the owner can fix them. It is a way of *reading* a system, and it comes before any tool.

A login page shows two boxes and a button. A hacker asks:
- What is the page **not** showing?
- What happens when a field gets a value the developer never expected?
- Who decided this button should be the only way in?

Behind every screen is a set of rules someone wrote, and each rule rests on an **assumption**. The builder may assume:
- That visitors only type what the form asks for
- That nobody reads the page source
- That a hidden button stays hidden

> Ethical hacking is the habit of questioning those assumptions in a careful order and writing down the ones that turn out to be wrong.

---

## The Legal Line

The skill is **not** illegal. Using it on a system you do not own, or have no permission to test, **is**.

> What decides it is **authorization**, not technique.

| Action | Legal? | Why |
|--------|--------|-----|
| Reading the source of a page you are visiting | ✅ Yes (everywhere) | The browser was given that code to display |
| Logging into someone else's account | ❌ No | Even with an easy-to-guess password |

In most countries **unauthorized access is a crime**, however curious you were.

The same action can be a **paid job** on one site and a **crime** on another. Written permission is the only difference.

---

## Vocabulary

| Term | Meaning |
|------|---------|
| **Flag** | A secret string you find by solving a challenge. Finding it proves you did the work. |
| **CTF** | Capture The Flag: a style of challenge where solving a puzzle reveals a flag. |
| **Practice platform** | A site like this one, where every target exists to be attacked. |
| **Bug bounty** | A company's public invitation to find flaws under written rules. Valid reports get paid. |

---

## Worked Example: What a Flag Looks Like

On HackerDNA, a flag is a **UUID**, which is a randomly generated identifier. Here is one:
---
# Methodology

**Lesson** · 3 min read

This section covers the method professionals follow: a **four-move loop** you repeat from minute to minute, and the **four stages** that organise a whole job. A one-week authorized test of a practice shop shows both at work.

---

## The Attacker's Loop

Almost every attack, from a first flag hunt to a million dollar bug bounty, follows the same four moves. Together they are called the **attacker's loop**. Experienced hackers rarely name them, because after a while they stop being steps and become a reflex.

1. **Observe** — look at the system. What does it show, and what does it hide?
2. **Question** — what did the builder assume? What happens at the edges of the rules?
3. **Test** — check one idea in the smallest way you can, and only on something you are invited to touch.
4. **Learn** — either it worked, or it showed you why not. Then you go round again, knowing more.

---

## The Four Stages of an Engagement

An **engagement** is one authorized testing job, with a client, a written scope and an end date. The loop runs hundreds of times during an engagement, and the work falls into four stages. Each stage hands something concrete to the next.

| Stage | What you do | What it produces |
|-------|-------------|------------------|
| **Reconnaissance** | Gather information before touching anything: read the source, follow every link, note what the site runs on | A map |
| **Enumeration** | Go deeper on what the map shows | Leads |
| **Exploitation** | Use a weakness to make the system do something it should not, and stop at the proof | Proof |
| **Reporting** | Write down what you found, how, why it matters and how to fix it | The report |

---

## Worked Example: One Week on shop.example

The owners of `shop.example` invite you **in writing** to test their website for one week. They give you a test account and a contact address for questions. Here are your notes at the end of the week:

---

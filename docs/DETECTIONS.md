# Detection catalog

Generated from the YAML files in `rules/`. Thresholds live in those files and are meant to be tuned.

## SEN-001: SSH brute force

| | |
|---|---|
| Severity | high |
| ATT&CK | T1110.001 Brute Force: Password Guessing (Credential Access) |
| Logic | 8 or more events per `src_ip` within 120s |

Many failed SSH logins from one source address in a short time.

**In plain English:** Someone standing at your front door trying key after key. One wrong key is a mistake. Eight wrong keys in two minutes is a burglar with a key ring.

**Could be innocent when:**

- A misconfigured script or backup job retrying a stale password
- A vulnerability scanner run by your own security team

**Response:**

1. Confirm none of the attempts succeeded (see SEN-003)
2. Block the source address at the perimeter
3. Check whether the targeted usernames are real accounts, which suggests a leaked user list
4. Move SSH behind a VPN or require key-based authentication

## SEN-002: Password spraying

| | |
|---|---|
| Severity | high |
| ATT&CK | T1110.003 Brute Force: Password Spraying (Credential Access) |
| Logic | 6 or more distinct `user` values per `src_ip` within 600s |

One source tries to log in as many different users, a few attempts each.

**In plain English:** Instead of trying 1,000 keys on one door, the burglar tries one common key ("Summer2026!") on 1,000 doors. Each door only sees one attempt, so lockout counters never trip. You only see it by watching the whole street.

**Could be innocent when:**

- A jump host or NAT gateway that many real users share

**Response:**

1. Identify which accounts were targeted and force a reset for any with weak passwords
2. Block the source address
3. Check identity provider logs for the same source

## SEN-003: Successful login after repeated failures

| | |
|---|---|
| Severity | critical |
| ATT&CK | T1078 Valid Accounts (Initial Access) |
| Logic | 5 or more matching events, then a follow-up event, same `src_ip`, within 900s |

A source that failed SSH authentication several times then logged in successfully.

**In plain English:** The burglar tried a ring of keys, and then the door opened. The failures were noise. The success is the emergency, because now they are inside.

**Could be innocent when:**

- A real user who forgot their password and eventually remembered it

**Response:**

1. Treat the account as compromised. Disable it and kill its active sessions
2. Review everything that account did after the successful login
3. Reset the credential and look for new SSH keys, cron jobs, or accounts
4. Block the source address

## SEN-004: SQL injection attempt

| | |
|---|---|
| Severity | high |
| ATT&CK | T1190 Exploit Public-Facing Application (Initial Access) |
| Logic | Single matching event |

A web request whose decoded URL contains SQL injection syntax.

**In plain English:** A form asks for your name and you write "Bob, and also hand me everyone's file." If the clerk reads that aloud to the records room without thinking, they hand the files over. SQL injection is slipping commands into a field that expected plain data.

**Could be innocent when:**

- Security training content or blog posts that discuss SQL in the URL
- An authorized penetration test

**Response:**

1. Check the response status and size. A 200 with an unusually large body may mean it worked
2. Confirm the application uses parameterized queries on that endpoint
3. Block or rate limit the source, and add a WAF rule

## SEN-005: Cross-site scripting attempt

| | |
|---|---|
| Severity | medium |
| ATT&CK | T1190 Exploit Public-Facing Application (Initial Access) |
| Logic | Single matching event |

A web request whose decoded URL contains script injection syntax.

**In plain English:** Pinning a fake notice on the office bulletin board. The building trusts the board, so everyone who reads it follows the fake instructions. XSS plants attacker code on a site so that visitors' browsers run it.

**Could be innocent when:**

- Developers testing input handling

**Response:**

1. Check whether the payload is reflected back unescaped
2. Verify output encoding and the Content Security Policy on the page

## SEN-006: Path traversal attempt

| | |
|---|---|
| Severity | high |
| ATT&CK | T1190 Exploit Public-Facing Application (Initial Access) |
| Logic | Single matching event |

A web request trying to climb out of the web root to read system files.

**In plain English:** You ask the librarian for a book "three shelves back, out the door, down the hall, in the manager's office." The ../ trick walks out of the public folder and into places the website was never meant to serve.

**Could be innocent when:**

- Rare. Legitimate URLs almost never contain ../ after decoding

**Response:**

1. Check the response status. A 200 on /etc/passwd is a confirmed file read
2. Patch or fix path handling on the affected endpoint

## SEN-007: Known attack tool user agent

| | |
|---|---|
| Severity | low |
| ATT&CK | T1595.002 Active Scanning: Vulnerability Scanning (Reconnaissance) |
| Logic | Single matching event |

A web client identifying itself as a common scanning or exploitation tool.

**In plain English:** A stranger walking your fence line in a jacket that says "LOCKPICK CLUB." Careless attackers leave the tool's default name on. Skilled ones change it, so this is a cheap early warning, never proof of safety.

**Could be innocent when:**

- Your own vulnerability management scans

**Response:**

1. Low priority alone. Raise the priority if the same source triggers other rules

## SEN-008: Web directory enumeration

| | |
|---|---|
| Severity | medium |
| ATT&CK | T1595.003 Active Scanning: Wordlist Scanning (Reconnaissance) |
| Logic | 25 or more events per `src_ip` within 60s |

A burst of 404 responses to one client, typical of wordlist-driven content discovery.

**In plain English:** Someone walking down a hotel corridor trying every door handle. Most are locked (404), but they are building a map of which ones are not.

**Could be innocent when:**

- A broken deployment that makes real assets return 404
- Search engine crawlers hitting stale links

**Response:**

1. Review which paths returned 200 to this client. Those are what it found
2. Rate limit the source

## SEN-009: Port scan

| | |
|---|---|
| Severity | medium |
| ATT&CK | T1046 Network Service Discovery (Discovery) |
| Logic | 15 or more distinct `dst_port` values per `src_ip` within 60s |

One source blocked by the firewall on many different destination ports.

**In plain English:** A building has 65,535 windows. A port scan is someone walking around tapping on each one to learn which are open and what is behind them.

**Could be innocent when:**

- Authorized vulnerability scans
- Peer-to-peer software

**Response:**

1. Check which ports the firewall ALLOWED for this source, since that is what the scan found
2. If the source is internal, treat it as a possibly compromised host mapping the network

## SEN-010: Large outbound transfer to external host

| | |
|---|---|
| Severity | high |
| ATT&CK | T1048 Exfiltration Over Alternative Protocol (Exfiltration) |
| Logic | Single matching event |

An internal host sent more than 500 MB to an address outside the network in one connection.

**In plain English:** The alarm that matters in a bank is the one on the way OUT. Staff carry envelopes out all day. Someone wheeling out a pallet at 3am is different.

**Could be innocent when:**

- Cloud backups, large uploads to sanctioned SaaS, video conferencing

**Response:**

1. Identify the destination and whether it is a sanctioned service
2. Identify which user and process on the host sent the data
3. Isolate the host if the destination is unknown

## SEN-011: Outbound connection to known-malicious address

| | |
|---|---|
| Severity | critical |
| ATT&CK | T1071 Application Layer Protocol (Command and Control) |
| Logic | Single matching event |

An internal host connected out to an address on the threat intelligence list (command-and-control, malware staging, data drop sites).

**In plain English:** An employee's desk phone keeps calling a number that police have already tied to a crime ring. You do not know what was said, but the call itself tells you that desk is compromised.

**Could be innocent when:**

- Stale intelligence. IP addresses get reassigned to innocent owners

**Response:**

1. Isolate the internal host from the network
2. Capture memory and disk for forensics before rebooting
3. Hunt for the same destination across all other hosts

## SEN-012: Encoded or download-and-run PowerShell

| | |
|---|---|
| Severity | high |
| ATT&CK | T1059.001 Command and Scripting Interpreter: PowerShell (Execution) |
| Logic | Single matching event |

PowerShell launched with an encoded command or an in-memory download cradle.

**In plain English:** A note passed in class, written in code. Legitimate admins rarely need to scramble their commands. Encoding is how attackers keep the real instructions away from anyone reading over their shoulder.

**Could be innocent when:**

- Some management tools (SCCM, Intune) use encoded commands legitimately

**Response:**

1. Read the decoded command (Sentinel decodes the Base64 for you in the alert summary)
2. Identify the parent process that launched it
3. Isolate the host if the decoded command downloads or executes remote content

## SEN-013: New local account created

| | |
|---|---|
| Severity | medium |
| ATT&CK | T1136.001 Create Account: Local Account (Persistence) |
| Logic | Single matching event |

A new user account was created on a Linux or Windows host.

**In plain English:** A burglar who cuts themselves a spare key so they can return whenever they like, even after you change the lock they came in through.

**Could be innocent when:**

- Normal onboarding, if it arrives through the approved provisioning process

**Response:**

1. Match the account against a change ticket or HR record
2. If there is no ticket, disable the account and review who created it

## SEN-014: Account added to administrators group

| | |
|---|---|
| Severity | high |
| ATT&CK | T1098 Account Manipulation (Privilege Escalation) |
| Logic | Single matching event |

A user was added to a privileged local group.

**In plain English:** The spare key was bad enough. Now the burglar has upgraded it to the master key that opens every room in the building.

**Could be innocent when:**

- Approved admin onboarding

**Response:**

1. Verify against a change ticket
2. Remove the membership and investigate the account that made the change

## SEN-015: Security audit log cleared

| | |
|---|---|
| Severity | critical |
| ATT&CK | T1070.001 Indicator Removal: Clear Windows Event Logs (Defense Evasion) |
| Logic | Single matching event |

The Windows Security event log was cleared (event 1102).

**In plain English:** Wiping the fingerprints and taking the CCTV tape. Almost nobody clears this log for an honest reason, and the act of clearing it is itself recorded, which is the one fingerprint they cannot wipe.

**Could be innocent when:**

- Almost none in production

**Response:**

1. Treat the host as compromised until proven otherwise
2. Recover the missing window from the central log copy, which is exactly why logs get forwarded

## SEN-016: Password hash file read with sudo

| | |
|---|---|
| Severity | high |
| ATT&CK | T1003.008 OS Credential Dumping: /etc/passwd and /etc/shadow (Credential Access) |
| Logic | Single matching event |

A sudo command touched /etc/shadow, where Linux stores password hashes.

**In plain English:** Photocopying the building's entire key cabinet. The hashes are not passwords yet, but they can be cracked offline at leisure, with no more failed-login noise to give the attacker away.

**Could be innocent when:**

- Administrators doing account maintenance

**Response:**

1. Confirm with the user whether they ran it
2. If not, assume every password on that host is exposed and rotate them

## SEN-017: Office application launched a command shell

| | |
|---|---|
| Severity | high |
| ATT&CK | T1204.002 User Execution: Malicious File (Execution) |
| Logic | Single matching event |

Word, Excel, PowerPoint or Outlook started cmd, PowerShell or a script host.

**In plain English:** A letter that, once opened, stands up and starts rearranging your office. Documents are for reading. When one launches a command prompt, a malicious macro almost certainly just ran.

**Could be innocent when:**

- A handful of legacy finance macros. Allowlist those by command line

**Response:**

1. Isolate the host
2. Find the document and the email that delivered it, then search all mailboxes for copies

## SEN-018: Traffic volume anomaly

| | |
|---|---|
| Severity | medium |
| ATT&CK | T1498 Network Denial of Service (Impact) |
| Logic | Minute volume with z-score of 4 or more against a 30 minute baseline |

Flags a minute whose event count is far above the rolling 30-minute baseline for that log source (z-score of 4 or more).

**In plain English:** Like a shop owner who knows a normal Tuesday sees 40 customers. If 900 walk in within a minute, nobody needs a rulebook to know something is off.

**Could be innocent when:**

- Marketing campaigns, product launches, load tests

**Response:**

1. Identify the top talker and check whether it is a customer or a bot
2. Rate limit or challenge the source at the edge
3. Check whether the flood is cover for a quieter attack

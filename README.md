# CampusConnect — Cryptographic Protocol Implementation & Network Security Threat Analysis

## How to run

```bash
python3 rsa.py                # runs both required RSA test cases
python3 diffie_hellman.py     # runs both required Diffie-Hellman test cases

# or, run a single custom case for either script:
python3 rsa.py <p> <q> <e> <m>
python3 diffie_hellman.py <p> <alpha> <a> <b>
```

Both scripts print every intermediate value (RSA: `n`, `phi(n)`, `e`, `d`, `c`,
recovered `m`; Diffie-Hellman: `A`, `B`, and both independently computed `K`
values) and end with an explicit pass/fail check.

**Expected results:**
- `rsa.py`: for both test cases, the recovered plaintext equals the original `m`
  — (a) `p=3, q=11, e=3, m=4` → `c=31`, recovered `m=4`; (b) `p=61, q=53, e=17, m=65`
  → `c=2790`, recovered `m=65`.
- `diffie_hellman.py`: for both test cases, Alice's and Bob's independently
  computed `K` are equal — (worked example) `p=29, alpha=2, a=5, b=12` → `K=16`;
  (additional) `p=23, alpha=5, a=6, b=15` → `K=2`.

---

## 1. Security-principle mapping

| Implementation | Security principle(s) addressed |
|---|---|
| **RSA** (`rsa.py`) | **Confidentiality** — encrypting `m` into `c` with the public key `e` means only the holder of the private key `d` can recover `m`. RSA's key-pair structure also makes it usable for **authentication** and **non-repudiation** (not exercised by this script, but inherent to the algorithm): a party can encrypt/sign data with their *private* key so that anyone can verify it with the corresponding *public* key, proving the message came from that key-holder and that they cannot later deny having produced it. |
| **Diffie-Hellman** (`diffie_hellman.py`) | **Confidentiality** — it lets two parties derive a shared secret `K` over a channel an eavesdropper can observe, without ever transmitting `K` itself (only `A` and `B` cross the wire, and recovering `a` or `b` from them requires solving the discrete log problem). It does **not** address authentication on its own: nothing in the protocol proves that the party you exchanged `A`/`B` with is who they claim to be, which is exactly what enables a man-in-the-middle attack (see Task 4(e) below). |

### Why Diffie-Hellman is a key-exchange protocol, not an encryption algorithm

Diffie-Hellman never takes a plaintext message as input and never produces a
ciphertext as output — its only job is to let two parties who have never met
agree on a shared secret number `K` over a channel that an attacker can watch.
That shared secret still has to be handed off to a *separate* symmetric cipher
(e.g., AES) before any actual data can be encrypted, which is why `K` alone is
not a "message". RSA, by contrast, directly supports both halves of a
public-key cryptosystem: it can generate a public/private key pair *and* it
defines an explicit encryption transform (`c = m^e mod n`) and decryption
transform (`m = c^d mod n`) that operate on a real message, which is why RSA
can be classified as a full encryption algorithm and Diffie-Hellman cannot.

---

## 2. Threat-model write-up

### (a) Firewall placement

Place a **network firewall at the network perimeter**, in front of
CampusConnect's public-facing web/application servers (i.e., in a DMZ,
between the internet and the internal network where the database and other
back-end services live). Given this is production-facing infrastructure
serving real login traffic, a **hardware (or cloud-managed, e.g. a cloud
provider's network firewall/security-group appliance) firewall** is the
right fit here rather than a software firewall on each host alone — it can
inspect and filter traffic for the whole server tier at line rate before it
ever reaches an individual machine, and it centralizes rule management
instead of relying on every server being configured correctly.

**Recommended traffic-filtering rule:** allow inbound traffic only on
**port 443/TCP (HTTPS)** to the login server's IP address (with 80/TCP
permitted only to redirect to 443), and deny all other inbound ports by
default. This is a port-based rule because the login service has exactly
one legitimate entry point (the HTTPS web front end), so anything else
inbound has no business reason to reach that server.

### (b) HIDS vs. NIDS

CampusConnect should deploy **both a Host-based IDS (HIDS) and a
Network-based IDS (NIDS)**, because they detect different things:

- A **NIDS** monitors traffic *between* hosts and can detect network-level
  attacks — port scans, known exploit signatures in transit, unusual traffic
  volume/DDoS patterns — but it **cannot** see inside encrypted HTTPS payloads
  or detect that a file was tampered with *on* a specific server.
- A **HIDS** monitors activity *on* a single server (file-integrity changes,
  suspicious log entries, unexpected process/privilege-escalation activity)
  and **cannot** see attack patterns occurring on the network between other
  hosts that never touch the monitored machine.

Since CampusConnect needs to catch both "something bad is happening on the
wire" and "something bad already happened on this specific server," neither
type alone covers the whole picture.

### (c) HTTP vs. HTTPS

CampusConnect's login page **must use HTTPS**, not plain HTTP. Specifically,
plain HTTP transmits the login form's username and password fields as
unencrypted plaintext across the network, so anyone able to observe traffic
on the path (e.g., on shared Wi-Fi, a compromised router, or an ISP link) can
capture those credentials with a packet sniffer — this is **credential
sniffing**. HTTPS (TLS) encrypts the entire request/response, including the
credentials, so an eavesdropper only sees ciphertext. (HTTPS also protects
against **session hijacking** via stolen session cookies, since the session
cookie is likewise encrypted in transit — but the specific vulnerability most
directly tied to the *login* page itself is credential sniffing.)

### (d) Authentication design: least privilege + MFA

**Roles and permissions (principle of least privilege — each role gets only
what it needs, nothing more):**

| Role | Permissions |
|---|---|
| **Student** | Read-only access to their *own* enrollment records, grades, and course schedule. No write access to grades, no visibility into other students' records. |
| **Instructor** | Read/write access to grades and rosters *only* for courses they are assigned to teach (via `courses.instructor_id`); read-only visibility into their students' contact info; no access to other instructors' courses or to system-wide admin functions. |
| **Admin** | Full read/write access needed to manage the schema-level data — creating/removing courses, instructors, and student accounts — but even admin access should be scoped to what's operationally necessary (e.g., not needing raw database credentials for day-to-day account management if an admin panel suffices). |

**Multi-factor authentication:** require at least two factors to log in —
**Factor 1: password** (something the user knows) and **Factor 2: a
time-based one-time code from an authenticator app, or a push notification
to a registered device** (something the user has). For the highest-privilege
role (**admin**), CampusConnect should require MFA on every login with no
"remember this device" exception, since a compromised admin account gives an
attacker the broadest blast radius; student and instructor accounts can use
MFA with a reasonable trusted-device exception to balance security and
day-to-day usability.

### (e) One plausible attack, classified

**Attack:** An attacker on the same network segment as a student (e.g., an
open campus Wi-Fi network) runs a packet-capture tool and passively listens
to traffic to and from CampusConnect's login page. Because the login page
currently runs on plain HTTP, the attacker can read the student's username
and password directly out of the captured packets in plaintext, without
ever having to inject, alter, or resend any traffic.

**Classification: passive.** This is a passive attack because the attacker
only *observes* traffic that is already flowing across the network — they
never modify, inject, block, or replay any packet, and CampusConnect's
servers and the victim's browser behave completely normally throughout
(nothing about the attack would be detectable by looking at the traffic's
integrity, only by noticing that it was unencrypted in the first place).


# Daily Hack #110
**First blood**

**M2F14M3**

**Solved by**
- sfmt
- Cyberelements
- Sidra
- rpaul1730
- JoeS
- fedvillalba

**The header that says where you are**

**Privilege Escalation & Post-Exploitation**

**Difficulty:** Medium
**~4 min**
**+10 XP**

---

## Mission briefing

Thornbury manages the access control for a few dozen buildings, and the door schedules are read-only to anyone outside the management network. That restriction is real: the API refuses you from the internet and says so. It is also enforced by asking the caller where the caller is. Get the Leeds site schedule, read the overrides at the bottom of it, and name the door that a facilities ticket has left open to anyone who walks up to it for the next two months.

---

## Investigate

Repeater on the Thornbury schedule API, with the request as it leaves your machine. The `X-Forwarded-For` header is prefilled with your own address. Edit it and send again.

### REQUEST

```http
GET /api/v2/sites/leeds-kirkstall/schedule HTTP/1.1
Host: access.thornbury.example
Authorization: Bearer tb_rd_9f41c0b7e2
X-Forwarded-For: 10.12.0.9
Accept: application/json

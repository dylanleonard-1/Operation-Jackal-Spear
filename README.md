# 🌍 Operation Jackal Spear 🦁

Recent reports reveal a newly discovered Advanced Persistent Threat (APT) group known as **"Jackal Spear,"** originating from South Africa and occasionally operating in Egypt. This group has been targeting large corporations using **spear-phishing campaigns** and **credential stuffing attacks**. By exploiting stolen credentials, they can gain access to systems with minimal login attempts.

Their primary targets are **executives**. Once they successfully compromise an account, they establish persistence by creating a secondary account on the same system with a similar username. This new account is then used to exfiltrate sensitive data while avoiding detection. 🚨

## 🎯 Your Mission:
Management has tasked you with identifying **Indicators of Compromise (IoCs)** related to this South African/Egyptian APT within our systems. If you find any IoCs, conduct a thorough investigation to track the attacker’s movements and piece together their tactics, techniques, and procedures (TTPs) until you’ve “solved the challenge.” 🔍

### 🏆 Final Step:
Once you’ve completed your hunt, present the **“flag”** to the community to claim your reward! 🎉

Good luck! 🍀

---

## 🔎 Getting Started:

Your first task is to discover and submit the **name of the host** within the **Cyber Range** that was compromised by the APT.

---

## 💥 Step 1: Investigating Suspicious Logins

### **What We're Doing:**
We began by looking for **suspicious login activities** by querying the **DeviceLogonEvents** table. These events track successful and failed login attempts on devices. We aimed to detect any **brute-force attacks** or credential stuffing attempts.
### **The Query:**

### **SQL Code**

```kusto
let SuspiciousLogins =
   DeviceLogonEvents
   | where Timestamp > ago(30d)  // Expand time range to last 30 days
   | where not(AccountName in ("root", "labuser", "admin"))  // Exclude these accounts
   | summarize
       FailedAttempts = countif(ActionType == "LogonFailed"),  // Count failed login attempts
       SuccessfulLogins = countif(ActionType == "LogonSuccess")  // Count successful logins
     by AccountName, DeviceName, RemoteIP  // Group by account, device, and IP
   | where FailedAttempts > 5 and SuccessfulLogins > 0;  // Filter suspicious logins
```

- **Time Range**: We expanded the time range to the **last 30 days** to capture recent login attempts.
- **Excluding System Accounts**: We excluded **system accounts** such as `"root"`, `"labuser"`, and `"admin"`, since these accounts are typically not used by regular users and may not be relevant to our investigation.
- **Failed and Successful Logins**: We counted the number of **failed logins** and **successful logins** for each account and device combination.
- **Filter Suspicious Logins**: We looked for accounts with **more than 5 failed attempts** followed by at least one successful login. This pattern suggests a **brute-force attack**.

### **What it looks like in SQL**


### **Breakdown of the Code:**
- `Timestamp > ago(30d)`: Focused on the past **30 days** to capture recent events.
- `where not(AccountName in ("root", "labuser", "admin"))`: Filtered out system accounts.
- `summarize`: Aggregated the login attempts to count the number of failed and successful logins.
- `where FailedAttempts > 5 and SuccessfulLogins > 0`: We focused on accounts with **multiple failed attempts** and **at least one successful login**.

### **What We Learned:**
This query helped us identify devices that had frequent **login failures** followed by **successful logins**, suggesting a possible **brute-force attack** or attempt to bypass authentication systems.

---

## 🌍 Step 2: Identifying Egypt-Based IPs

### **What We're Doing:**
To identify **Egypt-based IPs**, we cross-referenced the IP addresses found in the logs with **publicly available IP ranges** assigned to Egypt. This is crucial because APT groups like "Jackal Spear" are known to operate from this region.

### **Why It Matters:**
By identifying the **location of IPs**, we can better understand the geographical source of the attack and check if the attack aligns with the known TTPs of the group.

---

## 📝 Step 3: Investigating File Events

### **What We're Doing:**
We used **DeviceFileEvents** to track file activities such as **creation**, **renaming**, or **modification** on the compromised machine. This is to identify any **sensitive files** that were altered or created during the attack.

### **The Query:**

### **SQL Code**

```kusto
DeviceFileEvents
| where DeviceName == "corpnet-1-ny"  // Focus on the compromised machine
| where ActionType in ("FileCreated", "FileRenamed", "FileModified")  // Filter for creation, renaming, and modification
| where RequestAccountName == "chadwick.s"  // Filter by user account
| where FileName endswith ".pdf" or FileName endswith ".zip" or FileName endswith ".txt"  // Filter by file extensions
| project Timestamp, RequestAccountName, ActionType, FileName, DeviceName  // Show relevant columns
| order by Timestamp desc  // Sort by most recent events
```
The query tracked file events on the compromised machine **"corpnet-1-ny"**. We filtered by file extensions (e.g., `.pdf`, `.zip`, `.txt`) to identify relevant files that could contain sensitive data.

### **What it looks like in SQL**

### **Breakdown of the Code:**
- `DeviceName == "corpnet-1-ny"`: Focused the query on the compromised device.
- `ActionType in ("FileCreated", "FileRenamed", "FileModified")`: Filtered for file creation, renaming, or modification events.
- `where FileName endswith ".pdf" or FileName endswith ".zip" or FileName endswith ".txt"`: Focused on specific file types that are commonly associated with sensitive data.
- `order by Timestamp desc`: Sorted the results by **most recent events**.

### **What Happened:**
Unfortunately, this query didn’t show the specific **.pdf** file we were looking for because **file access** (reads or exfiltrations) wasn't captured by this query. We needed to adjust our approach to track **file access events** instead.

---

## 🔍 Step 4: Using DeviceEvents for File Access

### **What We're Doing:**
Since **file modification** wasn’t captured, we switched to **DeviceEvents**, which can track **file access** events (such as **reads**), which are critical for detecting unauthorized access or exfiltration.

### **The Query:**
We focused on events that track sensitive file **reads** (file access):

### **SQL Code**

```kusto
DeviceEvents
| where DeviceName contains "corpnet-1-ny"  // Focus on the compromised machine
| where InitiatingProcessAccountName contains "chadwick.s"  // Filter by the account used for the attack
| where ActionType contains "SensitiveFileRead"  // Track sensitive file reads
```

- `DeviceName contains "corpnet-1-ny"`: Focused on the compromised device.
- `ActionType contains "SensitiveFileRead"`: Focused on tracking when **sensitive files** are **accessed** or **read**.

### **What it looks like in SQL**


### **What We Learned:**
This query helped us identify when sensitive files were **accessed** or **read** by the attacker. Even if files were not modified, this could indicate **exfiltration** attempts.

---

## 📂 Step 5: Detailed File Access Information

### **What We're Doing:**
We retrieved detailed information about the accessed file. The query showed that the file **CRISPR-X_Next-Generation_Gene_Editing_for_Artificial_Evolution.pdf** was accessed on the compromised machine.

### **File Access Details:**
This confirms that the attacker **read this file** during the compromise, which is a significant clue in understanding their movements and intentions. 🔍

---

## ✅ Conclusion

By initially investigating **suspicious login attempts** using the **DeviceLogonEvents** query, and then adjusting our approach to track **file access events** using **DeviceEvents**, we successfully identified the **compromised machine** and the **sensitive file accessed** during the attack. 

This allowed us to trace the **attacker's movements** and better understand their **tactics, techniques, and procedures (TTPs)**. We now have a clearer picture of the attack and the data exfiltrated during the compromise. 🚨

---

**Great job!** 🏆 You’ve completed the investigation and learned valuable insights into the **Jackal Spear** APT’s activities. Continue monitoring for any new indicators or suspicious behavior! 🎯

---

### ⚠️ Always Stay Alert! ✨

Remember, detecting and mitigating attacks like these requires constant vigilance and quick action. Stay secure! 🔐




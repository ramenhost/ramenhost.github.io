---
title: Today I Learned
description: Microblogs of some small things I've learned.
date: 2024-11-28 13:51:00 +0530
categories: [Microblog]
tags: [programming, home-lab, networking]
pin: true
media_subpath: ../../images/til
---

---
<div class="card">
<div class="card-header" style="background-color: #F4EAE0;">
    Nov 28, 2024
</div>
<div class="card-body">
<h3 class="card-title" style="margin-top: 6px; margin-bottom: 20px;">Using dynamic DNS for home server</h3>
<p class="card-text content">
It is often joked about sharing localhost URL with others, but there are scenarios where exposing a local port to the internet is genuinely useful. For instance, individuals running their own media servers or self-hosted cloud services can relate. Many internet providers use <a href="https://en.wikipedia.org/wiki/Carrier-grade_NAT">CGNAT</a> for IPv4, which, combined with NAT in home routers, complicates exposing local services to the internet. While this is beneficial for security, it can be frustrating for those who know what they are doing.

With the advent of IPv6, things are changing. ISPs are now providing public IPv6 addresses. By opening the necessary port in your router's firewall, you can access your local services using the public IPv6 address from anywhere. The challenge, however, is that IPv6 addresses are typically dynamic and change frequently. This is where dynamic DNS comes into play. By obtaining a domain name and running dynamic DNS software, you can keep the DNS record updated whenever the IPv6 address changes. This allows you to access your local services using a static domain name instead of the ever-changing IPv6 address.  
<blockquote class="blockquote mb-0">
<p class="content">Exposing local services to internet can heavily undermine security of your network. Not recommended unless you know what you are doing.</p>
</blockquote><br>
Here is my setup of Plex media server with dynamic DNS <a href="https://gist.github.com/ramenhost/9d26175abcbebf5c739e8de7d3ec3d13">https://gist.github.com/ramenhost/9d26175abcbebf5c739e8de7d3ec3d13</a>
</p>
</div>
</div>

---

<div class="card">
<div class="card-header" style="background-color: #F4EAE0;">
    Nov 12, 2024
</div>
<div class="card-body">
<h3 class="card-title" style="margin-top: 6px; margin-bottom: 20px;">Typecasting pointers in C is arch-dependent</h3>
<p class="card-text content">
I've been writing C for 8 years and have confidently downcasted pointers after checking for value overflow. Today I learned that typecasting pointers to a smaller datatype works only on little-endian architectures. On big-endian systems, the pointer will reference the most significant bytes, leading to unexpected results. I realized this the hard way when my <a href="https://github.com/openssl/openssl/pull/24636">OpenSSL PR</a> failed CI tests on big-endian architectures.

<img src="c-pointer-typecast.jpg" alt="C pointer typecasting issues with big-endian">

</p>
</div>
</div>

---

<div class="card">
<div class="card-header" style="background-color: #F4EAE0;">
    Sep 20, 2024
</div>
<div class="card-body">
<h3 class="card-title" style="margin-top: 6px; margin-bottom: 20px;">Cloudflare knows what http library you use</h3>
<p class="card-text content">
In X, <a href="https://x.com/zoriya_dev">@zoriya_dev</a> shared an issue where an API request was blocked by Cloudflare when using Python's `aiohttp` library, while the same request worked fine with curl and the `requests` library. People got together to investigate the issue.
<blockquote  class="twitter-tweet tw-align-center" data-cards="hidden" data-conversation="none" data-dnt="true"><p lang="en" dir="ltr">here is the python code (that gets cloudflare blocked)<br>the curl requests (that works)<br><br>and the netcat to print requests (by changing https://thexem by http://localhost), first is python second is curl <a href="https://t.co/eJZydIRbkK">https://t.co/eJZydIRbkK</a> <a href="https://t.co/8TSDb7WjMs">pic.twitter.com/8TSDb7WjMs</a></p>&mdash; Zoe Roux (@zoriya_dev) <a href="https://twitter.com/zoriya_dev/status/1837039528399212793?ref_src=twsrc%5Etfw">September 20, 2024</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

Initial analysis suggested that Cloudflare was blocking requests based on the User-Agent header. However, this theory was quickly disproven as the User-Agent header was identical in both `aiohttp` and `curl` requests. Even after ensuring that the entire HTTP request was the same for both libraries, the issue persisted. This indicated that the detection mechanism was operating at a lower level, likely involving TLS records.

Using Wireshark, I discovered that the TLS extensions differed between `aiohttp` and `curl`. By adding any single TLS extension to `aiohttp`, the block was bypassed, effectively disrupting the blacklisted fingerprint.

<img src="cf-tls-fingerprint.jpg" alt="Adding TLS extension to bypass TLS fingerprinting">

TLS fingerprinting is a common technique used by Cloudflare and other services to detect bots and malicious traffic. Cloudflare offers varying degrees of protection that can be configured by the domain owner. In this case, it is possible that the domain was put in a higher protection level where TLS fingerprint of `aiohttp` is blacklisted. 

</p>
</div>
</div>

---

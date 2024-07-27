---
title: Automating Twitter redirect to read Medium member articles
description: A stealthy way to read medium.com member stories for free without an account or subscription. Also, a brief on how I modded the medium android app to automate the process.
date: 2020-06-14 11:25:00 +0530
categories: [General]
tags: [reverse-engineering]
pin: true
image:
  path: ../images/medium/medium-membership-dialog.png
---

I started reading medium.com after a quite long break and the first thing I noticed is that almost all the stories in my feed are behind the $5/month paywall. There was a time when you could open the app, read till you become tired and then you refresh to get a fresh new feed of free stories. That time is gone for good now.

### Stealthy way
Medium is not that much into restricting us from member stories. We can read up to 3 member stories per month for free. And the bonus is that we don’t need an account. Every time we want to read a story, we can copy the link into a new incognito tab.
The downside is that we are always a stranger to medium's suggestion algorithm.

### Twitter way
Next little hole in the paywall is for Twitter users. When we come from Twitter through a direct story link, Medium allows us to read the story regardless of membership. This is an intentional hole punched by medium itself to facilitate sharing in Twitter. We can paste the link into Twitter DM or tweet, click and come from there.

<blockquote class="twitter-tweet"><p lang="en" dir="ltr">All <a href="https://twitter.com/Medium?ref_src=twsrc%5Etfw">@Medium</a> paywalled stories are now free and unmetered when you’re coming from Twitter.</p>&mdash; Ev (@ev) <a href="https://twitter.com/ev/status/1100899021621583872?ref_src=twsrc%5Etfw">February 27, 2019</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>
{: .prompt-info }

Now though the second method is better for suggestions, it needs a couple of clicks for reading each story which can be annoying for regular use.

### APK mod
Automating the Twitter route would make the reading life much simpler. I went on to create a mod for the medium android app. Everything works super smooth and I almost feel like a member. Here goes the brief on what I did.

After a bit of digging into how medium detects the users coming from Twitter links, the answer is the obvious HTTP referer header. The key to unlock medium member stories is having `referer: https://t.co/random` in header. I tried to automate this.

I used [apktool](https://apktool.org/) for disassembling and [JD-GUI](https://java-decompiler.github.io/) for decompiling the Java classes. After hours of analysing scrambled and decompiled Java code, found two functions in the HTTP library (okhttp3). One is `RequestBuilder.build()` which is invoked each time a new HTTP request is built. Another one is `HeadersBuilder.add()` which can be used to add one extra header. Since decompiled Java code cannot be built back into apk, I patched the disassembled smali code. After messing up with registers and long `adb log` sessions, got the mod working.

<script src="https://gist.github.com/ramenhost/e516049b12731580b08821f10bc160b0.js"></script>

Medium uses split apks so that common functionality is in the base apk and device specific resources are in a seperate apk. Jarsigner didn't work with split apks for some reason. [apksigner](https://developer.android.com/tools/apksigner) saved the day.

Happy reverse engineering :\)

---
layout: default
title: "VESSEL - Reproducibility Model v2"
permalink: /model.html
---

# Reproducibility Model v2

### Legend: 

<ul>
    <li>&#9989;: Supported</li>
    <li>&#10060;: Unsupported</li>
    <li><i class="fa-solid fa-bolt"></i>:Hadolint Rule</li>
</ul>

{% for cat in site.data.rep_model.Categories %}

## {{ cat.Category }}

{% include rule_table.html rules=cat.Rules category=cat.Category %}
<br>

{% endfor %}

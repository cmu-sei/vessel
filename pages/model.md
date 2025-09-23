---
layout: default
title: "VESSEL - Reproducibility Model v2"
permalink: /model.html
---

# Reproducibility Model v2

{% for cat in site.data.rep_model.Categories %}

### {{ cat.Category }}

{% include rule_table.html rules=cat.Rules category=cat.Category %}

{% endfor %}

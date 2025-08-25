---
layout: default
title: "VESSEL - Reproducibility Model v2"
permalink: /model.html
---

# Reproducibility Model v2

<table class="model-table">
    <thead>
        <tr>
            {% for key in site.data.rep_model[0] -%}
                <th>{{ key[0] | capitalize -}}</th>
            {% endfor %}
        </tr>
    </thead>
    <tbody>
        {% for row in site.data.rep_model -%}
            <tr>
                {% for col in row -%}
                    <td>
                        {%- if col[1] == true or col[1] == false -%}
                            {{ col[1] | capitalize }}
                        {%- else -%}
                            {{ col[1] | escape }}
                        {%- endif -%}
                    </td>
                {% endfor -%}
            </tr>
        {% endfor -%}
    </tbody>
</table>
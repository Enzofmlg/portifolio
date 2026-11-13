# SQL Injection (Time-Based Blind) in `products_tags.php` — `option_order_by` Parameter

**Security Assessment Report** **Target:** Modified Shop 3.3.0 rev 16825 — Admin Panel

## Affected Product

- **Product:** Modified Shop
- **Version tested:** 3.3.0
- **Revision:** 16825
- **Affected component:** Product Tags
- **Relevant endpoint:** `/admin/products_tags.php`
- **Vulnerable parameter:** `option_order_by` (GET)
- **Vulnerable source file:** `/admin/includes/modules/products_tags.php`
- **Vendor:** `https://github.com/modified-shop/modified-shop`

## 1. Summary

A Time-Based Blind SQL Injection vulnerability was identified in the product tags management module of Modified Shop 3.3.0 rev 16825.

The vulnerability arises because the GET parameter `option_order_by` is read directly from the request and concatenated into the `ORDER BY` clause of a SQL query, without validation, escaping, or parameterization.

Exploitation was confirmed using a conditional SQL expression that queries `information_schema.tables` and triggers a five-second delay when the condition evaluates to true.

## 2. Vulnerability Classification

| Field | Details |
|---|---|
| Exploitation Method | Time-Based Blind SQL Injection |
| CWE | CWE-89 |
| Severity | Medium |
| Authentication | Required — authenticated admin session |

## 3. Source Code Location

**File:** `admin/includes/modules/products_tags.php`

The parameter is read directly from the request with no validation:

```php
if (isset($_GET['option_order_by']) && $_GET['option_order_by']) {
    $option_order_by = $_GET['option_order_by'];
    $_POST['current_product_id'] = (int)$_GET['current_product_id'];
} else {
    $option_order_by = 'sort_order,options_id,options_name';
}
```

Its value is then concatenated directly into the SQL query:

```php
$options_query = xtc_db_query("SELECT *
                                 FROM " . TABLE_PRODUCTS_TAGS_OPTIONS . "
                                WHERE languages_id = '".(int)$_SESSION['languages_id']."'
                                  AND (filter = '1' OR status = '1')
                             ORDER BY ". $option_order_by);
```

**Vulnerable point:** `$option_order_by` is concatenated at line 42 with no allowlist restricting it to valid sortable columns or expressions.

## 4. Input Filtering Analysis

`admin/includes/application_top.php` runs `Inputfilter::validate()` against `$_GET`, `$_POST`, and `$_REQUEST`.

However, in `includes/classes/inputfilter.php`, `option_order_by` is not among the parameters routed to the numeric, alphanumeric, or other restrictive-format validation routines. It falls through to the `default` branch, which applies no generic SQL sanitization.

A `safeSQL()` method does exist in `includes/classes/class.inputfilter.php`, but its presence does not mean it is applied automatically to this parameter. Tracing the execution flow shows no call to it before the value reaches the query.

The existing filtering mechanism therefore does not prevent SQL injection at this point.

## 5. Proof of Concept

**Vulnerable endpoint (tested instance):**

```
http://172.25.44.135:8080/admin/products_tags.php?current_product_id=1&option_order_by=sort_order%2CIF%28%28SELECT%20COUNT%28%2A%29%20FROM%20information_schema.tables%20WHERE%20table_schema%3DDATABASE%28%29%20AND%20table_name%3D%27products_tags_options%27%29%3D1%2CSLEEP%285%29%2C0%29
```

**Decoded injected expression:**

```sql
sort_order, IF(
    (
        SELECT COUNT(*)
        FROM information_schema.tables
        WHERE table_schema = DATABASE()
          AND table_name = 'products_tags_options'
    ) = 1,
    SLEEP(5),
    0
)
```

This expression checks whether the `products_tags_options` table exists in the current database. When the condition is true, `SLEEP(5)` delays the query's execution by five seconds, confirming that the injected SQL is evaluated by the database engine rather than discarded or escaped.

## 6. Dynamic Evidence

Exploitation was validated using an authenticated admin session and a valid `current_product_id`.

| Test | Response Time |
| --- | --: |
| Baseline request | 0.025 s |
| Request with payload | 5.028 s |
| Observed difference | ≈ 5.003 s |

The MariaDB general query log also recorded the injected expression inside the `ORDER BY` clause, confirming that user-controlled input reached the SQL query as executed by the database engine.

The combination of source code evidence, the database query log, and the measured timing difference confirms the vulnerability.

## 7. Exploitation Requirements

Exploitation requires:

- An authenticated administrative session.
- Access permission to the product tags management feature.
- A valid `current_product_id`.
- At least one existing option record for the query to iterate over.

This vulnerability has not been demonstrated as exploitable by an anonymous, unauthenticated user.

## 8. Impact

The vulnerability allows manipulation of the SQL query executed by the admin module.

Using time-based blind SQL injection techniques, an authenticated user with the required permissions can infer information stored in the database by observing differences in response time — for example, confirming table and column names, or extracting data character by character.

Depending on the privileges granted to the application's database user and the structure of further crafted queries, additional forms of data access or manipulation may also be possible. These additional possibilities were not demonstrated in this proof of concept and would require separate validation.

## 9. Recommendations

The application should avoid concatenating user-controlled parameters directly into SQL clauses. Specifically:

1. Replace the free-form `option_order_by` parameter with an allowlist of permitted sorting columns.
2. Validate both the sort field and sort direction before building the query.
3. Reject arbitrary SQL expressions in this parameter.
4. Use prepared statements for all query values.
5. Review other locations in the application that build `ORDER BY` clauses via concatenation of external parameters.

**Example of a safer approach:**

```php
$allowed_order = [
    'sort_order' => 'sort_order',
    'options_id' => 'options_id',
    'options_name' => 'options_name'
];

$requested_order = $_GET['option_order_by'] ?? 'sort_order';

$option_order_by = $allowed_order[$requested_order] ?? 'sort_order';
```

Column names and SQL expressions are not protected by prepared statements in the same way that values are, since identifiers cannot be bound as query parameters. They must instead be validated against an allowlist before being placed into the query.

## 10. Classification

- **CWE-89:** Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection').
- **Category:** SQL Injection.
- **Confirmed technique:** Time-Based Blind.
- **Authentication:** Administrative (authenticated).

## 11. Conclusion

The GET parameter `option_order_by` allows injection of arbitrary SQL expressions into the `ORDER BY` clause of the query executed by the product tags management module.

The vulnerability was confirmed through source code review, analysis of the input filtering flow, inspection of the MariaDB general query log, and comparison of response times under normal and malicious payloads.

The observed behavior confirms a Time-Based Blind SQL Injection vulnerability in an administrative feature of Modified Shop 3.3.0 rev 16825.

## 12. Credits

- **Researcher:** 11Lnz – Enzo Lenzi
- **Group:** Red Scan Academy

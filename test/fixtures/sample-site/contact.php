<?php
require 'config.php';
$name = htmlspecialchars($_POST['name'] ?? '');
mail(CONTACT_EMAIL, 'New enquiry', "From: $name");

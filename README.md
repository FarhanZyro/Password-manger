# Password Manager – PHP OOP

A simple web-based password manager built with PHP OOP and MySQL.

## Requirements
- XAMPP (PHP 8.0+, MySQL, Apache)
- Extensions: `openssl`, `pdo_mysql`

## Setup

1. **Database** – Open phpMyAdmin, go to SQL tab, paste and run `sql/schema.sql`

2. **Config** – Edit `config/config.php` with your DB credentials:
```php
   'user' => 'root',
   'pass' => '',
```

3. **Files** – Copy the `password_manager` folder to `C:\xampp\htdocs\`

4. **Open** – Go to `http://localhost/password_manager/public/index.php`

## Features
- Register / Login (bcrypt password hashing)
- AES-256 encrypted password storage
- Password generator (configurable length, character types)
- Save, view and delete password records
- Change login password (encryption key auto re-wrapped)

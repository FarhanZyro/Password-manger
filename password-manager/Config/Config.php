<?php
return [
    'db' => [
        'host'    => 'localhost',
        'dbname'  => 'password_manager',
        'user'    => 'root',      // change this
        'pass'    => '',          // change this
        'charset' => 'utf8mb4',
    ],
    'bcrypt_cost'       => 12,
    'pbkdf2_iterations' => 100000,
];
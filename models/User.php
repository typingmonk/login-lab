<?php

class User extends MiniEngine_Table
{
    protected $_primary_keys = 'user_id';

    protected $_columns = [
        'user_id' => ['type' => 'int'],
        'displayname' => ['type' => 'text'],
        'info' => ['type' => 'text'] // For storing JSON data
    ];

    protected $_relations = [
        'user_associates' => [
            'rel' => 'has_many',
            'type' => 'UserAssociate',
            'foreign_key' => 'user_id',
        ],
    ];

    public static function create($displayname, $info = [])
    {
        $user_data = [
            'displayname' => $displayname,
            'info' => json_encode($info),
        ];

        try {
            $user = self::insert($user_data);
            return $user;
        } catch (Exception $e) {
            error_log("Error creating user: " . $e->getMessage());
            return null;
        }
    }

    public static function isLoggedIn()
    {
        $user_id = MiniEngine::getSession('user_id');
        return $user_id !== null;
    }
}

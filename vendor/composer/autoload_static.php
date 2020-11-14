<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInitc2267e67192cf31fbc2e1aca813b29b4
{
    public static $prefixLengthsPsr4 = array (
        'e' => 
        array (
            'elzobrito\\' => 10,
        ),
    );

    public static $prefixDirsPsr4 = array (
        'elzobrito\\' => 
        array (
            0 => __DIR__ . '/../..' . '/src',
        ),
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->prefixLengthsPsr4 = ComposerStaticInitc2267e67192cf31fbc2e1aca813b29b4::$prefixLengthsPsr4;
            $loader->prefixDirsPsr4 = ComposerStaticInitc2267e67192cf31fbc2e1aca813b29b4::$prefixDirsPsr4;

        }, null, ClassLoader::class);
    }
}
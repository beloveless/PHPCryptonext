# PHPCrypton

Encrypt your PHP source code using PHPCrypton. Like IonCube Loader but it's free...


## How to Compile

### Install PHP-CPP first

        sudo apt-get install git gcc make re2c php7.0 php7.0-json php7.0-dev libpcre3-dev 
        git clone https://github.com/CopernicaMarketingSoftware/PHP-CPP.git
        cd PHP-CPP/
        make
        sudo make install

### Compile the source

        make
        sudo make install

## How to Recompile

        make clean
        make
        sudo make install

## Important!

Don't forget to change firstkey and secondkey in main.cpp file.

Change INI_DIR in Makefile according to your machine

make sure you have enable php mod using
        
        phpenmod phpcrypton


## Encrypt php file

```php
<?php

        PHPCrypton::encodeFile("bf-cbc", "loop.php");

?>
```

## Encrypt code

```php
<?php

        $code = '$x = 1;        
                while($x <= 5) {
                echo "The number is: $x <br>";
                $x++;
                }';
        PHPCrypton::encode("bf-cbc", $code);

?>
```

## Encryption algorithm choices

Use any open ssl cipher method [https://www.php.net/manual/en/function.openssl-get-cipher-methods.php](https://www.php.net/manual/en/function.openssl-get-cipher-methods.php)



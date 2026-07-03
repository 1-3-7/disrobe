<?php
function greet($name) {
    $message = "Hello, " . $name . "!";
    return $message;
}

class Calculator {
    private $total = 0;
    public function add($x) {
        $this->total += $x;
        return $this->total;
    }
    public function result() {
        return $this->total;
    }
}

$calc = new Calculator();
$calc->add(10);
$calc->add(32);
echo greet("world");
echo "\n";
echo "Sum: " . $calc->result();

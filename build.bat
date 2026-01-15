@echo off
echo Building ClapScan...
cargo build --release
echo.
echo Installing to PATH...
.\target\release\clapscan.exe --install
echo Copying to project root...
copy target\release\clapscan.exe .
echo.
echo Done! You can now use: clapscan.exe --help

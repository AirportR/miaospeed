1. 请在go编译时将go编译缓存目录设置为当前项目目录的文件夹，比如：

   ```powershell
   $env:GOCACHE = "$PWD\.gocache"
   New-Item -ItemType Directory -Force -Path $env:GOCACHE | Out-Null
   ```
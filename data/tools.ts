
import { Tool, ToolArg } from '../types';

// --- Helpers ---

export const getUrlPrefix = (isHttps: boolean) => isHttps ? 'https://' : 'http://';

export const formatTargetWithPort = (target: string, port: string) => {
    if (!target) return '$TARGET';
    return port ? `${target}:${port}` : target;
};

// Helper to create arguments easily
export const createArg = {
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
        args: [ARG_CREDS],
        generate: (v, args) => {
            const auth = args.useCreds ? `-U '${v.username || '$USERNAME'}%${v.password || '$PASSWORD'}'` : '-N';
            return `smbclient ${auth} -L //${v.target || '$TARGET'}/`;
        }
    },
    {
        id: 'smbmap',
        name: 'smbmap',
        category: 'SERVICE',
        subcategory: 'SMB',
        desc: 'SMB enumeration tool.',
        authMode: 'optional',
        args: [ARG_CREDS],
        generate: (v, args) => {
            const auth = args.useCreds
                ? `-u '${v.username || 'user'}' -p '${v.password || 'pass'}'`
                : `-u 'guest' -p ''`;
            return `smbmap -H ${v.target || '$TARGET'} ${auth}`;
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
            const proto = args.udp ? '-sU' : '';
            return `nmap ${proto} -sV -sC -Pn -v ${v.target || '$TARGET'}`;
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
            return `rustscan -a ${v.target || '$TARGET'} --ulimit 5000`;
        }
    },

    {
        id: 'msfconsole',
        name: 'Metasploit Handler',
        category: 'EXPLOIT',
        subcategory: 'Listeners',
        desc: 'Quick listener setup.',
        authMode: 'none',
        args: [
            createArg.input('lhost', 'LHOST', '', 'tun0 IP'),
            createArg.input('lport', 'LPORT', '4444', '4444'),
            createArg.input('payload', 'Payload', 'linux/x64/meterpreter/reverse_tcp', 'linux/x64/...')
        ],
        generate: (v, args) => {
            const lhost = args.lhost || '$LHOST';
            const lport = args.lport || '$LPORT';
            return `msfconsole -q -x "use exploit/multi/handler; set payload ${args.payload || '$PAYLOAD'}; set LHOST ${lhost}; set LPORT ${lport}; run"`;
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
            const targetWithPort = formatTargetWithPort(v.target, v.port);
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
            const targetWithPort = formatTargetWithPort(v.target, v.port);
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
        args: [ARG_HTTPS, ARG_OUTPUT, ARG_WL_DIR],
        generate: (v, args) => {
            const prefix = getUrlPrefix(args.useHttps);
            const targetWithPort = formatTargetWithPort(v.target, v.port);
            let cmd = `ffuf -u ${prefix}${targetWithPort}/FUZZ -w ${args.wordlistDir || '$WORDLIST_DIR'} -ic`;
            if (args.saveOutput) cmd += ` -o ffuf_dir.txt`;
            return cmd;
        }
    },
    {
        id: 'feroxbuster',
        name: 'Feroxbuster',
        category: 'WEB',
        subcategory: 'Directory Fuzzing',
        desc: 'Simple, fast, recursive content discovery.',
        authMode: 'none',
        args: [ARG_HTTPS, ARG_OUTPUT, ARG_WL_DIR],
        generate: (v, args) => {
            const prefix = getUrlPrefix(args.useHttps);
            const targetWithPort = formatTargetWithPort(v.target, v.port);
            let cmd = `feroxbuster -u ${prefix}${targetWithPort} -w ${args.wordlistDir || '$WORDLIST_DIR'}`;
            if (args.saveOutput) cmd += ` -o ferox_output.txt`;
            return cmd;
        }
    },
    {
        id: 'httpx',
        name: 'Httpx',
        category: 'WEB',
        subcategory: 'Fingerprinting',
        desc: 'HTTP toolkit for single target.',
        authMode: 'none',
        args: [ARG_HTTPS],
        generate: (v, args) => {
            const prefix = getUrlPrefix(args.useHttps);
            return `httpx -u ${prefix}${v.target || '$TARGET'}`;
        }
    },
    {
        id: 'gowitness',
        name: 'Gowitness',
        category: 'WEB',
        subcategory: 'Fingerprinting',
        desc: 'Screenshot utility.',
        authMode: 'none',
        args: [ARG_HTTPS],
        generate: (v, args) => {
            const prefix = getUrlPrefix(args.useHttps);
            const targetWithPort = formatTargetWithPort(v.target, v.port);
            return `gowitness single ${prefix}${targetWithPort} -P screenshots`;
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
            const targetWithPort = formatTargetWithPort(v.target, v.port);
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
            const targetWithPort = formatTargetWithPort(v.target, v.port);
            let cmd = `nuclei -u ${prefix}${targetWithPort}`;
            if (args.saveOutput) cmd += ` -o nuclei_vulns.txt`;
            return cmd;
        }
    },
];

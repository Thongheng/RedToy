import { Copy } from 'lucide-react';
import { Card, Button, PayloadBlock } from '../ui';
import { useClipboard } from '../../hooks/useClipboard';

export default function WindowsHostEnumTool() {
    const { copied, copy } = useClipboard();

    const systemCommands = [
        { name: 'System Information', desc: 'Retrieve detailed information about the system', cmd: 'systeminfo' },
        { name: 'Computer System Information', desc: 'Retrieve information about the computer system', cmd: 'Get-WmiObject Win32_ComputerSystem' },
        { name: 'Computer and Domain Name', desc: 'Display the computer and user domain name', cmd: 'echo "$env:COMPUTERNAME.$env:USERDNSDOMAIN"' },
        { name: 'Security Patches', desc: 'List all security patches', cmd: 'Get-Hotfix -description "Security update"' },
        { name: 'Detailed Security Patches', desc: 'List all security patches with detailed information', cmd: 'wmic qfe get HotfixID,ServicePackInEffect,InstallDate,InstalledBy,InstalledOn' },
        { name: 'Environment Variables', desc: 'List all environment variables', cmd: 'Get-ChildItem Env: | ft Key,Value' },
        { name: 'CMD Environment Variables', desc: 'List all environment variables using CMD', cmd: 'set' },
        { name: 'Add AV Exclusion Path', desc: 'Add an exclusion path to the antivirus', cmd: 'Add-MpPreference -ExclusionPath "<Path to be excluded>"' },
        { name: 'List AV Exclusion Paths', desc: 'List all exclusion paths in the antivirus', cmd: 'Get-MpPreference | select -ExpandProperty ExclusionPath' },
    ];

    const networkCommands = [
        { name: 'IP Configuration', desc: 'Display the IP configuration', cmd: 'ipconfig /all' },
        { name: 'ARP Table', desc: 'Display the ARP table', cmd: 'arp -a' },
        { name: 'WLAN Profiles', desc: 'Show all WLAN profiles', cmd: 'netsh wlan show profiles' },
        { name: 'Specific WLAN Profile', desc: 'Show a specific WLAN profile', cmd: 'netsh wlan show profile name="PROFILE-NAME" key=clear' },
    ];

    return (
        <div className="space-y-6">
            <div>
                <h2 className="text-2xl font-black text-white mb-2">Windows Host Enumeration</h2>
                <p className="text-gray-400 text-sm">
                    System and network information gathering commands for Windows environments
                </p>
            </div>

            {/* System Information */}
            <Card className="!p-6">
                <h3 className="text-lg font-bold text-[#a2ff00] mb-4">System Information Gathering</h3>
                <p className="text-gray-400 text-sm mb-4">Commands to retrieve system information</p>
                <PayloadBlock
                    content={systemCommands.map(item => `# ${item.name} - ${item.desc}\n${item.cmd}`).join('\n\n')}
                />
            </Card>

            {/* Network Information */}
            <Card className="!p-6">
                <h3 className="text-lg font-bold text-[#a2ff00] mb-4">Network Information Gathering</h3>
                <PayloadBlock
                    content={networkCommands.map(item => `# ${item.name} - ${item.desc}\n${item.cmd}`).join('\n\n')}
                />
            </Card>
        </div>
    );
}

